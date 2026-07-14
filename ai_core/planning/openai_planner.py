"""OpenAI / DeepSeek structured-output planner.

Uses OpenAI's JSON mode (``response_format={"type": "json_object"}``) to
produce a ``PentestPlan`` directly from enumeration data.  The same prompt
and schema design as the Anthropic extended-thinking planner, adapted to
the OpenAI function-calling convention.
"""

from __future__ import annotations

import json
from typing import Any

from ai_core.llm_engine import LLMClient, RetryableError, FatalError
from ai_core.planning.base_planner import BasePlanner
from ai_core.planning.plan_schema import (
    AttackPhase,
    PentestPlan,
    PlannedStep,
    TokenAssessment,
)

# ---------------------------------------------------------------------------
# Prompt — shared across OpenAI-style planners
# ---------------------------------------------------------------------------

_PLANNER_SYSTEM = """\
Sen bir Vault güvenlik değerlendirme uzmanısın.
Sana bir pentest oturumunun token enumeration aşamasından toplanan ham bulgular verilecek.

Görevin:
1. Token'ın gerçek gücünü ve erişim seviyesini değerlendir (root mu, admin mi, standard mı?)
2. Enumeration verilerinden hedef ortama özel bilgi çıkar:
   - Gözlemlenen policy isimleri, path prefix'leri, mount isimleri, namespace'ler
   - Bu isimlere dayalı akıllı tahminler (örn. "db-admin" varsa "db-readonly" de dene)
3. Mevcut token ile zincirlenebilecek en etkili saldırı yollarını belirle
4. 'dynamic_policies' alanını doldururken: jenerik "admin, root, vault-admin" listesinden kaçın.
   Bunun yerine bu spesifik ortamdan gözlemlediğin isimleri ve mantıklı türevlerini kullan.
5. Öncelikli sıralı adımlardan oluşan bir plan üret

## Kullanılabilir Aktif Araçlar

Planın 'steps' listesine dahil edebileceğin araçlar ve ne zaman kullanılacakları:

### Standart Aktif Saldırı
- run_privilege_escalation: Token yaratma izni görünüyorsa; yetki yükseltme dene
- run_secret_exfiltration: Yüksek yetkili token elde edildikten sonra KV motorlarını sızdır

### Veritabanı Kimlik Bilgisi Avcısı
- run_database_credential_harvest: Vault Database Secrets Engine aktifse kullan.
  Tetikleyiciler — aşağıdakilerden herhangi biri varsa bu adımı plana ekle:
  * sys/mounts çıktısında "type": "database" olan mount görünüyorsa
  * capability_audit sonuçlarında database/ veya db/ path'ine okuma/listeleme erişimi varsa
  * KV enumeration'da database bağlantı bilgisi tespit edildiyse
  * policy içinde database/creds/* veya database/roles/* path'i bulunuyorsa

### Planlama Kuralları
- run_database_credential_harvest'ı run_privilege_escalation'dan SONRA çalıştır.
- Tek bir oturumda hem KV hem DB sızması hedefliyorsa sıra:
  1. run_privilege_escalation
  2. run_secret_exfiltration (KV)
  3. run_database_credential_harvest (DB)
- Database mount görünmüyorsa run_database_credential_harvest'ı plana ekleme.

Çıktını JSON olarak ver. SADECE JSON, başka metin yok.\
"""

# ---------------------------------------------------------------------------
# JSON schema (OpenAI structured-output compatible)
# ---------------------------------------------------------------------------

_PLAN_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["token_assessment", "risk_level", "steps"],
    "properties": {
        "token_assessment": {
            "type": "object",
            "required": ["power_level", "summary", "escalation_possible"],
            "properties": {
                "power_level": {
                    "type": "string",
                    "enum": ["root", "admin", "privileged", "standard", "restricted"],
                },
                "summary": {"type": "string"},
                "accessible_paths": {"type": "array", "items": {"type": "string"}},
                "escalation_possible": {"type": "boolean"},
            },
        },
        "risk_level": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
        "dynamic_policies": {
            "type": "array",
            "items": {"type": "string"},
        },
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool", "reason", "priority", "expected_impact"],
                "properties": {
                    "tool": {"type": "string"},
                    "reason": {"type": "string"},
                    "params": {"type": "object"},
                    "priority": {"type": "integer"},
                    "expected_impact": {"type": "string"},
                },
            },
        },
        "attack_narrative": {"type": "string"},
    },
}


def _build_prompt(vault_addr: str, token_hint: str, enum_data: dict) -> str:
    """Assemble the user prompt from enumeration data sections."""
    sections: list[str] = [
        f"## Hedef\n- Vault Adresi: {vault_addr}\n- Token: {token_hint}",
    ]

    if enum_data.get("token_info"):
        info = enum_data["token_info"]
        info_text = (
            json.dumps(info, indent=2, ensure_ascii=False)
            if isinstance(info, (dict, list))
            else str(info)
        )
        sections.append(f"## Token Metadata\n```json\n{info_text}\n```")

    if enum_data.get("capabilities"):
        sections.append(
            f"## Capability Audit Sonuçları\n```\n{enum_data['capabilities']}\n```"
        )

    if enum_data.get("priv_esc"):
        sections.append(
            f"## Privilege Escalation Simülasyonu\n```\n{enum_data['priv_esc']}\n```"
        )

    if enum_data.get("kv_paths"):
        sections.append(
            f"## KV Enumeration\n```\n{enum_data['kv_paths']}\n```"
        )

    if enum_data.get("env_scan"):
        sections.append(
            f"## Ortam Taraması\n```\n{enum_data['env_scan']}\n```"
        )

    if enum_data.get("findings"):
        findings = enum_data["findings"]
        findings_text = json.dumps(findings, indent=2, ensure_ascii=False)
        sections.append(
            f"## Mevcut Bulgular ({len(findings)} adet)\n```json\n{findings_text}\n```"
        )

    sections.append(
        "## Görev\n"
        "Yukarıdaki enumeration verilerini analiz et.\n"
        "Bu spesifik ortam için optimize edilmiş bir saldırı planı oluştur.\n"
        "SADECE JSON döndür, başka metin yok."
    )
    return "\n\n".join(sections)


def _parse_plan_json(raw: str) -> dict:
    """Extract and parse JSON from an LLM text response."""
    # Try direct parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try to extract from code fences
    import re
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Last resort: find first { ... } block
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse plan JSON from LLM output: {raw[:500]}")


def _build_plan(data: dict) -> PentestPlan:
    """Convert raw JSON dict to typed PentestPlan."""
    assessment_raw = data.get("token_assessment", {})
    assessment = TokenAssessment(
        power_level=assessment_raw.get("power_level", "unknown"),
        summary=assessment_raw.get("summary", ""),
        accessible_paths=assessment_raw.get("accessible_paths") or [],
        escalation_possible=bool(assessment_raw.get("escalation_possible", False)),
    )

    raw_steps: list[dict] = data.get("steps") or []
    steps = sorted(
        [
            PlannedStep(
                tool=s.get("tool", ""),
                reason=s.get("reason", ""),
                params=s.get("params") or {},
                priority=int(s.get("priority", 99)),
                expected_impact=s.get("expected_impact", ""),
                phase=_map_phase(s.get("tool", "")),
            )
            for s in raw_steps
            if s.get("tool")
        ],
        key=lambda s: s.priority,
    )

    return PentestPlan(
        token_assessment=assessment,
        risk_level=data.get("risk_level", "medium"),
        dynamic_policies=data.get("dynamic_policies") or [],
        steps=steps,
        attack_narrative=data.get("attack_narrative", ""),
    )


def _map_phase(tool_name: str) -> AttackPhase:
    """Map a tool name to its attack phase."""
    recon_tools = {"run_unauthenticated_recon", "run_hijack_scan", "run_env_scan"}
    audit_tools = {
        "run_capability_audit", "run_priv_esc_scan", "run_kv_enumeration",
        "run_ttl_audit", "run_auth_config_audit", "run_policy_auditor",
    }
    exploit_tools = {
        "run_privilege_escalation", "run_secret_exfiltration",
        "run_database_credential_harvest", "run_cloud_key_exfiltration",
        "run_active_module", "list_active_modules",
    }
    if tool_name in recon_tools:
        return AttackPhase.RECON
    if tool_name in audit_tools:
        return AttackPhase.AUDIT
    if tool_name in exploit_tools:
        return AttackPhase.EXPLOIT
    return AttackPhase.REPORT


# ---------------------------------------------------------------------------
# OpenAI Planner
# ---------------------------------------------------------------------------


class OpenAIPlanner(BasePlanner):
    """Generate a PentestPlan via OpenAI's chat completion API.

    Uses ``response_format={"type": "json_object"}`` when the model supports
    it, falling back to plain text + regex JSON extraction for older models.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ):
        self._llm = llm_client
        self._model = model or llm_client.model
        self._temperature = temperature
        self._max_tokens = max_tokens

    @property
    def provider_name(self) -> str:
        return "openai"

    def create_plan(
        self,
        vault_addr: str,
        token_hint: str,
        enum_data: dict[str, Any],
    ) -> PentestPlan:
        prompt = _build_prompt(vault_addr, token_hint, enum_data)

        # Build messages
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": prompt},
        ]

        # OpenAI tools format for structured output
        tools = [{
            "type": "function",
            "function": {
                "name": "create_pentest_plan",
                "description": "Save the pentest plan in structured format.",
                "parameters": _PLAN_JSON_SCHEMA,
            },
        }]

        try:
            response = self._llm.chat(
                system_prompt=_PLANNER_SYSTEM,
                messages=messages,
                tools=tools,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
        except (RetryableError, FatalError):
            # Return an empty plan on LLM errors
            return PentestPlan(
                vault_addr=vault_addr,
                risk_level="medium",
                attack_narrative="Plan generation failed — LLM unavailable.",
            )

        # Extract from tool call
        tool_calls = response.get("tool_calls") or []
        for tc in tool_calls:
            if tc.get("name") == "create_pentest_plan":
                args = tc.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                return _build_plan(args)

        # Fallback: try to parse from text content
        content = response.get("content") or ""
        if content.strip():
            try:
                data = _parse_plan_json(content)
                return _build_plan(data)
            except ValueError:
                pass

        return PentestPlan(
            vault_addr=vault_addr,
            risk_level="medium",
            attack_narrative="Plan generation produced no usable output.",
        )
