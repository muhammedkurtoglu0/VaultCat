"""Anthropic Claude extended-thinking planner.

Refactored from ``ai_core.thinking_planner``.  Uses Claude's native
``tool_use`` + ``extended thinking`` to produce a structured
``PentestPlan`` in a single API call.
"""

from __future__ import annotations

import json
import os
import warnings
from typing import Any

from ai_core.planning.base_planner import BasePlanner
from ai_core.planning.plan_schema import PentestPlan, PlannedStep, TokenAssessment

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

THINKING_BUDGET = 20_000
MAX_TOKENS = 26_000
DEFAULT_MODEL = "claude-opus-4-8"


# ---------------------------------------------------------------------------
# Structured-output tool definition
# ---------------------------------------------------------------------------

_CREATE_PLAN_TOOL: dict[str, Any] = {
    "name": "create_pentest_plan",
    "description": (
        "Vault pentest saldırı planını yapılandırılmış formatta kaydet. "
        "Yalnızca bu araç kullanılmalı; metin yanıtı verilmemeli."
    ),
    "input_schema": {
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
                        "description": "Tokenin güç seviyesi",
                    },
                    "summary": {
                        "type": "string",
                        "description": "Tokenin erişim kapasitesinin kısa açıklaması (2-3 cümle)",
                    },
                    "accessible_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Erişilebilir kritik Vault path'leri",
                    },
                    "escalation_possible": {
                        "type": "boolean",
                        "description": "Mevcut token ile yetki yükseltme mümkün mü?",
                    },
                },
            },
            "risk_level": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Genel risk seviyesi",
            },
            "dynamic_policies": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Hedef Vault ortamına özel, token üretiminde denemek için çıkarılmış "
                    "policy isimleri."
                ),
            },
            "steps": {
                "type": "array",
                "description": "Öncelikli sıralı saldırı adımları",
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
            "attack_narrative": {
                "type": "string",
                "description": (
                    "Saldırı akışının operatöre yönelik anlatımı: hangi zayıflıklar "
                    "mevcut, neden bu sıra, beklenen sonuçlar. 3-5 cümle."
                ),
            },
        },
    },
}

# ---------------------------------------------------------------------------
# System prompt
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
  Önemli parametreler:
  * mount_path (opsiyonel): belirli bir database mount varsa ilet (örn. "database/")
  * token: yakalanan escalated token varsa onu kullan; yoksa mevcut tokeni ilet

### Planlama Kuralları
- run_database_credential_harvest'ı run_privilege_escalation'dan SONRA çalıştır.
- Tek bir oturumda hem KV hem DB sızması hedefliyorsa sıra:
  1. run_privilege_escalation
  2. run_secret_exfiltration (KV)
  3. run_database_credential_harvest (DB)
- Database mount görünmüyorsa run_database_credential_harvest'ı plana ekleme.

SADECE 'create_pentest_plan' aracını çağırarak yapılandırılmış çıktı ver.
Metin yanıtı verme.\
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_prompt(vault_addr: str, token_hint: str, enum_data: dict) -> str:
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
        sections.append(f"## KV Enumeration\n```\n{enum_data['kv_paths']}\n```")

    if enum_data.get("env_scan"):
        sections.append(f"## Ortam Taraması\n```\n{enum_data['env_scan']}\n```")

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
        "create_pentest_plan aracını çağır."
    )
    return "\n\n".join(sections)


def _extract_thinking(response: Any) -> str:
    for block in response.content:
        if getattr(block, "type", None) == "thinking":
            return block.thinking or ""
    return ""


def _extract_tool_input(response: Any, tool_name: str) -> dict:
    for block in response.content:
        if getattr(block, "type", None) == "tool_use" and block.name == tool_name:
            return block.input or {}
    return {}


def _build_plan(data: dict, thinking: str) -> PentestPlan:
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
        thinking=thinking,
    )


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


class AnthropicPlanner(BasePlanner):
    """Generate a PentestPlan via Anthropic Claude's extended thinking."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        thinking_budget: int = THINKING_BUDGET,
    ):
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            warnings.warn(
                "ANTHROPIC_API_KEY not set — AnthropicPlanner will not be able to "
                "make API calls. Use a different planner or set the env var.",
                RuntimeWarning,
            )
            self._client = None
        else:
            import anthropic

            self._client = anthropic.Anthropic(api_key=resolved_key)
        self._model = model
        self._thinking_budget = thinking_budget

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def create_plan(
        self,
        vault_addr: str,
        token_hint: str,
        enum_data: dict[str, Any],
    ) -> PentestPlan:
        if self._client is None:
            return PentestPlan(
                vault_addr=vault_addr,
                risk_level="medium",
                attack_narrative=(
                    "Plan generation skipped — ANTHROPIC_API_KEY not configured. "
                    "Use a different planner provider."
                ),
            )

        prompt = _build_prompt(vault_addr, token_hint, enum_data)

        response = self._client.messages.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            thinking={"type": "enabled", "budget_tokens": self._thinking_budget},
            system=_PLANNER_SYSTEM,
            tools=[_CREATE_PLAN_TOOL],
            tool_choice={"type": "tool", "name": "create_pentest_plan"},
            messages=[{"role": "user", "content": prompt}],
        )

        thinking_text = _extract_thinking(response)
        plan_data = _extract_tool_input(response, "create_pentest_plan")
        return _build_plan(plan_data, thinking_text)
