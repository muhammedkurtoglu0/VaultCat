"""
AI Thinking Planner — tüm enumeration bulgularını tek bir Claude çağrısında
alır, extended thinking ile derin analiz yapar ve typed PentestPlan üretir.

Bu modül chat_ui.py içindeki phased session tarafından çağrılır.
Doğrudan MCP katmanına dokunmaz; ham veri dict alır.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import anthropic


# ─── Sabitler ─────────────────────────────────────────────────────────────────

# Yüksek thinking budget: tüm enum verisini görmesi için yeterli alan
THINKING_BUDGET = 20_000
# Thinking budget + yapılandırılmış çıktı + açıklama metni için yeterli
MAX_TOKENS = 26_000

DEFAULT_MODEL = "claude-opus-4-8"


# ─── Yapılandırılmış çıktı aracı ─────────────────────────────────────────────

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
                    "policy isimleri. Enumeration'dan gözlemlenen isimler, path prefix'lerinden "
                    "çıkarılan isimler ve ortama özel tahminler. Jenerik admin/root listesinden kaçın."
                ),
            },
            "steps": {
                "type": "array",
                "description": "Öncelikli sıralı saldırı adımları",
                "items": {
                    "type": "object",
                    "required": ["tool", "reason", "priority", "expected_impact"],
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "MCP tool adı (örn. run_privilege_escalation)",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Bu adımı neden çalıştırıyoruz",
                        },
                        "params": {
                            "type": "object",
                            "description": "Tool'a geçirilecek ek parametreler (vault_addr ve token otomatik eklenir)",
                        },
                        "priority": {
                            "type": "integer",
                            "description": "1=en yüksek öncelik",
                        },
                        "expected_impact": {
                            "type": "string",
                            "description": "Bu adım ne bulabilir / elde edebilir?",
                        },
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

# ─── Sistem promptu ────────────────────────────────────────────────────────────

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
  * KV enumeration'da database bağlantı bilgisi (db_host, db_password vb.) tespit edildiyse
  * policy içinde database/creds/* veya database/roles/* path'i bulunuyorsa
  Önemli parametreler:
  * mount_path (opsiyonel): belirli bir database mount varsa ilet (örn. "database/")
  * token: yakalanan escalated token varsa onu kullan; yoksa mevcut tokeni ilet

### Planlama Kuralları
- run_database_credential_harvest'ı run_privilege_escalation'dan SONRA çalıştır;
  böylece mümkün olan en yüksek yetkiyle credential üretilir.
- Tek bir oturumda hem KV hem DB sızması hedefliyorsa sıra:
  1. run_privilege_escalation
  2. run_secret_exfiltration (KV)
  3. run_database_credential_harvest (DB)
- Database mount görünmüyorsa run_database_credential_harvest'ı plana ekleme.

SADECE 'create_pentest_plan' aracını çağırarak yapılandırılmış çıktı ver.
Metin yanıtı verme.\
"""


# ─── Veri sınıfları ────────────────────────────────────────────────────────────

@dataclass
class PlannedStep:
    tool: str
    reason: str
    params: dict = field(default_factory=dict)
    priority: int = 1
    expected_impact: str = ""


@dataclass
class TokenAssessment:
    power_level: str  # root | admin | privileged | standard | restricted
    summary: str
    accessible_paths: list[str] = field(default_factory=list)
    escalation_possible: bool = False


@dataclass
class PentestPlan:
    token_assessment: TokenAssessment
    risk_level: str                # critical | high | medium | low
    dynamic_policies: list[str]
    steps: list[PlannedStep]
    attack_narrative: str
    thinking: str                  # ham thinking metni (denetim kaydı için)


# ─── Ana sınıf ────────────────────────────────────────────────────────────────

class ThinkingPlanner:
    """
    Enumeration bulgularını alır, extended thinking ile tek bir Claude
    çağrısında analiz eder ve typed PentestPlan döner.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        thinking_budget: int = THINKING_BUDGET,
    ) -> None:
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ["ANTHROPIC_API_KEY"]
        )
        self._model = model
        self._thinking_budget = thinking_budget

    def create_plan(
        self,
        vault_addr: str,
        token_hint: str,
        enum_data: dict[str, Any],
    ) -> PentestPlan:
        """
        Enumeration verisini alıp Claude'a düşündürür ve PentestPlan döner.

        Parameters
        ----------
        vault_addr : str
            Hedef Vault adresi.
        token_hint : str
            Gösterim amaçlı token önizlemesi (örn. "s.XXXX...").
        enum_data : dict
            Anahtarlar (hepsi opsiyonel):
              - capabilities : capability_audit çıktısı (str)
              - priv_esc     : priv_esc_scan çıktısı (str)
              - kv_paths     : kv_enumeration çıktısı (str)
              - token_info   : check_token çıktısı (dict)
              - findings     : mevcut bulgular listesi (list)
              - env_scan     : env_scanner çıktısı (str)
        """
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


# ─── Yardımcı fonksiyonlar ────────────────────────────────────────────────────

def _build_prompt(vault_addr: str, token_hint: str, enum_data: dict) -> str:
    sections: list[str] = [
        f"## Hedef\n- Vault Adresi: {vault_addr}\n- Token: {token_hint}",
    ]

    if enum_data.get("token_info"):
        info_text = (
            json.dumps(enum_data["token_info"], indent=2, ensure_ascii=False)
            if isinstance(enum_data["token_info"], (dict, list))
            else str(enum_data["token_info"])
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
        "Özellikle 'dynamic_policies' alanını doldururken: enumeration'dan "
        "gözlemlediğin policy isimlerini, path prefix'lerinden çıkardığın isimleri "
        "ve bu ortama özel tahminleri kullan. Jenerik listeden kaçın.\n"
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
