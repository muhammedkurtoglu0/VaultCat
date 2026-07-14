import json
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from active_execution.context import ExecutionContext
from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
from active_execution.modules.secret_exfiltration import SecretExfiltrationModule
from active_execution.modules.database_credential_harvest import DatabaseCredentialHarvestModule
from active_execution.modules.cloud_key_exfiltration import CloudKeyExfiltrationModule
from active_execution.registry import ActiveExecutionRegistry, RiskLevel, risk_level_allowed
from ai_core.llm_engine import LLMClient, detect_provider
from ai_core.session import session_manager
from core.report import clear_findings, findings as report_findings
from core.risk_score import calculate_risk
from scanners.capability_scanner import audit_token_capabilities
from scanners.auth_config_scanner import scan_auth_config_security
from scanners.kv_enumerator import scan_kv_tree
from scanners.policy_auditor import scan_policy_audit
from scanners.privilege_escalation_scanner import scan_privilege_escalation
from scanners.ttl_scanner import (
    DEFAULT_MAX_MOUNT_TTL_SECONDS,
    DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
    scan_ttl_governance,
)
from scanners.env_scanner import scan_environment, scan_vault_token_file
from credential_hijacking.hijack_analyzer import run_hijack_scan as _run_hijack_scan_impl
from reconnaissance.recon_context import ReconContext
from reconnaissance.tls_scanner import scan_tls
from reconnaissance.health_scanner import scan_health
from reconnaissance.version_risk_scanner import scan_version_risk
from reconnaissance.fingerprint_scanner import scan_fingerprint
from reconnaissance.ui_scanner import scan_ui
from reconnaissance.auth_surface_scanner import scan_auth_surface
from reconnaissance.deployment_scanner import scan_deployment
from reconnaissance.cors_scanner import scan_cors
from reconnaissance.header_scanner import scan_headers
from reconnaissance.endpoint_scanner import scan_endpoints


mcp_server = FastMCP(
    name="VaultPentestAgent",
    host="127.0.0.1",
    port=8000,
    stateless_http=True,
    json_response=True,
)

# Oturum düzeyinde yakalanan token ve bağlam durumu
# Migrated to ai_core.session.SessionManager — kept as alias for backward compat
_default_session = session_manager.get_or_create("default")
pentest_context: dict[str, Any] = {
    "captured_token": None,
}


def _sync_context_to_session() -> None:
    """Keep the legacy pentest_context in sync with SessionManager."""
    token = _default_session.get_resolved_token()
    pentest_context["captured_token"] = token


def build_active_registry() -> ActiveExecutionRegistry:
    """
    Registry oluşturmak için main'deki fonksiyonu çağır.
    Döngüsel import'u önlemek için import fonksiyon içinde yapılıyor.
    """
    from main import build_active_execution_registry
    return build_active_execution_registry()


def _module_metadata(module: Any) -> dict[str, Any]:
    return {
        "module_id": module.module_id,
        "title": module.title,
        "description": module.description,
        "risk_level": module.risk_level.value,
        "default_enabled": getattr(module, "default_enabled", False),
    }


def _execution_context(
    vault_addr: str,
    token: Optional[str] = None,
    namespace: Optional[str] = None,
    captured_token: Optional[str] = None,
) -> ExecutionContext:
    return ExecutionContext(
        vault_addr=vault_addr.rstrip("/"),
        token=token,
        namespace=namespace,
        captured_token=captured_token,
        escalated_token=captured_token,
    )


def _safe_module_filter(module_name: str) -> list[dict]:
    return [f for f in report_findings if f.get("module") == module_name]


def _new_findings_since(start_index: int, modules: set[str] | None = None) -> list[dict]:
    new_findings = report_findings[start_index:]
    if modules is None:
        return list(new_findings)
    return [finding for finding in new_findings if finding.get("module") in modules]


# ─── Unauthenticated Recon ─────────────────────────────────────────────────

@mcp_server.tool(
    name="run_unauthenticated_recon",
    description=(
        "Hedef Vault adresine karsi kimlik dogrulamasi gerektirmeyen pasif kesif taramasi yapar. "
        "TLS, saglik durumu, surum riski, parmak izi, UI, auth yuzey, CORS, HTTP basliklari "
        "ve uc nokta tespitini icerir. Token gerekmez."
    ),
)
async def run_unauthenticated_recon(vault_addr: str) -> str:
    clear_findings()
    try:
        start_index = len(report_findings)
        context = ReconContext(vault_addr)
        context.fetch_health_once()
        scan_tls(vault_addr)
        scan_health(vault_addr, context=context)
        scan_version_risk(vault_addr, context=context)
        scan_fingerprint(vault_addr, context=context)
        scan_ui(vault_addr, context=context)
        scan_auth_surface(vault_addr, context=context)
        scan_deployment(vault_addr, context=context)
        scan_cors(vault_addr, context=context)
        scan_headers(vault_addr, context=context)
        scan_endpoints(vault_addr, context=context)

        recon_modules = {
            "tls_scanner", "health_scanner", "version_risk_scanner",
            "fingerprint_scanner", "ui_scanner", "auth_surface_scanner",
            "deployment_scanner", "cors_scanner", "header_scanner", "endpoint_scanner",
        }
        recon_findings = _new_findings_since(start_index, recon_modules)
        return json.dumps(
            {
                "status": "completed",
                "target": vault_addr,
                "findings_count": len(recon_findings),
                "findings": recon_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Credential Hijack Scan ────────────────────────────────────────────────

@mcp_server.tool(
    name="run_hijack_scan",
    description=(
        "Belirtilen yerel dizini veya dosyayi Vault kimlik bilgisi materyali acisindan tarar. "
        "Token, AppRole role_id/secret_id, AWS anahtarlari, veritabani sifreleri ve "
        "git commit gecmisini icerir. path: taranacak klasor veya dosya yolu."
    ),
)
async def run_hijack_scan(
    path: str,
    vault_addr: Optional[str] = None,
    token: Optional[str] = None,
    validate_token: bool = False,
    validate_approle: bool = False,
    include_git_history: bool = True,
    max_file_size_mb: int = 5,
) -> str:
    clear_findings()
    try:
        _run_hijack_scan_impl(
            path,
            vault_addr=vault_addr,
            token=token,
            validate_token=validate_token,
            validate_approle=validate_approle,
            validate_db=False,
            include_git_history=include_git_history,
            max_file_size_bytes=max_file_size_mb * 1024 * 1024,
            excluded_dirs=None,
        )
        hijack_findings = _safe_module_filter("file_secret_scanner")
        return json.dumps(
            {
                "status": "completed",
                "path": path,
                "findings_count": len(hijack_findings),
                "findings": hijack_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Environment Scan ─────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_env_scan",
    description=(
        "Yerel ortam degiskenlerini ve ~/.vault-token dosyasini tarar. "
        "VAULT_TOKEN, VAULT_ADDR, VAULT_ROLE_ID gibi ortamda sakli Vault "
        "kimlik bilgilerini tespit eder. Parametre gerekmez."
    ),
)
async def run_env_scan() -> str:
    clear_findings()
    try:
        scan_environment()
        scan_vault_token_file()
        env_findings = _safe_module_filter("env_scanner")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(env_findings),
                "findings": env_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Capability Audit ─────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_capability_audit",
    description=(
        "Verilen Vault token'inin sys/capabilities-self uzerindeki yetkilerini denetler. "
        "Token'in hangi Vault yollarina hangi operasyonlari yapabilecegini gosterir. "
        "Gizli okuma veya degisiklik yapmaz."
    ),
)
async def run_capability_audit(
    vault_addr: str,
    token: str,
    paths: Optional[list[str]] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    try:
        audit_token_capabilities(vault_addr, token, paths=paths, namespace=namespace)
        cap_findings = _safe_module_filter("capability_scanner")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(cap_findings),
                "findings": cap_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── KV Enumeration ───────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_kv_enumeration",
    description=(
        "Verilen Vault token ile KV secrets engine altindaki erisilebilen secret yollarini listeler. "
        "read_leaves=true verilirse leaf secret degerlerini de okur (dikkatli kullan). "
        "kv_version belirtilmezse otomatik algilanir."
    ),
)
async def run_kv_enumeration(
    vault_addr: str,
    token: str,
    kv_path: Optional[str] = None,
    kv_version: Optional[int] = None,
    namespace: Optional[str] = None,
    max_depth: int = 5,
    concurrency: int = 5,
    read_leaves: bool = False,
    blind_brute: bool = False,
) -> str:
    clear_findings()
    try:
        scan_kv_tree(
            vault_addr,
            token,
            kv_path,
            kv_version=kv_version,
            namespace=namespace,
            max_depth=max_depth,
            concurrency=concurrency,
            read_leaves=read_leaves,
            blind_brute=blind_brute,
        )
        kv_findings = _safe_module_filter("kv_enumerator")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(kv_findings),
                "findings": kv_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── TTL Audit ────────────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_ttl_audit",
    description=(
        "Vault secrets engine mount TTL'lerini ve PKI sertifika rolu TTL yonetimini denetler. "
        "Asiri uzun TTL veya politika ihlallerini tespit eder."
    ),
)
async def run_ttl_audit(
    vault_addr: str,
    token: str,
    namespace: Optional[str] = None,
    max_mount_ttl_seconds: int = DEFAULT_MAX_MOUNT_TTL_SECONDS,
    max_pki_cert_ttl_seconds: int = DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
) -> str:
    clear_findings()
    try:
        scan_ttl_governance(
            vault_addr,
            token,
            namespace=namespace,
            max_mount_ttl_seconds=max_mount_ttl_seconds,
            max_pki_cert_ttl_seconds=max_pki_cert_ttl_seconds,
        )
        ttl_findings = _safe_module_filter("ttl_scanner")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(ttl_findings),
                "findings": ttl_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Privilege Escalation Scanner (read-only simulation) ──────────────────

@mcp_server.tool(
    name="run_priv_esc_scan",
    description=(
        "Vault token'inin yetki yukseltme riskini sys/capabilities-self kullanarak guvenli sekilde simule eder. "
        "Gercekte token olusturmaz veya degisiklik yapmaz. "
        "Kritik policy erisimlerini rapor eder. "
        "Aktif yetki yukseltme denemesi icin run_privilege_escalation kullan."
    ),
)
async def run_priv_esc_scan(
    vault_addr: str,
    token: str,
    policy_names: Optional[list[str]] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    try:
        scan_privilege_escalation(
            vault_addr,
            token,
            policy_names=policy_names,
            namespace=namespace,
        )
        priv_findings = _safe_module_filter("privilege_escalation_scanner")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(priv_findings),
                "findings": priv_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Auth Config Audit ────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_auth_config_audit",
    description=(
        "Kubernetes, AWS ve LDAP auth method konfigurasyon guvenligini denetler. "
        "Yanlis yapilandirilmis auth methodlari, eksik dogrulama adimlari ve "
        "esnek politikalari tespit eder."
    ),
)
async def run_auth_config_audit(
    vault_addr: str,
    token: str,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    try:
        scan_auth_config_security(vault_addr, token, namespace=namespace)
        auth_findings = _safe_module_filter("auth_config_scanner")
        return json.dumps(
            {
                "status": "completed",
                "findings_count": len(auth_findings),
                "findings": auth_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Policy Auditor ───────────────────────────────────────────────────────

@mcp_server.tool(
    name="run_policy_auditor",
    description=(
        "Ele gecirilen token'in okuma yetkisi olan tum ACL politikalarini "
        "(/v1/sys/policies/acl) tek tek ceker ve HCL analizinden gecirir. "
        "Genis wildcard path'ler ve sys/auth/identity uzerindeki yuksek riskli "
        "yetkileri raporlar. Vault durumunu degistirmez (read-only)."
    ),
)
async def run_policy_auditor(
    vault_addr: str,
    token: str,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    try:
        result = scan_policy_audit(vault_addr, token, namespace=namespace)
        policy_findings = _safe_module_filter("policy_auditor") + _safe_module_filter("policy_scanner")
        return json.dumps(
            {
                "status": "completed",
                "policies_listed": len((result or {}).get("policies", [])),
                "policies_analyzed": len((result or {}).get("audited", [])),
                "policies_read_denied": len((result or {}).get("denied", [])),
                "findings_count": len(policy_findings),
                "findings": policy_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


# ─── Findings & Risk Score ─────────────────────────────────────────────────

@mcp_server.tool(
    name="get_findings",
    description=(
        "Bu oturumda biriken tum pentest bulgularini dondurur. "
        "AI bu sonucu kullanarak hangi moduller calistigini, "
        "hangi bulgularin mevcut oldugunu ve risk profilini degerlendirilebilir."
    ),
)
async def get_findings() -> str:
    risk = calculate_risk(report_findings)
    summary: dict[str, int] = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS")}
    for f in report_findings:
        sev = f.get("severity", "INFO")
        summary[sev] = summary.get(sev, 0) + 1

    return json.dumps(
        {
            "total": len(report_findings),
            "summary": summary,
            "risk_score": risk["score"],
            "risk_grade": risk["grade"],
            "findings": report_findings,
        },
            ensure_ascii=False,
    )


@mcp_server.tool(
    name="get_risk_score",
    description=(
        "Mevcut bulgulara dayali genel risk skorunu ve not harfini dondurur (0-100, A-F). "
        "AI bu skoru pentest kampanyasinin ne kadar ilerledigini degerlendirmek icin kullanir."
    ),
)
async def get_risk_score() -> str:
    risk = calculate_risk(report_findings)
    return json.dumps(risk, ensure_ascii=False)


# ─── NVD CVE Cache Management ────────────────────────────────────────────

@mcp_server.tool(
    name="refresh_nvd_cache",
    description=(
        "NVD (National Vulnerability Database) API'sinden HashiCorp Vault CVE'lerini ceker "
        "ve yerel onbellege kaydeder. Bu cache daha sonra version_cve_matcher tarafindan "
        "kullanilir. API anahtari icin NVD_API_KEY cevre degiskeni desteklenir "
        "(anahtarsiz: 5 istek/30sn, anahtarla: 50 istek/30sn)."
    ),
)
async def refresh_nvd_cache() -> str:
    try:
        from reconnaissance.nvd_client import (
            _load_cache,
            fetch_vault_cves_from_nvd,
        )

        cves = fetch_vault_cves_from_nvd(force_refresh=True)
        cache = _load_cache()
        return json.dumps(
            {
                "status": "completed",
                "cve_count": len(cves),
                "last_fetched": cache.get("last_fetched"),
                "sample": [
                    f"{c['cve_id']} [{c['severity']}]" for c in cves[:10]
                ],
            },
            ensure_ascii=False,
        )
    except ImportError:
        return json.dumps(
            {"status": "error", "message": "NVD client dependency missing."},
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps(
            {"status": "error", "message": str(error)},
            ensure_ascii=False,
        )


# ─── Session Management ──────────────────────────────────────────────────


@mcp_server.tool(
    name="get_session_status",
    description=(
        "Mevcut pentest oturumunun durumunu döndürür: hedefler, token geçmişi, "
        "aktif plan, faz ve bulgular. Session ID verilmezse varsayılan oturum kullanılır."
    ),
)
async def get_session_status(session_id: str = "default") -> str:
    session = session_manager.get_or_create(session_id)
    status = session.to_dict()
    status["findings_count"] = len(report_findings)
    risk = calculate_risk(report_findings)
    status["risk_score"] = risk["score"]
    status["risk_grade"] = risk["grade"]
    return json.dumps(status, ensure_ascii=False)


@mcp_server.tool(
    name="reset_session",
    description=(
        "Pentest oturumunu sıfırlar: tüm token'lar, planlar ve hedefler temizlenir. "
        "Bulgular etkilenmez. Session ID verilmezse varsayılan oturum kullanılır."
    ),
)
async def reset_session(session_id: str = "default") -> str:
    session = session_manager.get_or_create(session_id)
    session.token_history.clear()
    session.active_token = None
    session.escalated_token = None
    session.active_plan = None
    session.plan_history.clear()
    session.current_phase = "recon"
    pentest_context["captured_token"] = None
    return json.dumps(
        {"status": "completed", "message": f"Session '{session_id}' reset."},
        ensure_ascii=False,
    )


@mcp_server.tool(
    name="create_attack_plan",
    description=(
        "Birikmiş enumeration bulgularından AI destekli çok adımlı saldırı planı üretir. "
        "Plan; token değerlendirmesi, dinamik policy isimleri, öncelikli adımlar ve "
        "saldırı anlatısı içerir. Üretilen plan oturuma kaydedilir ve "
        "execute_attack_plan ile çalıştırılabilir."
    ),
)
async def create_attack_plan(
    vault_addr: str,
    token: Optional[str] = None,
    provider: Optional[str] = None,
    session_id: str = "default",
) -> str:
    from ai_core.planning import create_planner, PentestPlan

    session = session_manager.get_or_create(session_id)
    if vault_addr:
        session.set_target(vault_addr)
    if token:
        session.add_token(token, source="user_provided")

    # Collect enumeration data from findings
    enum_data: dict[str, Any] = {"findings": list(report_findings)}
    token_hint = token[:12] + "..." if token and len(token) > 12 else (token or "none")

    llm_provider = provider or detect_provider()
    try:
        planner = create_planner(llm_provider)
        plan = planner.create_plan(vault_addr, token_hint, enum_data)
        plan_dict = plan.to_dict()
        session.active_plan = plan_dict
        session.touch()
        return json.dumps(
            {
                "status": "completed",
                "plan": plan_dict,
                "provider": llm_provider,
                "message": f"Plan generated with {plan.total_steps} steps via {llm_provider}.",
            },
            ensure_ascii=False,
        )
    except Exception as exc:
        return json.dumps(
            {"status": "error", "message": f"Plan generation failed: {exc}"},
            ensure_ascii=False,
        )


@mcp_server.tool(
    name="execute_attack_plan",
    description=(
        "Kaydedilmiş saldırı planını adım adım çalıştırır. Plan create_attack_plan ile "
        "üretilmiş olmalıdır. Her adımın sonucu değerlendirilir; başarısız adımlar "
        "planın on_failure ayarına göre atlanır, tekrarlanır veya durdurulur."
    ),
)
async def execute_attack_plan(
    vault_addr: str,
    token: Optional[str] = None,
    session_id: str = "default",
    max_risk: str = "state_changing",
) -> str:
    session = session_manager.get_or_create(session_id)
    plan_dict = session.active_plan
    if not plan_dict:
        return json.dumps(
            {
                "status": "error",
                "message": (
                    "No active plan found. Run create_attack_plan first, "
                    "or import a plan."
                ),
            },
            ensure_ascii=False,
        )

    resolved_token = token or session.get_resolved_token()
    if not resolved_token:
        return json.dumps(
            {"status": "error", "message": "No token available for plan execution."},
            ensure_ascii=False,
        )

    # Execute steps sequentially using the active execution engine
    registry = build_active_registry()
    engine_ctx = _execution_context(vault_addr, token=resolved_token)
    results = []

    for step in plan_dict.get("steps", []):
        tool_name = step.get("tool", "")
        params = step.get("params", {})

        # Try to map tool name to a module
        tool_module_map = {
            "run_privilege_escalation": "privilege_escalation.token_abuse",
            "run_secret_exfiltration": "secret_exfiltration.kv_dump",
            "run_database_credential_harvest": "database_credential_harvest.dynamic_creds",
            "run_cloud_key_exfiltration": "cloud_key_exfiltration.key_dump",
        }
        module_id = tool_module_map.get(tool_name)

        if module_id:
            module = registry.get(module_id)
            if module:
                try:
                    max_risk_level = RiskLevel(max_risk)
                except ValueError:
                    max_risk_level = RiskLevel.STATE_CHANGING

                if not risk_level_allowed(module.risk_level, max_risk_level):
                    results.append({
                        "step": tool_name,
                        "status": "blocked",
                        "message": f"Risk level {module.risk_level.value} exceeds max {max_risk}",
                    })
                    continue

                if not module.can_run(engine_ctx):
                    results.append({
                        "step": tool_name,
                        "status": "skipped",
                        "message": f"Module {module_id} cannot run with current context",
                    })
                    continue

                try:
                    result = module.execute(engine_ctx, params)
                    results.append({
                        "step": tool_name,
                        "status": result.status,
                        "message": result.message,
                        "evidence": result.evidence or {},
                    })
                    # Update session with captured token
                    captured = (
                        (result.evidence or {}).get("captured_token")
                        or getattr(engine_ctx, "captured_token", None)
                    )
                    if captured:
                        session.set_escalated_token(captured)
                        pentest_context["captured_token"] = captured
                        engine_ctx.token = captured

                    # Stop on failure if configured
                    on_failure = step.get("on_failure", "abort")
                    if result.status not in ("success", "partial") and on_failure == "abort":
                        results.append({"step": "plan", "status": "aborted",
                                       "message": f"Stopped at {tool_name} due to failure"})
                        break

                except Exception as exc:
                    results.append({
                        "step": tool_name,
                        "status": "error",
                        "message": str(exc),
                    })
                    if step.get("on_failure", "abort") == "abort":
                        break
            else:
                results.append({
                    "step": tool_name,
                    "status": "error",
                    "message": f"Module not found: {module_id}",
                })
        else:
            results.append({
                "step": tool_name,
                "status": "skipped",
                "message": f"No direct module mapping for tool: {tool_name}. Use run_active_module.",
            })

    plan_dict["results"] = results
    session.active_plan = plan_dict
    session.touch()

    # Aggregate findings from execution context
    for finding in engine_ctx.findings:
        from core.report import add_finding
        add_finding(
            finding.get("severity", "INFO"),
            finding.get("title", ""),
            finding.get("description", ""),
            evidence=finding.get("evidence"),
            module="active_execution",
            target=vault_addr,
        )

    return json.dumps(
        {
            "status": "completed",
            "plan_id": plan_dict.get("id", ""),
            "steps_executed": len(results),
            "results": results,
        },
        ensure_ascii=False,
    )


# ─── Active Execution: Privilege Escalation ───────────────────────────────

@mcp_server.tool(
    name="run_privilege_escalation",
    description=(
        "Belirtilen hedef Vault adresine ve dusuk yetkili token'a karsi "
        "otonom policy discovery ile AKTIF yetki yukseltme dener. "
        "Bu islem state-changing olup yeni bir token olusturur."
    ),
)
async def run_privilege_escalation(
    vault_addr: str,
    token: str,
    policies: Optional[list[str]] = None,
    ttl: str = "30m",
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    context = ExecutionContext(
        vault_addr=vault_addr.rstrip("/"),
        token=token,
        namespace=namespace,
    )
    module = PrivilegeEscalationModule()
    params: dict[str, Any] = {"ttl": ttl, "namespace": namespace}
    if policies:
        params["policies"] = policies

    try:
        result = module.execute(context, params)
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)

    evidence = result.evidence or {}
    if result.status == "success":
        captured = evidence.get("captured_token") or getattr(context, "captured_token", None)
        pentest_context["captured_token"] = captured
        if captured:
            session = session_manager.get_or_create("default")
            session.set_escalated_token(captured)
            _sync_context_to_session()

    return json.dumps(
        {
            "status": result.status,
            "message": result.message,
            "evidence": evidence,
            "captured_token": pentest_context.get("captured_token"),
            "findings": context.findings,
        },
        ensure_ascii=False,
    )


# ─── Active Execution: Secret Exfiltration ────────────────────────────────

@mcp_server.tool(
    name="run_secret_exfiltration",
    description=(
        "Belirtilen hedef Vault adresindeki KV motorlarindan veri sizdirir. "
        "Token verilmezse onceki privilege escalation adiminda ele gecirilen token kullanilir."
    ),
)
async def run_secret_exfiltration(
    vault_addr: str,
    token: Optional[str] = None,
    max_depth: int = 3,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    active_token = token or pentest_context.get("captured_token")
    if not active_token:
        return json.dumps(
            {
                "status": "error",
                "message": (
                    "Sizdirma icin token iletilmedi ve onceki adimdan yakalanan "
                    "token bulunamadi. Once run_privilege_escalation calistirin."
                ),
            },
            ensure_ascii=False,
        )

    context = ExecutionContext(
        vault_addr=vault_addr.rstrip("/"),
        token=active_token,
        namespace=namespace,
    )
    context.captured_token = pentest_context.get("captured_token") or active_token
    context.escalated_token = context.captured_token

    module = SecretExfiltrationModule()
    try:
        result = module.execute(context, {"namespace": namespace, "max_depth": max_depth})
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)

    summary = "Sizdirma basarili" if result.status == "success" else "Sizdirma basarisiz"

    return json.dumps(
        {
            "status": result.status,
            "summary": summary,
            "message": result.message,
            "evidence": result.evidence or {},
            "findings": context.findings,
        },
        ensure_ascii=False,
    )


# ─── Active Execution: Database Credential Harvest ───────────────────────────

@mcp_server.tool(
    name="run_database_credential_harvest",
    description=(
        "Vault Database Secrets Engine uzerinden veritabani kimlik bilgisi avlar. "
        "Aktif database mount'larini kesfeder, dinamik ve statik roller icin kimlik bilgisi "
        "uretir veya alir. Yuksek yetkili roller (admin/dba) otomatik olarak isaretlenir. "
        "Token verilmezse onceki adimdan yakalanan captured_token kullanilir. "
        "Bu islem state-changing'dir: her cagri veritabaninda yeni bir kullanici olusturabilir."
    ),
)
async def run_database_credential_harvest(
    vault_addr: str,
    token: Optional[str] = None,
    mount_path: Optional[str] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    active_token = token or pentest_context.get("captured_token")
    if not active_token:
        return json.dumps(
            {
                "status": "error",
                "message": (
                    "Kimlik bilgisi avcisi icin token iletilmedi ve onceki adimdan "
                    "yakalanan token bulunamadi. Token saglayin veya once "
                    "run_privilege_escalation calistirin."
                ),
            },
            ensure_ascii=False,
        )

    context = ExecutionContext(
        vault_addr=vault_addr.rstrip("/"),
        token=active_token,
        captured_token=pentest_context.get("captured_token") or active_token,
        namespace=namespace,
    )

    module = DatabaseCredentialHarvestModule()
    try:
        result = module.execute(
            context,
            {
                "token": active_token,
                "mount_path": mount_path,
                "namespace": namespace,
            },
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)

    evidence = result.evidence or {}
    harvested = evidence.get("credentials", [])
    high_priv = [c for c in harvested if c.get("high_privilege")]

    return json.dumps(
        {
            "status": result.status,
            "message": result.message,
            "total_harvested": evidence.get("total_harvested", 0),
            "high_privilege_count": len(high_priv),
            "db_mounts": evidence.get("db_mounts", []),
            "credentials": harvested,
            "errors": evidence.get("errors", []),
            "findings": context.findings,
        },
        ensure_ascii=False,
    )


# ─── Active Execution: Cloud Key Exfiltration ────────────────────────────────

@mcp_server.tool(
    name="run_cloud_key_exfiltration",
    description=(
        "Vault AWS, Azure veya GCP Secrets Engine uzerinden bulut IAM anahtari sızdirir. "
        "Aktif cloud mount'larini kesfeder; AWS icin access_key+secret_key, Azure icin "
        "client_id+client_secret, GCP icin service account key (JSON) veya access token uretir. "
        "Yuksek yetkili roller (Administrator/Owner/PowerUser/roles/owner) otomatik isaretlenir. "
        "provider parametresiyle yalnizca tek bir bulut saglaycisini hedefleyebilirsin. "
        "Token verilmezse onceki adimdan yakalanan captured_token kullanilir. "
        "Bu islem state-changing'dir: her cagri bulut tarafinda yeni kimlik bilgisi olusturur."
    ),
)
async def run_cloud_key_exfiltration(
    vault_addr: str,
    token: Optional[str] = None,
    provider: Optional[str] = None,
    mount_path: Optional[str] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    active_token = token or pentest_context.get("captured_token")
    if not active_token:
        return json.dumps(
            {
                "status": "error",
                "message": (
                    "Bulut anahtari sızdirma icin token iletilmedi ve onceki adimdan "
                    "yakalanan token bulunamadi. Token saglayin veya once "
                    "run_privilege_escalation calistirin."
                ),
            },
            ensure_ascii=False,
        )

    context = ExecutionContext(
        vault_addr=vault_addr.rstrip("/"),
        token=active_token,
        captured_token=pentest_context.get("captured_token") or active_token,
        namespace=namespace,
    )

    module = CloudKeyExfiltrationModule()
    try:
        result = module.execute(
            context,
            {
                "token": active_token,
                "provider": provider,
                "mount_path": mount_path,
                "namespace": namespace,
            },
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)

    evidence = result.evidence or {}
    harvested = evidence.get("credentials", [])
    high_priv = [c for c in harvested if c.get("high_privilege")]

    return json.dumps(
        {
            "status": result.status,
            "message": result.message,
            "total_harvested": evidence.get("total_harvested", 0),
            "high_privilege_count": len(high_priv),
            "cloud_mounts": evidence.get("cloud_mounts", []),
            "credentials": harvested,
            "errors": evidence.get("errors", []),
            "findings": context.findings,
        },
        ensure_ascii=False,
    )


# ─── Active Execution: Generic Module Runner ──────────────────────────────

@mcp_server.tool(
    name="list_active_modules",
    description=(
        "Toolun aktif execution modullerini listeler. "
        "AI bu ciktiyi hangi module_id ile hangi guvenlik adimini calistiracagini "
        "planlamak icin kullanir."
    ),
)
async def list_active_modules() -> str:
    registry = build_active_registry()
    modules = [_module_metadata(module) for module in registry.list_modules()]
    return json.dumps({"modules": modules}, ensure_ascii=False)


@mcp_server.tool(
    name="run_active_module",
    description=(
        "Registry'deki herhangi bir aktif execution modulunu module_id ile calistirir. "
        "vault_addr hedef Vault URL'sidir; token opsiyoneldir, verilmezse onceki "
        "adimda yakalanan captured_token kullanilir. params modulu besleyen ek parametreleri tasir."
    ),
)
async def run_active_module(
    module_id: str,
    vault_addr: str,
    token: Optional[str] = None,
    params: Optional[dict[str, Any]] = None,
    max_risk: str = "state_changing",
    namespace: Optional[str] = None,
) -> str:
    clear_findings()
    registry = build_active_registry()
    module = registry.get(module_id)
    if not module:
        return json.dumps(
            {
                "status": "error",
                "message": f"Module not found: {module_id}",
                "available_modules": registry.module_ids(),
            },
            ensure_ascii=False,
        )

    try:
        max_risk_level = RiskLevel(max_risk)
    except ValueError:
        return json.dumps(
            {
                "status": "error",
                "message": f"Invalid max_risk: {max_risk}",
                "allowed_values": [level.value for level in RiskLevel],
            },
            ensure_ascii=False,
        )

    if not risk_level_allowed(module.risk_level, max_risk_level):
        return json.dumps(
            {
                "status": "blocked",
                "message": (
                    f"Module risk '{module.risk_level.value}' exceeds "
                    f"allowed max_risk '{max_risk_level.value}'."
                ),
                "module": _module_metadata(module),
            },
            ensure_ascii=False,
        )

    active_token = token or pentest_context.get("captured_token")
    context = _execution_context(
        vault_addr=vault_addr,
        token=active_token,
        namespace=namespace,
        captured_token=pentest_context.get("captured_token"),
    )

    module_params = dict(params or {})
    if namespace and "namespace" not in module_params:
        module_params["namespace"] = namespace

    if not module.can_run(context):
        return json.dumps(
            {
                "status": "skipped",
                "message": f"Module cannot run with current context: {module_id}",
                "module": _module_metadata(module),
                "context": {
                    "vault_addr": context.vault_addr,
                    "has_token": bool(context.token),
                    "has_captured_token": bool(context.captured_token),
                },
            },
            ensure_ascii=False,
        )

    try:
        result = module.execute(context, module_params)
    except Exception as error:
        return json.dumps(
            {"status": "error", "message": f"Execution failed: {error}"},
            ensure_ascii=False,
        )

    evidence = result.evidence or {}
    captured = (
        evidence.get("captured_token")
        or getattr(context, "captured_token", None)
        or getattr(context, "escalated_token", None)
    )
    if captured:
        pentest_context["captured_token"] = captured
        session = session_manager.get_or_create("default")
        session.set_escalated_token(captured)
        _sync_context_to_session()

    return json.dumps(
        {
            "status": result.status,
            "message": result.message,
            "module": _module_metadata(module),
            "evidence": evidence,
            "captured_token": captured,
            "findings": context.findings,
        },
        ensure_ascii=False,
    )


# ─── Servis başlatıcı ─────────────────────────────────────────────────────

def start_mcp_service(host: str = "127.0.0.1", port: int = 8000):
    mcp_server.settings.host = host
    mcp_server.settings.port = port
    mcp_server.run(transport="streamable-http")


def tool_schema(tool: Any) -> dict[str, Any]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
    if isinstance(schema, dict) and schema.get("type") == "object":
        return schema
    return {"type": "object", "properties": {}, "required": []}


if __name__ == "__main__":
    start_mcp_service()