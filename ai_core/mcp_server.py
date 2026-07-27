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
from core.report import clear_findings, clear_module_findings, findings as report_findings
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
    """Return the default active execution registry with all modules registered."""
    from active_execution.modules import get_default_registry
    return get_default_registry()


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
    clear_module_findings("file_secret_scanner", "hijack_analyzer")
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
    clear_module_findings("env_scanner")
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
        "Gizli okuma veya degisiklik yapmaz. "
        "ONEMLI: Sonuclari aldiktan sonra sys/mounts ve sys/auth endpoint'lerini "
        "run_raw_vault_request ile okuyarak mount'lari ve auth method'larini kesfet. "
        "Cogu token'in bu endpoint'lerde read yetkisi vardir, capability audit gostermese bile dene."
    ),
)
async def run_capability_audit(
    vault_addr: str,
    token: str,
    paths: Optional[list[str]] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_module_findings("capability_scanner")
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
    clear_module_findings("kv_enumerator")
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
    clear_module_findings("ttl_scanner")
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
    clear_module_findings("privilege_escalation_scanner")
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
    clear_module_findings("auth_config_scanner")
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
    clear_module_findings("policy_auditor", "policy_scanner")
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


# ─── Single Policy Read ────────────────────────────────────────────────────

@mcp_server.tool(
    name="read_single_policy",
    description=(
        "Tek bir Vault ACL politikasini ismiyle okur. "
        "Token sys/policies/acl uzerinde LIST yetkisine sahip olmasa bile "
        "sys/policies/acl/* uzerinden tekil policy okuyabilir. "
        "'default', 'root' ve token'in kendi policy isimleriyle baslayin. "
        "Read-only, Vault durumunu degistirmez."
    ),
)
async def read_single_policy(
    vault_addr: str,
    token: str,
    policy_name: str,
    namespace: Optional[str] = None,
) -> str:
    """Read a single Vault ACL policy by name."""
    try:
        import hvac
        from core.tls_config import get_verify

        client = hvac.Client(
            url=vault_addr.rstrip("/"),
            token=token,
            namespace=namespace,
            timeout=5,
            verify=get_verify(),
        )
        try:
            response = client.sys.read_acl_policy(policy_name)
        except (AttributeError, TypeError):
            response = client.adapter.get(url=f"/v1/sys/policies/acl/{policy_name}")
            if hasattr(response, "json"):
                response = response.json()

        if not isinstance(response, dict):
            return json.dumps(
                {"status": "error", "message": f"Unexpected response format for policy '{policy_name}'"},
                ensure_ascii=False,
            )

        data = response.get("data") if isinstance(response.get("data"), dict) else response
        policy_text = data.get("policy") or data.get("rules")
        if not isinstance(policy_text, str) or not policy_text.strip():
            policy_text = "# Built-in policy — no explicit HCL rules"

        # Run HCL analysis on the policy
        clear_module_findings("policy_scanner")
        from scanners.policy_scanner import analyze_hcl_policy
        analyze_hcl_policy(policy_text, policy_name=policy_name, target=vault_addr)

        policy_findings = _safe_module_filter("policy_scanner")
        return json.dumps(
            {
                "status": "completed",
                "policy_name": policy_name,
                "policy_text": policy_text,
                "findings_count": len(policy_findings),
                "findings": policy_findings,
            },
            ensure_ascii=False,
        )
    except Exception as error:
        error_msg = str(error)
        if "permission denied" in error_msg.lower() or "403" in error_msg:
            return json.dumps(
                {"status": "denied", "policy_name": policy_name,
                 "message": f"Token cannot read policy '{policy_name}': {error_msg}"},
                ensure_ascii=False,
            )
        return json.dumps(
            {"status": "error", "policy_name": policy_name, "message": error_msg},
            ensure_ascii=False,
        )


# ─── Raw Vault API Request ──────────────────────────────────────────────────

@mcp_server.tool(
    name="run_raw_vault_request",
    description=(
        "Ham Vault API istegi gonder. Token OPSIYONELDIR — AppRole login, "
        "userpass login gibi unauthenticated islemler icin token='' veya token=None "
        "gonder (X-Vault-Token header eklenmez). Token verilirse authenticate edilmis "
        "istek yapilir. GET/POST/PUT/DELETE. "
        "Kullaniciya curl komutu onermek yerine BU TOOL'U KULLAN. "
        "Ornek AppRole login: method='POST', path='auth/approle/login', "
        "body={'role_id':'...', 'secret_id':'...'}, token=''. "
        "ONEMLI: Ayni islemi yapan bir AKTIF MODUL varsa (seal, unseal, "
        "database harvest, privilege escalation vb) MODULU KULLAN. "
        "Bu tool SADECE modul olmayan ozel islemler icindir."
    ),
)
async def run_raw_vault_request(
    vault_addr: str,
    method: str,
    path: str,
    token: Optional[str] = None,
    body: Optional[dict[str, Any]] = None,
    namespace: Optional[str] = None,
) -> str:
    """Execute a raw Vault API request, optionally authenticated."""
    import requests
    from core.tls_config import get_verify

    # ── Redirect to dedicated modules when they exist ──────────────────
    _module_paths = {
        "sys/seal": "vault_seal.seal_vault",
        "sys/unseal": "vault_seal.unseal_vault",
        "sys/seal-status": "vault_seal.seal_status",
    }
    # Tolerate paths passed with a leading "v1/" (LLMs often include it):
    # "v1/sys/health" would otherwise become /v1/v1/sys/health and 403/404.
    _clean_path = path.strip("/")
    if _clean_path.startswith("v1/"):
        _clean_path = _clean_path[3:]
    if _clean_path in _module_paths:
        return json.dumps(
            {
                "status": "redirect",
                "message": (
                    f"'{path}' icin dedicated modul var: '{_module_paths[_clean_path]}'. "
                    f"Bu islemi run_active_module ile yap. Ornek: "
                    f"run_active_module(module_id='{_module_paths[_clean_path]}', ...)"
                ),
            },
            ensure_ascii=False,
        )

    allowed_methods = {"GET", "POST", "PUT", "DELETE", "LIST"}
    method = method.upper()
    if method not in allowed_methods:
        return json.dumps(
            {"status": "error", "message": f"Invalid method: {method}. Use GET/POST/PUT/DELETE/LIST."},
            ensure_ascii=False,
        )

    base_url = vault_addr.rstrip("/")
    if _clean_path == "ui" or _clean_path.startswith("ui/"):
        # The Vault UI is served at /ui, not under /v1
        url = f"{base_url}/{_clean_path}"
    else:
        url = f"{base_url}/v1/{_clean_path}"
    headers = {"Content-Type": "application/json"}
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    if token:
        headers["X-Vault-Token"] = token

    try:
        if method in ("POST", "PUT"):
            resp = requests.request(method, url, headers=headers, json=body or {},
                                     verify=get_verify(), timeout=10)
        else:
            resp = requests.request(method, url, headers=headers,
                                     verify=get_verify(), timeout=10)

        try:
            data = resp.json()
        except ValueError:
            data = {"raw_text": resp.text[:500]}

        if resp.status_code >= 400:
            return json.dumps(
                {"status": "failed", "http_status": resp.status_code,
                 "method": method, "path": path, "response": data},
                ensure_ascii=False,
            )

        return json.dumps(
            {"status": "success", "http_status": resp.status_code,
             "method": method, "path": path, "response": data},
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps(
            {"status": "error", "method": method, "path": path, "message": str(error)},
            ensure_ascii=False,
        )


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
    except Exception as error:
        return json.dumps(
            {"status": "error", "message": str(error)},
            ensure_ascii=False,
        )


# ─── Web Search ──────────────────────────────────────────────────────


@mcp_server.tool(
    name="web_search",
    description=(
        "Web'de arama yapar. Vault CVE'leri, exploit detayları, konfigürasyon "
        "referansları ve hata mesajları için kullanılır. Sonuçlar 24 saat önbelleklenir."
    ),
)
async def web_search(
    query: str,
    max_results: int = 5,
    prefer_domains: list[str] | None = None,
    fetch_top_n: int = 0,
) -> str:
    try:
        from ai_core.web_search import search_web

        results = await search_web(query, max_results=max_results,
                                   prefer_domains=prefer_domains,
                                   fetch_top_n=fetch_top_n)
        return json.dumps({
            "query": query,
            "total": len(results),
            "results": [
                {
                    "title": r["title"],
                    "url": r["url"],
                    "snippet": r["snippet"],
                    "full_text": r.get("full_text"),
                }
                for r in results
            ],
        }, ensure_ascii=False)
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
    clear_module_findings("privilege_escalation.token_abuse")
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
    clear_module_findings("secret_exfiltration.kv_dump")
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
        "Bu islem state-changing'dir: her cagri veritabaninda yeni bir kullanici olusturabilir. "
        "KRITIK: sys/mounts ciktisinda 'database/' mount'u gordugun anda BU ARACI MUTLAKA DENE. "
        "Token zayif gorunse bile database/creds/* okuma yetkisi olabilir — KV enumeration bos olsa bile "
        "bu araci atlama. DB admin credential'lari bu sayede ele gecirilir."
    ),
)
async def run_database_credential_harvest(
    vault_addr: str,
    token: Optional[str] = None,
    mount_path: Optional[str] = None,
    namespace: Optional[str] = None,
) -> str:
    clear_module_findings("database_credential_harvest.dynamic_creds")
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
    clear_module_findings("cloud_key_exfiltration.key_dump")
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
        "adimda yakalanan captured_token kullanilir. params modulu besleyen ek parametreleri tasir. "
        "ONEMLI: Modul 'blocked: exceeds max_risk' hatasi verirse, ayni modulu "
        "max_risk='destructive' ile tekrar cagirarak blokaji kaldirabilirsin. "
        "Kullanici 'bloklamayi kaldir' derse max_risk='destructive' ile yeniden dene."
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


# ─── Security MCP: Compliance Check ──────────────────────────────────────


@mcp_server.tool(
    name="run_compliance_check",
    description=(
        "Hedef Vault'a karsi CIS Benchmark kontrollerini calistirir. "
        "TLS, auth, audit, policy, token ve seal yapilandirmalarini "
        "en iyi uygulamalara gore denetler. Read-only, state-changing yok."
    ),
)
async def run_compliance_check(
    vault_addr: str,
    token: Optional[str] = None,
) -> str:
    """Basic CIS-aligned compliance check against a Vault instance."""
    checks: list[dict] = []
    passed = 0
    failed = 0

    try:
        import requests as req
        from core.tls_config import get_verify

        base = vault_addr.rstrip("/")
        h = {"X-Vault-Token": token} if token else {}
        # Disable TLS verification for localhost/self-signed certs
        verify = base.startswith("https://") and "localhost" not in base

        # ── CIS 1.1: Ensure TLS is enabled ──────────────────────────
        try:
            r = req.get(f"{base}/v1/sys/health", headers=h, verify=verify, timeout=5)
            is_https = base.startswith("https")
            checks.append({
                "id": "CIS-1.1", "title": "TLS enabled",
                "status": "PASS" if is_https else "FAIL",
                "detail": "Vault serves over HTTPS" if is_https else "Vault serves over HTTP — enable TLS",
            })
            if is_https: passed += 1
            else: failed += 1
        except Exception as e:
            checks.append({"id": "CIS-1.1", "title": "TLS enabled", "status": "ERROR", "detail": str(e)})

        # ── CIS 2.1: Audit device enabled ───────────────────────────
        if token:
            try:
                r = req.get(f"{base}/v1/sys/audit", headers=h, verify=verify, timeout=5)
                audit_data = r.json() if r.status_code == 200 else {}
                has_audit = bool(audit_data.get("data", {}))
                checks.append({
                    "id": "CIS-2.1", "title": "Audit logging enabled",
                    "status": "PASS" if has_audit else "FAIL",
                    "detail": f"Audit devices: {list(audit_data.get('data', {}).keys())}" if has_audit
                    else "No audit devices enabled — enable audit logging",
                })
                if has_audit: passed += 1
                else: failed += 1
            except Exception:
                checks.append({"id": "CIS-2.1", "title": "Audit logging enabled", "status": "SKIP", "detail": "Token cannot read sys/audit"})

        # ── CIS 3.1: Root token not in use ──────────────────────────
        if token:
            try:
                r = req.get(f"{base}/v1/auth/token/lookup-self", headers=h, verify=verify, timeout=5)
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    is_root = "root" in data.get("policies", [])
                    checks.append({
                        "id": "CIS-3.1", "title": "Root token not in active use",
                        "status": "FAIL" if is_root else "PASS",
                        "detail": "Root token in use — create named admin policies instead" if is_root
                        else "Token is not root",
                    })
                    if not is_root: passed += 1
                    else: failed += 1
            except Exception:
                checks.append({"id": "CIS-3.1", "title": "Root token not in use", "status": "SKIP", "detail": "Cannot verify token identity"})

        # ── CIS 4.1: Seal status check ──────────────────────────────
        try:
            r = req.get(f"{base}/v1/sys/seal-status", headers=h, verify=verify, timeout=5)
            if r.status_code == 200:
                sealed = r.json().get("sealed", True)
                checks.append({
                    "id": "CIS-4.1", "title": "Vault is unsealed",
                    "status": "PASS" if not sealed else "FAIL",
                    "detail": "Vault is sealed — unseal it" if sealed else "Vault is unsealed and operational",
                })
                if not sealed: passed += 1
                else: failed += 1
        except Exception:
            checks.append({"id": "CIS-4.1", "title": "Vault is unsealed", "status": "ERROR", "detail": "Cannot reach Vault"})

        # ── CIS 5.1: CORS not wildcard ──────────────────────────────
        if token:
            try:
                r = req.get(f"{base}/v1/sys/config/cors", headers=h, verify=verify, timeout=5)
                if r.status_code == 200:
                    cors = r.json().get("data", {})
                    origins = cors.get("allowed_origins", [])
                    has_wildcard = "*" in origins
                    checks.append({
                        "id": "CIS-5.1", "title": "CORS not wildcard",
                        "status": "FAIL" if has_wildcard else "PASS",
                        "detail": "Wildcard CORS origin: *" if has_wildcard
                        else f"Allowed origins: {origins}",
                    })
                    if not has_wildcard: passed += 1
                    else: failed += 1
            except Exception:
                checks.append({"id": "CIS-5.1", "title": "CORS not wildcard", "status": "SKIP", "detail": "Token cannot read CORS config"})

        score = round((passed / max(passed + failed, 1)) * 100)
        return json.dumps({
            "status": "completed",
            "compliance_score": score,
            "passed": passed,
            "failed": failed,
            "total_checks": len(checks),
            "checks": checks,
        }, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


# ─── Security MCP: Network Probe ──────────────────────────────────────────


@mcp_server.tool(
    name="run_network_probe",
    description=(
        "Hedef Vault adresine karsi hafif ag taramasi yapar. "
        "Port erisimi, HTTP/HTTPS yanit sureleri, rate-limiting varligi, "
        "redirect zincirleri ve TLS sertifika zincirini analiz eder. "
        "Aktif exploitation yok — sadece ag katmani bilgi toplama."
    ),
)
async def run_network_probe(
    vault_addr: str,
    ports: Optional[list[int]] = None,
) -> str:
    """Lightweight network probe of a Vault target."""
    import socket
    import ssl
    import time as _time

    target = vault_addr.rstrip("/")
    # Extract host and port from URL
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 8200)

    checks: list[dict] = []
    scan_ports = ports or [port, 8200, 8201, 443, 80]

    # ── Port scan ───────────────────────────────────────────────────
    for p in scan_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = _time.monotonic()
            result = sock.connect_ex((host, p))
            elapsed = (_time.monotonic() - start) * 1000
            sock.close()
            checks.append({
                "port": p,
                "open": result == 0,
                "latency_ms": round(elapsed, 1),
                "service": {8200: "Vault API", 8201: "Vault Cluster", 443: "HTTPS", 80: "HTTP"}.get(p, "unknown"),
            })
        except Exception as e:
            checks.append({"port": p, "open": False, "error": str(e)})

    # ── HTTP response timing ────────────────────────────────────────
    try:
        import requests as req
        from core.tls_config import get_verify

        start = _time.monotonic()
        r = req.get(f"{target}/v1/sys/health", verify=get_verify(), timeout=5)
        elapsed = (_time.monotonic() - start) * 1000

        # Check rate-limit headers
        rate_limit_headers = {
            k: v for k, v in r.headers.items()
            if "rate" in k.lower() or "limit" in k.lower()
        }

        checks.append({
            "type": "http_response",
            "status_code": r.status_code,
            "response_time_ms": round(elapsed, 1),
            "server_header": r.headers.get("Server", "not set"),
            "rate_limiting": bool(rate_limit_headers),
            "rate_limit_headers": rate_limit_headers,
        })
    except Exception as e:
        checks.append({"type": "http_response", "error": str(e)})

    # ── TLS certificate chain ───────────────────────────────────────
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            ssock.connect((host, port))
            cert = ssock.getpeercert(binary_form=False)
            cert_bin = ssock.getpeercert(binary_form=True)
            ssock.close()

            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            try:
                parsed_cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                issuer = str(parsed_cert.issuer)
                subject = str(parsed_cert.subject)
                not_after = parsed_cert.not_valid_after_utc.isoformat()
                is_self_signed = issuer == subject
            except Exception:
                issuer = cert.get("issuer", "unknown")
                subject = cert.get("subject", "unknown")
                not_after = cert.get("notAfter", "unknown")
                is_self_signed = False

            checks.append({
                "type": "tls_certificate",
                "subject": str(subject)[:200],
                "issuer": str(issuer)[:200],
                "expires": str(not_after),
                "self_signed": is_self_signed,
            })
        except Exception as e:
            checks.append({"type": "tls_certificate", "error": str(e)})

    return json.dumps({
        "status": "completed",
        "host": host,
        "target_port": port,
        "checks": checks,
    }, ensure_ascii=False)


# ─── Security MCP: Full Report Export ─────────────────────────────────────


@mcp_server.tool(
    name="export_full_report",
    description=(
        "Tum bulgulari JSON + Markdown + PDF olarak tek cagrida disari aktarir. "
        "Uc rapor formatini da ayni anda uretir, dosya yollarini dondurur. "
        "output_prefix verilmezse 'pentest_report_<timestamp>' kullanilir."
    ),
)
async def export_full_report(
    output_prefix: Optional[str] = None,
    target: Optional[str] = None,
) -> str:
    """Generate JSON, Markdown, and PDF reports in one call."""
    from datetime import datetime
    from core.report import (
        export_json_report,
        export_markdown_report,
        export_pdf_report,
        findings,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = output_prefix or f"pentest_report_{ts}"

    result = {"status": "completed", "findings_count": len(findings), "reports": {}}

    # JSON
    json_path = export_json_report(f"{prefix}.json", target=target)
    if json_path:
        result["reports"]["json"] = str(json_path)

    # Markdown
    md_path = export_markdown_report(f"{prefix}.md", target=target)
    if md_path:
        result["reports"]["markdown"] = str(md_path)

    # PDF
    try:
        pdf_path = export_pdf_report(f"{prefix}.pdf", target=target)
        if pdf_path:
            result["reports"]["pdf"] = str(pdf_path)
    except Exception as e:
        result["reports"]["pdf_error"] = str(e)

    return json.dumps(result, ensure_ascii=False)


# ─── Security MCP: Webhook Notification ────────────────────────────────────


@mcp_server.tool(
    name="send_notification",
    description=(
        "Pentest sonuclarini webhook uzerinden gonderir. Slack, Discord, Teams "
        "veya ozel webhook URL'lerine JSON payload gonderir. "
        "Bulgulari ozetler ve en kritik 5 bulguyu iletir."
    ),
)
async def send_notification(
    webhook_url: str,
    target: Optional[str] = None,
    notification_type: str = "slack",
) -> str:
    """Send pentest results summary to a webhook (Slack/Discord/Teams)."""
    import requests as req
    from core.report import findings
    from core.risk_score import calculate_risk

    risk = calculate_risk(findings)

    # Build summary
    critical = [f for f in findings if f.get("severity") == "CRITICAL"][:5]
    high = [f for f in findings if f.get("severity") == "HIGH"][:3]

    summary_lines = [
        f"🔒 Vault Pentest Complete",
        f"Target: {target or 'unknown'}",
        f"Risk Score: {risk['score']}/100 ({risk['grade']})",
        f"Findings: {len(findings)} total",
    ]

    for f in critical:
        summary_lines.append(f"  🔴 [{f['severity']}] {f['title']}")
    for f in high:
        summary_lines.append(f"  🟠 [{f['severity']}] {f['title']}")

    summary = "\n".join(summary_lines)

    # Build payload for different types
    if notification_type == "slack":
        payload = {"text": summary, "username": "Vault Pentest Bot"}
    elif notification_type == "discord":
        payload = {"content": summary, "username": "Vault Pentest Bot"}
    elif notification_type == "teams":
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "title": "Vault Pentest Complete",
            "text": summary,
        }
    else:
        payload = {"text": summary, "findings_count": len(findings), "risk": risk}

    try:
        r = req.post(webhook_url, json=payload, timeout=10)
        return json.dumps({
            "status": "sent" if r.status_code in (200, 204) else "failed",
            "http_status": r.status_code,
            "notification_type": notification_type,
            "summary": summary,
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


# ─── Security MCP: Audit Log Scanner ──────────────────────────────────────


@mcp_server.tool(
    name="run_audit_log_scan",
    description=(
        "Vault audit log'larini (yerel dosya veya API uzerinden) anomali ve "
        "guvenlik olaylari icin tarar. Supheli token kullanimlari, "
        "yetkisiz erisim denemeleri ve policy degisikliklerini tespit eder."
    ),
)
async def run_audit_log_scan(
    audit_log_path: Optional[str] = None,
    vault_addr: Optional[str] = None,
    token: Optional[str] = None,
    max_lines: int = 10000,
) -> str:
    """Scan Vault audit logs for suspicious activity patterns."""
    findings: list[dict] = []
    total_lines = 0

    # Patterns to detect
    suspicious_patterns = {
        "auth/token/create": ("Token creation", "MEDIUM"),
        "sys/policy": ("Policy modification", "HIGH"),
        "sys/audit": ("Audit device modification", "CRITICAL"),
        "sys/seal": ("Seal operation", "CRITICAL"),
        "sys/unseal": ("Unseal operation", "HIGH"),
        "sys/auth": ("Auth method modification", "HIGH"),
        "permission denied": ("Access denied", "LOW"),
        "auth/userpass/login": ("Userpass login", "LOW"),
        "auth/approle/login": ("AppRole login", "LOW"),
    }

    # ── Scan local audit log ──────────────────────────────────────────
    if audit_log_path:
        try:
            import os
            if os.path.isfile(audit_log_path):
                with open(audit_log_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        total_lines += 1
                        if total_lines > max_lines:
                            break
                        line_lower = line.lower()
                        for pattern, (title, severity) in suspicious_patterns.items():
                            if pattern.lower() in line_lower:
                                try:
                                    import json as _json
                                    entry = _json.loads(line.strip())
                                    findings.append({
                                        "severity": severity,
                                        "title": title,
                                        "description": f"Audit log: {pattern}",
                                        "evidence": line.strip()[:300],
                                        "module": "audit_log_scanner",
                                    })
                                except Exception:
                                    findings.append({
                                        "severity": severity,
                                        "title": title,
                                        "description": f"Audit log: {pattern}",
                                        "evidence": line.strip()[:300],
                                        "module": "audit_log_scanner",
                                    })
                                break
            else:
                return json.dumps({
                    "status": "error",
                    "message": f"Audit log file not found: {audit_log_path}",
                }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": f"Cannot read audit log: {e}",
            }, ensure_ascii=False)

    # ── Scan via Vault API (if token provided) ────────────────────────
    elif vault_addr and token:
        try:
            import requests as req
            from core.tls_config import get_verify

            # Check if audit is enabled
            r = req.get(
                f"{vault_addr.rstrip('/')}/v1/sys/audit",
                headers={"X-Vault-Token": token},
                verify=get_verify(),
                timeout=5,
            )
            if r.status_code == 200:
                audit_data = r.json().get("data", {})
                if not audit_data:
                    findings.append({
                        "severity": "HIGH",
                        "title": "Audit logging not enabled",
                        "description": "No audit devices found — Vault operations are not being logged.",
                        "module": "audit_log_scanner",
                    })
                else:
                    for audit_path in audit_data:
                        findings.append({
                            "severity": "INFO",
                            "title": "Audit device found",
                            "description": f"Audit device at {audit_path}: {audit_data[audit_path].get('type', 'unknown')}",
                            "module": "audit_log_scanner",
                        })
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

    return json.dumps({
        "status": "completed",
        "lines_scanned": total_lines,
        "suspicious_events": len(findings),
        "findings": findings,
    }, ensure_ascii=False)


# ─── Security MCP: Container Security Scanner ──────────────────────────────


@mcp_server.tool(
    name="run_container_scan",
    description=(
        "Vault'un Docker/Kubernetes konteyner icinde calisip calismadigini kontrol eder. "
        "Konteyner guvenligi en iyi uygulamalarina gore: root kullanici, "
        "cap_add=IPC_LOCK, memory limitleri, read-only root filesystem gibi "
        "konulari denetler. Docker socket veya Kubernetes API'ye erisim gerekir."
    ),
)
async def run_container_scan(
    container_name: Optional[str] = None,
    vault_addr: Optional[str] = None,
) -> str:
    """Scan Vault container for security misconfigurations."""
    findings: list[dict] = []
    target_container = container_name or "vault-target"

    # ── Docker inspect (if available) ────────────────────────────────
    try:
        import subprocess

        r = subprocess.run(
            ["docker", "inspect", target_container],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            import json as _json
            data = _json.loads(r.stdout)
            if data:
                config = data[0]
                host_config = config.get("HostConfig", {})
                container_config = config.get("Config", {})

                # Check: root user?
                user = container_config.get("User", "root")
                if user in ("root", "0:0", ""):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "Container running as root",
                        "description": "Vault container runs as root. Use a non-root user for production.",
                        "module": "container_scanner",
                    })

                # Check: IPC_LOCK (needed for mlock)
                cap_add = host_config.get("CapAdd", [])
                if "IPC_LOCK" in cap_add:
                    findings.append({
                        "severity": "PASS",
                        "title": "IPC_LOCK capability present",
                        "description": "mlock can work correctly for memory locking.",
                        "module": "container_scanner",
                    })
                else:
                    findings.append({
                        "severity": "LOW",
                        "title": "IPC_LOCK missing",
                        "description": "Add cap_add: [IPC_LOCK] for mlock support.",
                        "module": "container_scanner",
                    })

                # Check: Memory limits
                memory = host_config.get("Memory", 0)
                if memory == 0:
                    findings.append({
                        "severity": "LOW",
                        "title": "No memory limit set",
                        "description": "Set a memory limit to prevent OOM attacks.",
                        "module": "container_scanner",
                    })

                # Check: Read-only rootfs
                if host_config.get("ReadonlyRootfs", False):
                    findings.append({
                        "severity": "PASS",
                        "title": "Read-only root filesystem",
                        "description": "Container rootfs is read-only.",
                        "module": "container_scanner",
                    })

                # Check: Privileged mode
                if host_config.get("Privileged", False):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "Container runs in privileged mode",
                        "description": "Privileged containers escape namespaces — remove --privileged flag.",
                        "module": "container_scanner",
                    })

                # Check: Ports exposed
                ports = host_config.get("PortBindings", {})
                findings.append({
                    "severity": "INFO",
                    "title": f"Exposed ports: {list(ports.keys())}",
                    "description": f"Container exposes ports: {list(ports.keys())}",
                    "module": "container_scanner",
                })

        else:
            # Try docker-compose
            r2 = subprocess.run(
                ["docker", "ps", "--filter", f"name={target_container}", "--format", "{{.Names}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=5,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                findings.append({
                    "severity": "INFO",
                    "title": "Container found",
                    "description": f"Container status: {r2.stdout.strip()}",
                    "module": "container_scanner",
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "title": "No Docker container found",
                    "description": "Vault may be running natively or Docker is not accessible.",
                    "module": "container_scanner",
                })
    except FileNotFoundError:
        findings.append({
            "severity": "INFO",
            "title": "Docker not available",
            "description": "Docker CLI not found — cannot scan containers.",
            "module": "container_scanner",
        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "title": "Container scan limited",
            "description": f"Docker inspect failed: {e}",
            "module": "container_scanner",
        })

    return json.dumps({
        "status": "completed",
        "container": target_container,
        "findings_count": len(findings),
        "findings": findings,
    }, ensure_ascii=False)


# ─── Security MCP: Threat Intelligence ─────────────────────────────────────


@mcp_server.tool(
    name="get_threat_intel",
    description=(
        "HashiCorp Vault ile ilgili en son guvenlik tehditlerini, CVE'leri "
        "ve guvenlik bultenlerini arar. NVD cache + web search kullanarak "
        "guncel tehdit istihbarati saglar."
    ),
)
async def get_threat_intel(
    vault_version: Optional[str] = None,
) -> str:
    """Fetch latest threat intelligence for HashiCorp Vault."""
    threats: list[dict] = []

    # ── Check NVD cache ───────────────────────────────────────────────
    try:
        from reconnaissance.nvd_client import _load_cache
        cache = _load_cache()
        cves = cache.get("cves", [])
        if cves:
            # Filter critical/high CVEs
            for cve in cves:
                if cve.get("severity") in ("CRITICAL", "HIGH"):
                    threats.append({
                        "source": "NVD",
                        "cve_id": cve.get("cve_id"),
                        "severity": cve.get("severity"),
                        "summary": cve.get("summary", "")[:200],
                        "published": cve.get("published", ""),
                    })
    except Exception:
        pass

    # ── Version-specific check ────────────────────────────────────────
    if vault_version:
        try:
            from reconnaissance.version_cve_matcher import match_version
            matches = match_version(vault_version)
            for m in matches:
                threats.append({
                    "source": "CVE Matcher",
                    "cve_id": m.get("cve_id"),
                    "severity": m.get("severity", "MEDIUM"),
                    "summary": m.get("summary", f"CVE matches version {vault_version}")[:200],
                    "matched_version": vault_version,
                })
        except Exception:
            pass

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats.sort(key=lambda t: sev_order.get(t.get("severity", ""), 99))

    return json.dumps({
        "status": "completed",
        "threat_count": len(threats),
        "vault_version": vault_version,
        "threats": threats[:20],
        "last_updated": "check NVD cache for fetch date",
    }, ensure_ascii=False)


# ─── Security MCP: Diff Report ────────────────────────────────────────────


@mcp_server.tool(
    name="generate_diff_report",
    description=(
        "Iki tarama sonucu arasindaki farki karsilastirir. "
        "Yeni bulgular, kapanmis bulgular ve degismis severity'leri tespit eder. "
        "onceki_json_path ve suanki bulgular arasinda diff cikarir."
    ),
)
async def generate_diff_report(
    previous_json_path: str,
    target: Optional[str] = None,
) -> str:
    """Compare current findings with a previous scan JSON export."""
    from core.report import findings as current_findings
    import os

    if not os.path.isfile(previous_json_path):
        return json.dumps({
            "status": "error",
            "message": f"Previous report not found: {previous_json_path}",
        }, ensure_ascii=False)

    try:
        with open(previous_json_path, "r", encoding="utf-8") as f:
            prev_data = json.load(f)
        prev_findings = prev_data.get("findings", [])
    except Exception as e:
        return json.dumps({
            "status": "error", "message": f"Cannot read previous report: {e}",
        }, ensure_ascii=False)

    # Build keys for comparison: (severity, title)
    current_keys = {(f.get("severity"), f.get("title")) for f in current_findings}
    prev_keys = {(f.get("severity"), f.get("title")) for f in prev_findings}

    new_findings = [f for f in current_findings if (f.get("severity"), f.get("title")) not in prev_keys]
    resolved_findings = [f for f in prev_findings if (f.get("severity"), f.get("title")) not in current_keys]
    unchanged = len(current_keys & prev_keys)

    # Severity changes: same title, different severity
    prev_by_title = {f.get("title"): f.get("severity") for f in prev_findings}
    severity_changes = []
    for f in current_findings:
        title = f.get("title")
        if title in prev_by_title and prev_by_title[title] != f.get("severity"):
            severity_changes.append({
                "title": title,
                "previous_severity": prev_by_title[title],
                "current_severity": f.get("severity"),
            })

    return json.dumps({
        "status": "completed",
        "previous_findings": len(prev_findings),
        "current_findings": len(current_findings),
        "new": len(new_findings),
        "resolved": len(resolved_findings),
        "unchanged": unchanged,
        "severity_changes": len(severity_changes),
        "new_findings": new_findings[:20],
        "resolved_findings": resolved_findings[:20],
        "severity_change_details": severity_changes[:20],
    }, ensure_ascii=False)


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