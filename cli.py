"""Vault Pentest Tool — Typer CLI entry point.

Commands:
    scan     Full pentest assessment (default)
    hijack   Credential hijacking scan
    chat     AI-powered chat agent
    mcp      Start MCP server

Usage:
    python cli.py scan --target http://localhost:8200 --token ROOT
    python cli.py hijack --path ./repo
    python cli.py chat --provider deepseek
    python cli.py mcp
"""

from __future__ import annotations

import sys
from typing import Optional

# Suppress urllib3 InsecureRequestWarning spam — this is a pentest tool,
# self-signed certs are the norm, not the exception.
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import typer

from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.registry import RiskLevel, risk_level_allowed
from ai_core.chat_ui import start_chat_session
from ai_core.dynamic_session import global_store
from core.client import VaultClient
from core.report import (
    add_finding,
    clear_findings,
    export_json_report,
    export_markdown_report,
    print_report,
    set_report_min_severity,
)
from credential_hijacking.hijack_analyzer import run_hijack_scan
from credential_hijacking.validators import validate_approle_credentials
from reconnaissance.auth_surface_scanner import scan_auth_surface
from reconnaissance.cors_scanner import scan_cors
from reconnaissance.deployment_scanner import scan_deployment
from reconnaissance.endpoint_scanner import scan_endpoints
from reconnaissance.fingerprint_scanner import scan_fingerprint
from reconnaissance.header_scanner import scan_headers
from reconnaissance.health_scanner import scan_health
from reconnaissance.nvd_client import fetch_vault_cves_from_nvd
from reconnaissance.recon_context import ReconContext
from reconnaissance.tls_scanner import scan_tls
from reconnaissance.ui_scanner import scan_ui
from reconnaissance.version_risk_scanner import scan_version_risk
from reconnaissance.vault_recon import scan_vault_recon
from scanners.auth_config_scanner import scan_auth_config_security
from scanners.capability_scanner import audit_token_capabilities
from scanners.env_scanner import scan_environment, scan_vault_token_file
from scanners.kv_enumerator import scan_kv_tree
from scanners.policy_scanner import read_policy, analyze_policy
from scanners.privilege_escalation_scanner import scan_privilege_escalation
from scanners.secret_scanner import test_secret_read
from scanners.token_scanner import check_token, analyze_token
from scanners.ttl_scanner import (
    DEFAULT_MAX_MOUNT_TTL_SECONDS,
    DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
    scan_ttl_governance,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RISK_LEVELS = [e.value for e in RiskLevel]

MODULE_CHOICES = [
    "privilege_escalation.token_abuse",
    "secret_exfiltration.kv_dump",
    "database_credential_harvest.dynamic_creds",
    "cloud_key_exfiltration.key_dump",
    "token_exploit.creation",
    "policy_exploit.modification",
    "audit_backdoor.disable",
    "cve_scanner.scan",
    "database_pivot.exploit",
    "cloud_pivot.exploit",
    "persistence.backdoor",
    "raft_storage.exploit",
    "unseal_key.exfiltration",
    "database_exploit.exploit",
    "cloud_exploit.exploit",
    "multi_persistence.backdoor",
    "payload_module.reverse_shell",
    "unauthenticated.attack",
    "pivot_engine.cross_service",
]

PROVIDER_CHOICES = ["aws", "azure", "gcp", "ollama", "openai", "anthropic", "deepseek", "kimi", "cursor"]
SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
DB_TYPE_CHOICES = ["postgres", "mysql", "mssql"]

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="vault-pentest",
    help="HashiCorp Vault penetration testing tool",
    no_args_is_help=True,
    add_completion=False,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_registry():
    from active_execution.modules import get_default_registry
    return get_default_registry()


def _run_unauthenticated_recon(target: str) -> None:
    print("\n======================================")
    print("Unauthenticated Vault Reconnaissance")
    print("======================================")
    context = ReconContext(target)
    context.fetch_health_once()
    scan_tls(target)
    scan_health(target, context=context)
    scan_version_risk(target, context=context)
    scan_fingerprint(target, context=context)
    scan_ui(target, context=context)
    scan_auth_surface(target, context=context)
    scan_deployment(target, context=context)
    scan_cors(target, context=context)
    scan_headers(target, context=context)
    scan_endpoints(target, context=context)


def _sync_session_from_context(ctx: ExecutionContext) -> None:
    """Feed tokens discovered by active modules back into the global store."""
    for attr in ("captured_token", "escalated_token"):
        token = getattr(ctx, attr, None)
        if token and token not in global_store.tokens:
            global_store.add_token(
                token,
                source=f"active_execution.{attr}",
                power_level="elevated" if attr == "escalated_token" else "unknown",
            )


def _resolve_target(target: str | None, addr: str | None) -> str | None:
    return target or addr


def _run_ai_analysis(
    vault_addr: str | None,
    ai_provider: str,
    ai_model: str | None,
) -> None:
    """Run LLM-powered analysis of scan findings and print a rich summary."""
    from core.report import findings as current_findings
    from core.risk_score import calculate_risk

    if not current_findings:
        print("\n[*] AI analysis skipped — no findings to analyze.")
        return

    print("\n" + "=" * 54)
    print("  AI-POWERED FINDING ANALYSIS")
    print("=" * 54)

    try:
        from ai_core.llm_engine import LLMClient
        from ai_core.models import get_default_model

        provider = ai_provider
        model = ai_model or get_default_model(provider)

        print(f"  Provider : {provider}")
        print(f"  Model    : {model}")
        print(f"  Findings : {len(current_findings)}")

        client = LLMClient(provider=provider, model=model)
        if not client.is_available():
            print(f"\n[!] Provider '{provider}' not available — check API key.")
            print(f"    Set {provider.upper()}_API_KEY environment variable.")
            return

        # Build a compact findings summary
        risk = calculate_risk(current_findings)
        sev_counts: dict[str, int] = {}
        for f in current_findings:
            sev = f.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        findings_text = "\n".join(
            f"[{f.get('severity', '?')}] {f.get('title', '')}"
            for f in current_findings[:30]
        )
        if len(current_findings) > 30:
            findings_text += f"\n... and {len(current_findings) - 30} more"

        prompt = (
            f"You are a Vault security expert analyzing pentest results.\n\n"
            f"Target: {vault_addr or 'unknown'}\n"
            f"Risk Score: {risk['score']}/100 ({risk['grade']})\n"
            f"Severity breakdown: {sev_counts}\n"
            f"Total findings: {len(current_findings)}\n\n"
            f"=== TOP FINDINGS ===\n{findings_text}\n=== END ===\n\n"
            f"Provide a concise 1-paragraph EXECUTIVE SUMMARY (business risk level).\n"
            f"Then list the TOP 5 MOST CRITICAL issues with:\n"
            f"  - Why it matters (one sentence)\n"
            f"  - The SINGLE most impactful fix (Vault CLI command or config change)\n"
            f"Use a table format where possible. Be specific — no vague advice.\n"
            f"Respond in the same language as the findings (Turkish/English)."
        )

        print("\n  Analyzing with AI...\n")
        response = client.chat(
            system_prompt="You are a senior Vault security consultant. Analyze pentest findings and provide actionable, specific remediation advice with exact CLI commands.",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2048,
        )

        content = response.get("content", "")
        if content:
            print(content)
        else:
            error = response.get("raw", "unknown error")
            print(f"\n[!] AI analysis failed: {error}")

    except ImportError as e:
        print(f"\n[!] AI analysis unavailable — missing dependency: {e}")
    except Exception as e:
        print(f"\n[!] AI analysis error: {e}")

    print("=" * 54)


def _export_reports(json_path: str | None, markdown_path: str | None, target: str | None) -> None:
    if json_path:
        export_json_report(json_path, target=target)
    if markdown_path:
        export_markdown_report(markdown_path, target=target)


def _run_single_module(
    module_id: str,
    vault_addr: str | None,
    token: str | None,
    namespace: str | None,
    active_max_risk: str,
    confirm_active: bool,
    hijack_path: str | None,
    provider: str | None,
    region: str,
    subscription_id: str | None,
    db_type: str,
    db_host: str | None,
    db_port: int | None,
    db_name: str,
    auth_path: str,
    role_name: str,
    token_ttl: str,
    active_ttl: str,
    active_exfil_max_depth: int,
    active_policy: list[str] | None,
) -> None:
    registry = _build_registry()
    engine = ActiveExecutionEngine(registry)
    context = ExecutionContext(
        vault_addr=vault_addr,
        token=token,
        namespace=namespace,
    )

    module = registry.get(module_id)
    if not module:
        print(f"[-] Module not found: {module_id}")
        return

    max_risk = RiskLevel(active_max_risk)
    if not risk_level_allowed(module.risk_level, max_risk):
        print(f"[-] Module risk '{module.risk_level.value}' exceeds max_risk '{max_risk.value}'")
        return

    if module.risk_level != RiskLevel.READ_ONLY and not confirm_active:
        print(f"[-] Module requires --confirm-active for risk level: {module.risk_level.value}")
        return

    params: dict = {
        "ttl": active_ttl,
        "namespace": namespace,
        "max_depth": active_exfil_max_depth,
        "search_path": hijack_path or ".",
        "provider": provider,
        "region": region,
        "subscription_id": subscription_id,
        "db_type": db_type,
        "db_host": db_host,
        "db_port": db_port,
        "db_name": db_name,
        "auth_path": auth_path,
        "role_name": role_name,
        "token_ttl": token_ttl,
    }
    if active_policy:
        params["policies"] = active_policy

    engine.execute_plan(
        [{"module_id": module_id, "params": params}],
        context,
        max_risk=max_risk,
        confirm_state_changing=confirm_active,
    )

    for finding in context.findings:
        add_finding(
            finding["severity"],
            finding["title"],
            finding["description"],
            evidence=finding.get("evidence"),
            module="active_execution",
            target=vault_addr,
        )

    # Feed discovered tokens back into global session for auto-escalation
    _sync_session_from_context(context)


def _run_active_auto(
    vault_addr: str | None,
    token: str | None,
    namespace: str | None,
    active_max_risk: str,
    confirm_active: bool,
    active_ttl: str,
    active_exfil_max_depth: int,
    active_policy: list[str] | None,
) -> None:
    registry = _build_registry()
    engine = ActiveExecutionEngine(registry)
    context = ExecutionContext(
        vault_addr=vault_addr,
        token=token,
        namespace=namespace,
    )
    max_risk = RiskLevel(active_max_risk)
    auto_steps: list[dict] = []

    for module_instance in registry.list_modules():
        if (
            getattr(module_instance, "default_enabled", False)
            and risk_level_allowed(module_instance.risk_level, max_risk)
        ):
            params: dict = {
                "ttl": active_ttl,
                "namespace": namespace,
                "max_depth": active_exfil_max_depth,
            }
            if active_policy:
                params["policies"] = active_policy
            auto_steps.append({
                "module_id": module_instance.module_id,
                "reason": "Automated active testing via auto-pilot execution engine.",
                "params": params,
            })

    if auto_steps:
        print(f"[*] Auto-pilot active execution initiated. Total tasks: {len(auto_steps)}")
        engine.execute_plan(
            auto_steps,
            context,
            max_risk=max_risk,
            confirm_state_changing=confirm_active,
        )
        for finding in context.findings:
            add_finding(
                finding["severity"],
                finding["title"],
                finding["description"],
                evidence=finding.get("evidence"),
                module="active_execution",
                target=vault_addr,
            )
    else:
        print("[-] No suitable active modules found for the current risk level.")

    # Feed discovered tokens back into global session
    _sync_session_from_context(context)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    # ── target ──
    target: Optional[str] = typer.Option(None, "--target", help="Target Vault URL, e.g. http://localhost:8200"),
    addr: Optional[str] = typer.Option(None, "--addr", help="Vault address (legacy alias for --target)"),
    token: Optional[str] = typer.Option(None, "--token", help="Vault token for authenticated checks"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Vault namespace"),
    skip_tls_verify: bool = typer.Option(False, "--skip-tls-verify", help="Disable TLS certificate verification"),
    # ── recon ──
    skip_recon: bool = typer.Option(False, "--skip-recon", help="Skip default unauthenticated recon"),
    vault_recon: bool = typer.Option(False, "--vault-recon", help="Run async Vault health/seal/leader recon"),
    nvd_refresh: bool = typer.Option(False, "--nvd-refresh", help="Force refresh NVD CVE cache"),
    # ── env ──
    env_scan: bool = typer.Option(False, "--env-scan", help="Scan local environment for Vault variables"),
    # ── authenticated audits ──
    validate_token: bool = typer.Option(False, "--validate-token", help="Validate discovered tokens"),
    validate_approle: bool = typer.Option(False, "--validate-approle", help="Validate discovered AppRole pairs"),
    role_id: Optional[str] = typer.Option(None, "--role-id", help="Role ID for AppRole validation"),
    secret_id: Optional[str] = typer.Option(None, "--secret-id", help="Secret ID for AppRole validation"),
    approle_mount: str = typer.Option("approle", "--approle-mount", help="AppRole auth mount path"),
    validate_db: bool = typer.Option(False, "--validate-db", help="Validate DB secrets engine metadata"),
    capability_audit: bool = typer.Option(False, "--capability-audit", help="Audit token capabilities"),
    capability_path: Optional[list[str]] = typer.Option(None, "--capability-path", help="Path for capability audit (repeatable)"),
    priv_esc_audit: bool = typer.Option(False, "--priv-esc-audit", help="Simulate privilege escalation risk"),
    token_policy: Optional[list[str]] = typer.Option(None, "--token-policy", help="Policy for priv-esc audit (repeatable)"),
    auth_config_audit: bool = typer.Option(False, "--auth-config-audit", help="Audit auth method configuration"),
    ttl_audit: bool = typer.Option(False, "--ttl-audit", help="Audit TTL governance"),
    max_mount_ttl_seconds: int = typer.Option(DEFAULT_MAX_MOUNT_TTL_SECONDS, "--max-mount-ttl-seconds"),
    max_pki_cert_ttl_seconds: int = typer.Option(DEFAULT_MAX_PKI_CERT_TTL_SECONDS, "--max-pki-cert-ttl-seconds"),
    # ── KV enumeration ──
    kv_enum: bool = typer.Option(False, "--kv-enum", help="Enumerate KV secret paths"),
    kv_path: Optional[str] = typer.Option(None, "--kv-path", help="KV start path for enumeration"),
    kv_version: Optional[int] = typer.Option(None, "--kv-version", help="KV engine version (1 or 2)"),
    kv_max_depth: int = typer.Option(10, "--kv-max-depth", help="Maximum KV recursion depth"),
    kv_concurrency: int = typer.Option(5, "--kv-concurrency", help="Max concurrent KV operations"),
    kv_no_read: bool = typer.Option(False, "--kv-no-read", help="Only list paths, don't read metadata"),
    kv_blind: bool = typer.Option(False, "--kv-blind", help="Brute-force common secret names on 403"),
    # ── secret / policy ──
    secret_path: str = typer.Option("secret/data/myapp", "--secret-path", help="Secret path to test"),
    policy: Optional[str] = typer.Option(None, "--policy", help="Policy name to analyze"),
    # ── active execution ──
    active_auto: bool = typer.Option(False, "--active-auto", help="Run default-enabled active execution modules"),
    active_max_risk: str = typer.Option(RiskLevel.READ_ONLY.value, "--active-max-risk", help="Max active execution risk level"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirm state-changing modules"),
    active_policy: Optional[list[str]] = typer.Option(None, "--active-policy", help="Policy for active token creation (repeatable)"),
    active_ttl: str = typer.Option("30m", "--active-ttl", help="TTL for active token creation"),
    active_exfil_max_depth: int = typer.Option(5, "--active-exfil-max-depth", help="Max KV depth for active exfiltration"),
    # ── single module ──
    module: Optional[str] = typer.Option(None, "--module", help="Run a single specific module"),
    db_pivot: bool = typer.Option(False, "--db-pivot", help="Enable database pivot module"),
    cloud_pivot: bool = typer.Option(False, "--cloud-pivot", help="Enable cloud pivot module"),
    persistence: bool = typer.Option(False, "--persistence", help="Enable persistence module"),
    pivot: bool = typer.Option(False, "--pivot", help="Enable cross-service pivot engine (DB -> OS -> infra)"),
    # ── module params ──
    provider: Optional[str] = typer.Option(None, "--provider", help="Cloud/LLM provider"),
    region: str = typer.Option("us-east-1", "--region", help="AWS region"),
    subscription_id: Optional[str] = typer.Option(None, "--subscription-id", help="Azure subscription ID"),
    db_type: str = typer.Option("postgres", "--db-type", help="Database type for pivot module"),
    db_host: Optional[str] = typer.Option(None, "--db-host", help="Database host"),
    db_port: Optional[int] = typer.Option(None, "--db-port", help="Database port"),
    db_name: str = typer.Option("postgres", "--db-name", help="Database name"),
    auth_path: str = typer.Option("approle-backdoor", "--auth-path", help="Auth path for persistence"),
    role_name: str = typer.Option("backdoor-role", "--role-name", help="Role name for persistence"),
    token_ttl: str = typer.Option("0", "--token-ttl", help="Token TTL for persistence (0=infinite)"),
    # ── hijack (inline) ──
    hijack_path: Optional[str] = typer.Option(None, "--hijack-path", help="Scan a path for leaked Vault credentials"),
    no_git_history: bool = typer.Option(False, "--no-git-history", help="Skip git history in hijack scan"),
    exclude_dir: Optional[list[str]] = typer.Option(None, "--exclude-dir", help="Exclude dir in hijack (repeatable)"),
    max_file_size_mb: int = typer.Option(5, "--max-file-size-mb", help="Max file size for hijack scan"),
    workers: int = typer.Option(0, "--workers", help="Parallel scanner workers (0=auto)"),
    # ── AI analysis ──
    ai_provider: Optional[str] = typer.Option(
        None, "--ai-provider",
        help="LLM provider for AI-powered finding analysis after scan (openai, anthropic, deepseek, kimi, cursor, ollama)",
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai-model",
        help="LLM model name for AI analysis. Auto-detected from provider if not set.",
    ),
    # ── reports ──
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Minimum severity to show/export"),
    json_report: Optional[str] = typer.Option(None, "--json", help="Export findings to JSON"),
    markdown_report: Optional[str] = typer.Option(None, "--markdown", help="Export findings to Markdown"),
    pdf_report: Optional[str] = typer.Option(None, "--pdf-report", help="Export findings to PDF with remediation"),
) -> None:
    """Run a full Vault pentest assessment.

    Add --ai-provider for LLM-powered analysis of findings after the scan.
    Example: python main.py scan --target URL --token TOKEN --ai-provider deepseek
    """
    clear_findings()

    # Register user token in global session for dynamic escalation
    if token:
        global_store.add_user_token(token)

    if skip_tls_verify:
        from core.tls_config import set_insecure_mode
        set_insecure_mode()
        print("[*] TLS certificate verification disabled")

    set_report_min_severity(min_severity)
    vault_addr = _resolve_target(target, addr)

    # ── Reconnaissance ──
    if vault_addr and not hijack_path and not vault_recon and not skip_recon:
        _run_unauthenticated_recon(vault_addr)

    if vault_addr and vault_recon:
        scan_vault_recon(vault_addr)

    if nvd_refresh:
        print("\n[+] Refreshing NVD CVE cache...")
        try:
            cves = fetch_vault_cves_from_nvd(force_refresh=True)
            print(f"[+] Cached {len(cves)} Vault-related CVEs from NVD.")
            if cves:
                for cve in cves[:10]:
                    print(f"    - {cve['cve_id']} [{cve['severity']}] {cve['summary'][:80]}...")
                if len(cves) > 10:
                    print(f"    ... and {len(cves) - 10} more")
        except Exception as error:
            print(f"[-] NVD refresh failed: {error}")

    # ── Credential hijacking ──
    if hijack_path:
        run_hijack_scan(
            hijack_path,
            vault_addr=vault_addr,
            token=token,
            validate_token=validate_token,
            validate_approle=validate_approle,
            validate_db=validate_db,
            include_git_history=not no_git_history,
            max_file_size_bytes=max_file_size_mb * 1024 * 1024,
            excluded_dirs=exclude_dir,
            max_workers=workers if workers > 0 else None,
        )

    # ── Environment scan ──
    if env_scan:
        scan_environment()
        scan_vault_token_file()

    # ── Authenticated audits ──
    if vault_addr and token and capability_audit:
        # Auto-generate paths from --kv-path for deeper coverage
        audit_paths = list(capability_path) if capability_path else None
        if kv_path and not audit_paths:
            mp = kv_path.rstrip("/")
            audit_paths = [
                f"{mp}/*",
                f"{mp}/data/*",
                f"{mp}/metadata/*",
                f"{mp}/data/admin/*",
                f"{mp}/data/production/*",
            ]
        audit_token_capabilities(vault_addr, token, paths=audit_paths, namespace=namespace)

    if vault_addr and token and priv_esc_audit:
        scan_privilege_escalation(vault_addr, token, policy_names=token_policy, namespace=namespace)

    if vault_addr and token and auth_config_audit:
        scan_auth_config_security(vault_addr, token, namespace=namespace)

    if vault_addr and token and ttl_audit:
        scan_ttl_governance(
            vault_addr, token,
            namespace=namespace,
            max_mount_ttl_seconds=max_mount_ttl_seconds,
            max_pki_cert_ttl_seconds=max_pki_cert_ttl_seconds,
        )

    if vault_addr and token and kv_enum:
        scan_kv_tree(
            vault_addr, token, kv_path,
            kv_version=kv_version,
            namespace=namespace,
            max_depth=kv_max_depth,
            concurrency=kv_concurrency,
            read_leaves=not kv_no_read,
            blind_brute=kv_blind,
        )

    # ── Single module / active execution ──
    requested_modules: list[str] = []
    if module:
        requested_modules.append(module)
    if db_pivot:
        requested_modules.append("database_pivot.exploit")
    if cloud_pivot:
        requested_modules.append("cloud_pivot.exploit")
    if persistence:
        requested_modules.append("persistence.backdoor")
    if pivot:
        requested_modules.append("pivot_engine.cross_service")
    requested_modules = list(dict.fromkeys(requested_modules))

    if requested_modules:
        for mod_id in requested_modules:
            _run_single_module(
                mod_id, vault_addr, token, namespace,
                active_max_risk, confirm_active, hijack_path,
                provider, region, subscription_id, db_type,
                db_host, db_port, db_name, auth_path, role_name,
                token_ttl, active_ttl, active_exfil_max_depth, active_policy,
            )

    if active_auto:
        _run_active_auto(
            vault_addr, token, namespace,
            active_max_risk, confirm_active,
            active_ttl, active_exfil_max_depth, active_policy,
        )

    # ── AppRole validation ──
    if vault_addr and validate_approle and role_id and secret_id:
        validate_approle_credentials(
            role_id, secret_id, vault_addr,
            mount_point=approle_mount,
            capability_paths=capability_path,
            namespace=namespace,
        )

    # ── Default authenticated checks ──
    if (
        vault_addr
        and token
        and not capability_audit
        and not kv_enum
        and not priv_esc_audit
        and not auth_config_audit
        and not ttl_audit
        and not active_auto
        and not requested_modules
    ):
        client = VaultClient(vault_addr, token)
        token_data = check_token(client)
        if token_data:
            analyze_token(token_data)
            test_secret_read(client, secret_path)
            if policy:
                policy_text = read_policy(client, policy)
                if policy_text:
                    analyze_policy(policy, policy_text)

    # ── AI-powered analysis ──────────────────────────────────────────
    if ai_provider:
        _run_ai_analysis(
            vault_addr=vault_addr,
            ai_provider=ai_provider,
            ai_model=ai_model,
        )

    # ── Reports ──
    print_report()
    report_target = hijack_path or vault_addr
    _export_reports(json_report, markdown_report, report_target)

    if pdf_report:
        from core.report import export_pdf_report
        export_pdf_report(pdf_report, target=report_target)


@app.command()
def hijack(
    path: str = typer.Argument(..., help="Path to scan for Vault credentials"),
    vault_addr: Optional[str] = typer.Option(None, "--target", help="Vault address for validation"),
    addr: Optional[str] = typer.Option(None, "--addr", help="Vault address (legacy)"),
    token: Optional[str] = typer.Option(None, "--token", help="Vault token for validation"),
    validate_token: bool = typer.Option(False, "--validate-token", help="Validate discovered tokens"),
    validate_approle: bool = typer.Option(False, "--validate-approle", help="Validate discovered AppRole pairs"),
    validate_db: bool = typer.Option(False, "--validate-db", help="Validate DB secrets engine metadata"),
    role_id: Optional[str] = typer.Option(None, "--role-id", help="Role ID for AppRole validation"),
    secret_id: Optional[str] = typer.Option(None, "--secret-id", help="Secret ID for AppRole validation"),
    approle_mount: str = typer.Option("approle", "--approle-mount", help="AppRole auth mount path"),
    capability_path: Optional[list[str]] = typer.Option(None, "--capability-path", help="Paths for capability audit (repeatable)"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Vault namespace"),
    no_git_history: bool = typer.Option(False, "--no-git-history", help="Skip git history scanning"),
    exclude_dir: Optional[list[str]] = typer.Option(None, "--exclude-dir", help="Exclude directory (repeatable)"),
    max_file_size_mb: int = typer.Option(5, "--max-file-size-mb", help="Maximum file size to scan (MB)"),
    workers: int = typer.Option(0, "--workers", help="Parallel scanner workers (0=auto)"),
    skip_recon: bool = typer.Option(False, "--skip-recon", help="Skip unauthenticated recon"),
    min_severity: Optional[str] = typer.Option(None, "--min-severity", help="Minimum severity to show/export"),
    json_report: Optional[str] = typer.Option(None, "--json", help="Export findings to JSON"),
    markdown_report: Optional[str] = typer.Option(None, "--markdown", help="Export findings to Markdown"),
) -> None:
    """Scan files and git history for leaked Vault credentials."""
    clear_findings()
    set_report_min_severity(min_severity)
    target = vault_addr or addr

    # Register user token in global session
    if token:
        global_store.add_user_token(token)

    if target and not skip_recon:
        _run_unauthenticated_recon(target)

    run_hijack_scan(
        path,
        vault_addr=target,
        token=token,
        validate_token=validate_token,
        validate_approle=validate_approle,
        validate_db=validate_db,
        include_git_history=not no_git_history,
        max_file_size_bytes=max_file_size_mb * 1024 * 1024,
        excluded_dirs=exclude_dir,
        max_workers=workers if workers > 0 else None,
    )

    if target and validate_approle and role_id and secret_id:
        validate_approle_credentials(
            role_id, secret_id, target,
            mount_point=approle_mount,
            capability_paths=capability_path,
            namespace=namespace,
        )

    print_report()
    _export_reports(json_report, markdown_report, path)


@app.command()
def chat(
    target: Optional[str] = typer.Option(None, "--target", help="Vault address"),
    token: Optional[str] = typer.Option(None, "--token", help="Vault token"),
    addr: Optional[str] = typer.Option(None, "--addr", help="Vault address (legacy)"),
    provider: Optional[str] = typer.Option(
        None, "--provider",
        help="LLM provider. If not set, you will be asked interactively. (ollama, openai, anthropic, deepseek)",
    ),
    model: Optional[str] = typer.Option(
        None, "--model",
        help="LLM model name. If not set, you will be asked interactively.",
    ),
    skip_tls_verify: bool = typer.Option(False, "--skip-tls-verify", help="Disable TLS certificate verification"),
    disable_web: bool = typer.Option(False, "--disable-web", help="Disable automatic web search (privacy/offline)"),
    auto_pilot: bool = typer.Option(False, "--auto-pilot", help="Auto-execute high-confidence PoCs from web search results"),
    stealth: bool = typer.Option(False, "--stealth", help="Enable stealth HTTP (balanced profile: light jitter, 5 concurrency, 429 backoff)"),
    profile: str = typer.Option("balanced", "--profile", help="Evasion profile: turbo|aggressive|balanced|stealth|paranoid|low_and_slow"),
    waf_evasion: str = typer.Option("none", "--waf-evasion", help="WAF evasion profile: none|light|moderate|aggressive"),
    auto_cleanup: bool = typer.Option(False, "--auto-cleanup", help="Automatically rollback all state changes when the session ends"),
    # ── Auto mode ──
    auto: bool = typer.Option(
        False, "--auto",
        help="Run fully autonomous pentest — no interactive prompts. Exits when complete.",
    ),
    pdf_report: Optional[str] = typer.Option(
        None, "--pdf-report",
        help="PDF report output path (default: reports/pentest_report_<timestamp>.pdf)",
    ),
    hijack_path: Optional[str] = typer.Option(
        None, "--hijack-path",
        help="Scan a local path for leaked credentials during auto mode",
    ),
    auto_max_risk: str = typer.Option(
        "read_only", "--auto-max-risk",
        help="Maximum risk level for auto mode (read_only, state_changing, destructive)",
    ),
    auto_max_turns: int = typer.Option(
        30, "--auto-max-turns",
        help="Maximum LLM turns during auto mode",
    ),
    # ── Continuous / cron mode ──
    interval: Optional[int] = typer.Option(
        None, "--interval",
        help="Run auto mode repeatedly every N seconds (cron-like continuous mode). Requires --auto.",
    ),
    # ── UI mode ──
    ui: str = typer.Option(
        "terminal", "--ui",
        help="UI mode: 'terminal' (TUI) or 'desktop' (CustomTkinter app)",
    ),
) -> None:
    """Start AI-powered pentest chat agent."""
    resolved_target = target or addr

    # Auto mode requires a target
    if auto and not resolved_target:
        print("❌ --auto mode requires --target <url>. Nothing to do.")
        raise typer.Exit(code=1)

    # --interval requires --auto
    if interval and not auto:
        print("❌ --interval requires --auto. Add --auto to enable autonomous mode.")
        raise typer.Exit(code=1)

    if interval and interval < 10:
        print("❌ --interval must be >= 10 seconds.")
        raise typer.Exit(code=1)

    if stealth or profile != "balanced":
        from reconnaissance.stealth_http import (
            set_evasion_profile, EvasionProfile, enable_stealth,
            _PROFILE_CONFIG,
        )
        profile_map = {
            "turbo": EvasionProfile.TURBO,
            "aggressive": EvasionProfile.AGGRESSIVE,
            "balanced": EvasionProfile.BALANCED,
            "stealth": EvasionProfile.STEALTH,
            "paranoid": EvasionProfile.PARANOID,
            "low_and_slow": EvasionProfile.LOW_AND_SLOW,
        }
        selected = profile_map.get(profile, EvasionProfile.BALANCED)
        enable_stealth()
        set_evasion_profile(selected)
        cfg = _PROFILE_CONFIG.get(selected, {})
        print(f"[*] Evasion profile: {selected.value} (jitter {cfg.get('jitter_min',0)}-{cfg.get('jitter_max',0)}s, concurrency {cfg.get('max_concurrency','?')})")

    if waf_evasion != "none":
        from active_execution.waf_evasion import (
            enable_waf_evasion, set_waf_evasion_profile, WAFEvasionProfile,
        )
        waf_profile_map = {
            "light": WAFEvasionProfile.LIGHT,
            "moderate": WAFEvasionProfile.MODERATE,
            "aggressive": WAFEvasionProfile.AGGRESSIVE,
        }
        selected_waf = waf_profile_map.get(waf_evasion)
        if selected_waf:
            enable_waf_evasion()
            set_waf_evasion_profile(selected_waf)
            print(f"[*] WAF evasion: {selected_waf.value} (body obfuscation + header diversity)")

    if skip_tls_verify:
        from core.tls_config import set_insecure_mode
        set_insecure_mode()
        print("[*] TLS certificate verification disabled")
    elif resolved_target and resolved_target.startswith("https://"):
        from core.tls_config import set_insecure_mode
        set_insecure_mode()

    if ui == "desktop":
        from ai_core.gui_app import start_gui
        start_gui(
            vault_addr=resolved_target,
            token=token,
            provider=provider,
            model=model,
            disable_web=disable_web,
            auto_pilot=auto_pilot,
            skip_tls_verify=skip_tls_verify,
        )
    else:
        start_chat_session(
            vault_addr=resolved_target,
            token=token,
            provider=provider,
            model=model,
            auto=auto,
            pdf_report=pdf_report,
            hijack_path=hijack_path,
            auto_max_risk=auto_max_risk,
            auto_max_turns=auto_max_turns,
            disable_web=disable_web,
            auto_pilot=auto_pilot,
            interval=interval,
        )


@app.command()
def cleanup(
    target: str = typer.Option(..., "--target", help="Vault address (https://vault.example.com:8200)"),
    token: str = typer.Option(..., "--token", help="Vault token with sufficient privileges for cleanup"),
    dry_run: bool = typer.Option(False, "--dry-run", help="List what would be cleaned without executing"),
    skip_tls_verify: bool = typer.Option(False, "--skip-tls-verify", help="Disable TLS certificate verification"),
) -> None:
    """Execute rollback of all recorded state changes from a session."""
    from active_execution.cleanup_engine import CleanupEngine

    if skip_tls_verify:
        from core.tls_config import set_insecure_mode
        set_insecure_mode()
        print("[*] TLS certificate verification disabled")

    engine = CleanupEngine.get()

    if dry_run:
        for line in engine.dry_run():
            print(line)
        return

    print(f"[*] Executing rollback against {target}...")
    result = engine.execute_rollback(
        vault_addr=target,
        token=token,
        verify_tls=not skip_tls_verify,
    )
    print(f"[*] Rollback complete: {result['succeeded']}/{result['total']} succeeded"
          + (f", {result['failed']} failed" if result['failed'] else ""))

    if result["failed"]:
        raise typer.Exit(code=1)


@app.command()
def mcp(
    skip_tls_verify: bool = typer.Option(False, "--skip-tls-verify", help="Disable TLS certificate verification"),
) -> None:
    """Start MCP server on 127.0.0.1:8000."""
    if skip_tls_verify:
        from core.tls_config import set_insecure_mode
        set_insecure_mode()
        print("[*] TLS certificate verification disabled")
    from ai_core.mcp_server import start_mcp_service
    start_mcp_service()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
