import argparse

from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.registry import (
    RiskLevel,
    risk_level_allowed,
)
from ai_core.chat_ui import start_chat_session
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

from scanners.capability_scanner import audit_token_capabilities
from scanners.auth_config_scanner import scan_auth_config_security
from scanners.kv_enumerator import scan_kv_tree
from scanners.privilege_escalation_scanner import scan_privilege_escalation
from scanners.ttl_scanner import (
    DEFAULT_MAX_MOUNT_TTL_SECONDS,
    DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
    scan_ttl_governance,
)
from scanners.token_scanner import check_token, analyze_token
from scanners.secret_scanner import test_secret_read
from scanners.policy_scanner import read_policy, analyze_policy
from scanners.env_scanner import scan_environment, scan_vault_token_file
from reconnaissance.auth_surface_scanner import scan_auth_surface
from reconnaissance.cors_scanner import scan_cors
from reconnaissance.deployment_scanner import scan_deployment
from reconnaissance.endpoint_scanner import scan_endpoints
from reconnaissance.fingerprint_scanner import scan_fingerprint
from reconnaissance.header_scanner import scan_headers
from reconnaissance.health_scanner import scan_health
from reconnaissance.recon_context import ReconContext
from reconnaissance.tls_scanner import scan_tls
from reconnaissance.ui_scanner import scan_ui
from reconnaissance.version_risk_scanner import scan_version_risk
from reconnaissance.vault_recon import scan_vault_recon


def build_active_execution_registry():
    from active_execution.modules import get_default_registry
    return get_default_registry()


def run_unauthenticated_recon(target):
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


def main():
    parser = argparse.ArgumentParser(
        description="Vault Pentest Tool"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=["hijack", "recon", "chat", "mcp"],
        help="Optional command: hijack, recon, chat, or mcp"
    )

    parser.add_argument(
        "--addr",
        help="Vault address for authenticated checks, example: http://localhost:8200"
    )

    parser.add_argument(
        "--token",
        help="Vault token"
    )

    parser.add_argument(
        "--secret-path",
        default="secret/data/myapp",
        help="Secret path to test"
    )

    parser.add_argument(
        "--policy",
        help="Policy name to analyze"
    )

    parser.add_argument(
        "--target",
        help="Target Vault URL, example: http://localhost:8200"
    )

    parser.add_argument(
        "--vault-recon",
        action="store_true",
        help="Run async unauthenticated Vault health/seal/leader recon only"
    )

    parser.add_argument(
        "--skip-recon",
        action="store_true",
        help="Skip the default unauthenticated recon when running targeted validation or authenticated audits"
    )

    parser.add_argument(
        "--skip-tls-verify",
        action="store_true",
        help="Disable TLS certificate verification (for self-signed lab certs)"
    )

    parser.add_argument(
        "--env-scan",
        action="store_true",
        help="Scan local environment for Vault-related variables"
    )

    parser.add_argument(
        "--json",
        help="Write findings to a JSON report file"
    )

    parser.add_argument(
        "--markdown",
        help="Write findings to a Markdown report file"
    )

    parser.add_argument(
        "--hijack-path",
        help="Recursively scan a local path for Vault credential material"
    )

    parser.add_argument(
        "--path",
        help="Path alias for the hijack command"
    )

    parser.add_argument(
        "--validate-token",
        action="store_true",
        help="Validate discovered Vault tokens against --target without reading secrets"
    )

    parser.add_argument(
        "--validate-approle",
        action="store_true",
        help="Validate discovered or supplied AppRole pairs against --target without reading secrets"
    )

    parser.add_argument(
        "--role-id",
        help="Role ID for direct authorized AppRole validation"
    )

    parser.add_argument(
        "--secret-id",
        help="Secret ID for direct authorized AppRole validation"
    )

    parser.add_argument(
        "--approle-mount",
        default="approle",
        help="AppRole auth mount path for direct validation"
    )

    parser.add_argument(
        "--validate-db",
        action="store_true",
        help="Validate Vault database secrets engine metadata with --target and --token without generating credentials"
    )

    parser.add_argument(
        "--capability-audit",
        action="store_true",
        help="Audit the supplied token with sys/capabilities-self without reading or modifying secrets"
    )

    parser.add_argument(
        "--capability-path",
        action="append",
        default=None,
        help="Vault path to check with --capability-audit; can be used multiple times"
    )

    parser.add_argument(
        "--priv-esc-audit",
        action="store_true",
        help="Safely simulate token privilege escalation risk with sys/capabilities-self"
    )

    parser.add_argument(
        "--auth-config-audit",
        action="store_true",
        help="Audit Kubernetes, AWS, and LDAP auth method configuration safety"
    )

    parser.add_argument(
        "--ttl-audit",
        action="store_true",
        help="Audit secrets engine mount TTL and PKI certificate role TTL governance"
    )

    parser.add_argument(
        "--active-auto",
        action="store_true",
        help="Run default-enabled active execution modules within --active-max-risk"
    )

    parser.add_argument(
        "--active-max-risk",
        choices=[level.value for level in RiskLevel],
        default=RiskLevel.READ_ONLY.value,
        help="Maximum active execution risk level allowed by --active-auto"
    )

    parser.add_argument(
        "--confirm-active",
        action="store_true",
        help="Explicitly confirm state-changing active execution modules"
    )

    parser.add_argument(
        "--active-policy",
        action="append",
        default=None,
        help="Policy to request during --active-auto token creation; can be used multiple times"
    )

    parser.add_argument(
        "--active-ttl",
        default="30m",
        help="TTL to request during --active-auto token creation"
    )

    parser.add_argument(
        "--active-exfil-max-depth",
        type=int,
        default=5,
        help="Maximum KV recursion depth for active secret exfiltration"
    )

    parser.add_argument(
        "--max-mount-ttl-seconds",
        type=int,
        default=DEFAULT_MAX_MOUNT_TTL_SECONDS,
        help="Maximum allowed secrets engine max_lease_ttl in seconds for --ttl-audit"
    )

    parser.add_argument(
        "--max-pki-cert-ttl-seconds",
        type=int,
        default=DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
        help="Maximum allowed PKI certificate role ttl/max_ttl in seconds for --ttl-audit"
    )

    parser.add_argument(
        "--token-policy",
        action="append",
        default=None,
        help="Policy name to include in --priv-esc-audit; can be used multiple times"
    )

    parser.add_argument(
        "--nvd-refresh",
        action="store_true",
        help="Force refresh of NVD CVE cache (fetches latest HashiCorp Vault CVEs from NVD API)"
    )

    parser.add_argument(
        "--kv-enum",
        action="store_true",
        help="Enumerate accessible KV secret paths with list/read metadata operations"
    )

    parser.add_argument(
        "--kv-path",
        help="KV start path for --kv-enum, example: secret/ or kv/app"
    )

    parser.add_argument(
        "--kv-version",
        type=int,
        choices=[1, 2],
        help="KV engine version for --kv-enum; defaults to autodetect then KV v2"
    )

    parser.add_argument(
        "--kv-max-depth",
        type=int,
        default=10,
        help="Maximum recursive depth for --kv-enum"
    )

    parser.add_argument(
        "--kv-concurrency",
        type=int,
        default=5,
        help="Maximum concurrent KV list/read metadata operations"
    )

    parser.add_argument(
        "--kv-no-read",
        action="store_true",
        help="Only list KV paths during --kv-enum; do not read leaf metadata or key names"
    )

    parser.add_argument(
        "--kv-blind",
        action="store_true",
        help="When LIST fails (403), brute-force common secret names via direct GET (blind enumeration)"
    )

    parser.add_argument(
        "--namespace",
        help="Vault namespace to use for authenticated validation, capability audit, and KV enumeration"
    )

    parser.add_argument(
        "--no-git-history",
        action="store_true",
        help="Do not scan git history during hijack scans"
    )

    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=None,
        help="Directory name to exclude during hijack scans; can be used multiple times"
    )

    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        default=5,
        help="Maximum file size to scan during hijack scans"
    )

    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"],
        help="Only show/export findings at or above this severity"
    )

    # Yeni argümanlar
    parser.add_argument(
        "--db-pivot",
        action="store_true",
        help="Enable database pivot module"
    )

    parser.add_argument(
        "--cloud-pivot",
        action="store_true",
        help="Enable cloud pivot module"
    )

    parser.add_argument(
        "--persistence",
        action="store_true",
        help="Enable persistence module"
    )

    parser.add_argument(
        "--module",
        choices=[
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
            "unauthenticated.attack"
        ],
        help="Run a single specific module"
    )

    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp", "ollama", "openai", "anthropic", "deepseek"],
        help="Cloud provider for cloud_pivot, or LLM provider for chat"
    )

    parser.add_argument(
        "--model",
        help="LLM model for chat (e.g. llama3.1:8b, gpt-4o-mini, claude-sonnet-4-20250514)"
    )

    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for cloud_pivot"
    )

    parser.add_argument(
        "--subscription-id",
        help="Azure subscription ID for cloud_pivot"
    )

    parser.add_argument(
        "--db-type",
        choices=["postgres", "mysql", "mssql"],
        default="postgres",
        help="Database type for database_pivot module"
    )

    parser.add_argument(
        "--db-host",
        help="Database host for database_pivot module"
    )

    parser.add_argument(
        "--db-port",
        type=int,
        help="Database port for database_pivot module"
    )

    parser.add_argument(
        "--db-name",
        default="postgres",
        help="Database name for database_pivot module"
    )

    parser.add_argument(
        "--auth-path",
        default="approle-backdoor",
        help="Auth path for persistence module"
    )

    parser.add_argument(
        "--role-name",
        default="backdoor-role",
        help="Role name for persistence module"
    )

    parser.add_argument(
        "--token-ttl",
        default="0",
        help="Token TTL for persistence module (0 = infinite)"
    )

    args = parser.parse_args()

    # Her CLI çalıştırmasında temiz bir rapor durumu
    clear_findings()

    # TLS doğrulama kontrolü
    if args.skip_tls_verify:
        from core.tls_config import set_insecure_mode
        set_insecure_mode()
        print("[*] TLS certificate verification disabled")

    if args.command == "chat":
        llm_provider = args.provider if args.provider in ("ollama", "openai", "anthropic", "deepseek") else None
        start_chat_session(
            vault_addr=args.target or args.addr,
            token=args.token,
            provider=llm_provider,
            model=args.model,
        )
        return

    if args.command == "mcp":
        from ai_core.mcp_server import start_mcp_service
        start_mcp_service()
        return

    set_report_min_severity(args.min_severity)
    vault_addr = args.target or args.addr
    hijack_path = args.hijack_path or (args.path if args.command == "hijack" else None)

    if args.target and not hijack_path and not args.vault_recon and not args.skip_recon:
        run_unauthenticated_recon(args.target)

    if args.target and args.vault_recon:
        scan_vault_recon(args.target)

    if args.nvd_refresh:
        print("\n[+] Refreshing NVD CVE cache...")
        try:
            from reconnaissance.nvd_client import fetch_vault_cves_from_nvd

            cves = fetch_vault_cves_from_nvd(force_refresh=True)
            print(f"[+] Cached {len(cves)} Vault-related CVEs from NVD.")
            if cves:
                for cve in cves[:10]:
                    print(f"    - {cve['cve_id']} [{cve['severity']}] {cve['summary'][:80]}...")
                if len(cves) > 10:
                    print(f"    ... and {len(cves) - 10} more")
        except ImportError:
            print("[-] NVD client unavailable — install project dependencies.")
        except Exception as error:
            print(f"[-] NVD refresh failed: {error}")

    if hijack_path:
        run_hijack_scan(
            hijack_path,
            vault_addr=vault_addr,
            token=args.token,
            validate_token=args.validate_token,
            validate_approle=args.validate_approle,
            validate_db=args.validate_db,
            include_git_history=not args.no_git_history,
            max_file_size_bytes=args.max_file_size_mb * 1024 * 1024,
            excluded_dirs=args.exclude_dir,
        )

    if args.env_scan:
        scan_environment()
        scan_vault_token_file()

    if vault_addr and args.token and args.capability_audit:
        audit_token_capabilities(
            vault_addr,
            args.token,
            paths=args.capability_path,
            namespace=args.namespace,
        )

    if vault_addr and args.token and args.priv_esc_audit:
        scan_privilege_escalation(
            vault_addr,
            args.token,
            policy_names=args.token_policy,
            namespace=args.namespace,
        )

    if vault_addr and args.token and args.auth_config_audit:
        scan_auth_config_security(
            vault_addr,
            args.token,
            namespace=args.namespace,
        )

    if vault_addr and args.token and args.ttl_audit:
        scan_ttl_governance(
            vault_addr,
            args.token,
            namespace=args.namespace,
            max_mount_ttl_seconds=args.max_mount_ttl_seconds,
            max_pki_cert_ttl_seconds=args.max_pki_cert_ttl_seconds,
        )

    if vault_addr and args.token and args.kv_enum:
        scan_kv_tree(
            vault_addr,
            args.token,
            args.kv_path,
            kv_version=args.kv_version,
            namespace=args.namespace,
            max_depth=args.kv_max_depth,
            concurrency=args.kv_concurrency,
            read_leaves=not args.kv_no_read,
            blind_brute=args.kv_blind,
        )

    # Tekil modül çalıştırma
    requested_modules = []
    if args.module:
        requested_modules.append(args.module)
    if args.db_pivot:
        requested_modules.append("database_pivot.exploit")
    if args.cloud_pivot:
        requested_modules.append("cloud_pivot.exploit")
    if args.persistence:
        requested_modules.append("persistence.backdoor")
    requested_modules = list(dict.fromkeys(requested_modules))

    if requested_modules:
        registry = build_active_execution_registry()
        engine = ActiveExecutionEngine(registry)
        context = ExecutionContext(
            vault_addr=vault_addr,
            token=args.token,
            namespace=args.namespace,
        )

        for module_id in requested_modules:
            module = registry.get(module_id)
            if not module:
                print(f"[-] Module not found: {module_id}")
                continue

            max_risk = RiskLevel(args.active_max_risk)
            if not risk_level_allowed(module.risk_level, max_risk):
                print(f"[-] Module risk '{module.risk_level.value}' exceeds max_risk '{max_risk.value}'")
                continue
            elif module.risk_level != RiskLevel.READ_ONLY and not args.confirm_active:
                print(f"[-] Module requires --confirm-active for risk level: {module.risk_level.value}")
                continue
            else:
                params = {
                    "ttl": args.active_ttl,
                    "namespace": args.namespace,
                    "max_depth": args.active_exfil_max_depth,
                    "search_path": hijack_path or ".",
                    "provider": args.provider,
                    "region": args.region,
                    "subscription_id": args.subscription_id,
                    "db_type": args.db_type,
                    "db_host": args.db_host,
                    "db_port": args.db_port,
                    "db_name": args.db_name,
                    "auth_path": args.auth_path,
                    "role_name": args.role_name,
                    "token_ttl": args.token_ttl,
                }
                if args.active_policy:
                    params["policies"] = args.active_policy

                engine.execute_plan(
                    [{"module_id": module_id, "params": params}],
                    context,
                    max_risk=max_risk,
                    confirm_state_changing=args.confirm_active,
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

    # Active auto - tüm default_enabled modülleri çalıştır
    if args.active_auto:
        registry = build_active_execution_registry()
        engine = ActiveExecutionEngine(registry)
        context = ExecutionContext(
            vault_addr=vault_addr,
            token=args.token,
            namespace=args.namespace,
        )
        max_risk = RiskLevel(args.active_max_risk)
        auto_steps = []

        for module_instance in registry.list_modules():
            if (
                getattr(module_instance, "default_enabled", False)
                and risk_level_allowed(module_instance.risk_level, max_risk)
            ):
                params = {
                    "ttl": args.active_ttl,
                    "namespace": args.namespace,
                    "max_depth": args.active_exfil_max_depth,
                }
                if args.active_policy:
                    params["policies"] = args.active_policy

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
                confirm_state_changing=args.confirm_active,
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

    if vault_addr and args.validate_approle and args.role_id and args.secret_id:
        validate_approle_credentials(
            args.role_id,
            args.secret_id,
            vault_addr,
            mount_point=args.approle_mount,
            capability_paths=args.capability_path,
            namespace=args.namespace,
        )

    if (
        vault_addr
        and args.token
        and not args.capability_audit
        and not args.kv_enum
        and not args.priv_esc_audit
        and not args.auth_config_audit
        and not args.ttl_audit
        and not args.active_auto
        and not requested_modules
    ):
        client = VaultClient(vault_addr, args.token)

        token_data = check_token(client)

        if token_data:
            analyze_token(token_data)
            test_secret_read(client, args.secret_path)

            if args.policy:
                policy_text = read_policy(client, args.policy)

                if policy_text:
                    analyze_policy(args.policy, policy_text)

    print_report()

    if args.json:
        report_target = hijack_path or vault_addr
        export_json_report(args.json, target=report_target)

    if args.markdown:
        report_target = hijack_path or vault_addr
        export_markdown_report(args.markdown, target=report_target)


if __name__ == "__main__":
    main()
