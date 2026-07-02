import argparse

from core.client import VaultClient
from core.report import (
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
from reconnaissance.tls_scanner import scan_tls
from reconnaissance.ui_scanner import scan_ui
from reconnaissance.version_risk_scanner import scan_version_risk
from reconnaissance.vault_recon import scan_vault_recon


def run_unauthenticated_recon(target):
    print("\n======================================")
    print("Unauthenticated Vault Reconnaissance")
    print("======================================")

    scan_tls(target)
    scan_health(target)
    scan_version_risk(target)
    scan_fingerprint(target)
    scan_ui(target)
    scan_auth_surface(target)
    scan_deployment(target)
    scan_cors(target)
    scan_headers(target)
    scan_endpoints(target)


def main():
    parser = argparse.ArgumentParser(
        description="Vault Pentest Tool"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=["hijack", "recon"],
        help="Optional command: hijack or recon"
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

    args = parser.parse_args()
    set_report_min_severity(args.min_severity)
    vault_addr = args.target or args.addr
    hijack_path = args.hijack_path or (args.path if args.command == "hijack" else None)

    if args.target and not hijack_path and not args.vault_recon:
        run_unauthenticated_recon(args.target)

    if args.target and args.vault_recon:
        scan_vault_recon(args.target)

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
        )

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
