import argparse

from core.client import VaultClient
from core.report import (
    export_json_report,
    export_markdown_report,
    print_report,
    set_report_min_severity,
)
from credential_hijacking.hijack_analyzer import run_hijack_scan

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
        help="Validate discovered AppRole pairs against --target without reading secrets"
    )

    parser.add_argument(
        "--validate-db",
        action="store_true",
        help="Validate Vault database secrets engine metadata with --target and --token without generating credentials"
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

    if args.target and not hijack_path:
        run_unauthenticated_recon(args.target)

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

    if vault_addr and args.token:
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
