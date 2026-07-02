import re

from core.report import add_finding


MODULE_NAME = "version_cve_matcher"
VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")

KNOWN_VAULT_CVES = [
    {
        "cve_id": "CVE-2024-2048",
        "severity": "CRITICAL",
        "summary": (
            "Vault cert auth method did not correctly validate non-CA certificates, "
            "which may allow authentication bypass in affected configurations."
        ),
        "fixed_versions": "1.15.5 and 1.14.10",
        "references": [
            "https://discuss.hashicorp.com/t/hcsec-2024-05-vault-cert-auth-method-did-not-correctly-validate-non-ca-certificates/63382",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2048",
        ],
        "affected_ranges": [
            {"introduced": None, "fixed": "1.14.10"},
            {"introduced": "1.15.0", "fixed": "1.15.5"},
        ],
    },
    {
        "cve_id": "CVE-2023-6337",
        "severity": "HIGH",
        "summary": (
            "Vault may experience denial of service through memory exhaustion when "
            "handling large HTTP requests."
        ),
        "fixed_versions": "1.15.4, 1.14.8, and 1.13.12",
        "references": [
            "https://discuss.hashicorp.com/t/hcsec-2023-34-vault-vulnerable-to-denial-of-service-through-memory-exhaustion-when-handling-large-http-requests/60741",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-6337",
        ],
        "affected_ranges": [
            {"introduced": "1.12.0", "fixed": "1.13.12"},
            {"introduced": "1.14.0", "fixed": "1.14.8"},
            {"introduced": "1.15.0", "fixed": "1.15.4"},
        ],
    },
]


def match_vault_version_cves(version, target=None, add_findings=True):
    parsed_version = parse_vault_version(version)
    if parsed_version is None:
        if add_findings and version:
            add_finding(
                "LOW",
                "Vault version could not be matched against CVE rules",
                "The detected Vault version could not be parsed for local CVE range matching.",
                recommendation="Validate the Vault version string and compare it manually against vendor advisories.",
                evidence=f"version: {version}",
                module=MODULE_NAME,
                target=target,
            )
        return []

    matches = []
    for advisory in KNOWN_VAULT_CVES:
        if _version_in_any_range(parsed_version, advisory["affected_ranges"]):
            matches.append(advisory)
            if add_findings:
                _add_cve_finding(version, parsed_version, advisory, target)

    return matches


def parse_vault_version(version):
    if not isinstance(version, str):
        return None
    match = VERSION_PATTERN.match(version.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _version_in_any_range(version_tuple, affected_ranges):
    return any(
        _version_in_range(version_tuple, item.get("introduced"), item.get("fixed"))
        for item in affected_ranges
    )


def _version_in_range(version_tuple, introduced, fixed):
    introduced_tuple = parse_vault_version(introduced) if introduced else None
    fixed_tuple = parse_vault_version(fixed) if fixed else None

    if introduced_tuple and version_tuple < introduced_tuple:
        return False
    if fixed_tuple and version_tuple >= fixed_tuple:
        return False
    return True


def _add_cve_finding(raw_version, parsed_version, advisory, target):
    add_finding(
        advisory["severity"],
        f"Vault version matches known advisory: {advisory['cve_id']}",
        advisory["summary"],
        recommendation=(
            f"Review {advisory['cve_id']} and upgrade to a fixed Vault version "
            f"or newer. Fixed versions: {advisory['fixed_versions']}."
        ),
        evidence=(
            f"version: {raw_version}, parsed_version: {'.'.join(map(str, parsed_version))}, "
            f"cve: {advisory['cve_id']}, references: {', '.join(advisory['references'])}"
        ),
        module=MODULE_NAME,
        target=target,
    )
