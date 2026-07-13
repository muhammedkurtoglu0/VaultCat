import re

from core.report import add_finding


MODULE_NAME = "version_cve_matcher"
VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")

# Offline fallback — used when NVD API is unreachable and no cache exists.
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
    {
        "cve_id": "CVE-2023-37702",
        "severity": "HIGH",
        "summary": (
            "HashiCorp Vault and Vault Enterprise did not properly validate "
            "the JSON Web Token (JWT) role-bound audience claim when using "
            "the JWT/OIDC auth method."
        ),
        "fixed_versions": "1.14.0, 1.13.6, and 1.12.10",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-37702",
        ],
        "affected_ranges": [
            {"introduced": "1.12.0", "fixed": "1.12.10"},
            {"introduced": "1.13.0", "fixed": "1.13.6"},
        ],
    },
    {
        "cve_id": "CVE-2023-0665",
        "severity": "MEDIUM",
        "summary": (
            "HashiCorp Vault PKI mount not correctly validating requested "
            "certificate parameters."
        ),
        "fixed_versions": "1.13.1 and 1.12.5",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-0665",
        ],
        "affected_ranges": [
            {"introduced": "1.12.0", "fixed": "1.12.5"},
            {"introduced": "1.13.0", "fixed": "1.13.1"},
        ],
    },
    {
        "cve_id": "CVE-2024-8184",
        "severity": "HIGH",
        "summary": (
            "HashiCorp Vault and Vault Enterprise did not properly handle "
            "certain HTTP/2 frames, which could lead to denial of service."
        ),
        "fixed_versions": "1.18.1 and 1.17.9",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-8184",
        ],
        "affected_ranges": [
            {"introduced": None, "fixed": "1.17.9"},
            {"introduced": "1.18.0", "fixed": "1.18.1"},
        ],
    },
    {
        "cve_id": "CVE-2024-9180",
        "severity": "HIGH",
        "summary": (
            "HashiCorp Vault memory allocation issue when processing "
            "certain identity tokens."
        ),
        "fixed_versions": "1.18.2",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-9180",
        ],
        "affected_ranges": [
            {"introduced": "1.18.0", "fixed": "1.18.2"},
        ],
    },
    {
        "cve_id": "CVE-2025-2065",
        "severity": "CRITICAL",
        "summary": (
            "HashiCorp Vault vulnerable to authentication bypass via "
            "improperly configured trust bundles."
        ),
        "fixed_versions": "1.19.2 and 1.18.12",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-2065",
        ],
        "affected_ranges": [
            {"introduced": None, "fixed": "1.18.12"},
            {"introduced": "1.19.0", "fixed": "1.19.2"},
        ],
    },
    {
        "cve_id": "CVE-2024-10588",
        "severity": "MEDIUM",
        "summary": (
            "HashiCorp Vault improper validation of OCSP responses "
            "during certificate revocation checking."
        ),
        "fixed_versions": "1.18.5",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-10588",
        ],
        "affected_ranges": [
            {"introduced": "1.18.0", "fixed": "1.18.5"},
        ],
    },
]


def match_vault_version_cves(version, target=None, add_findings=True, use_nvd=True):
    """Compare a Vault version against known CVE ranges.

    When *use_nvd* is ``True`` (default), attempts to fetch live CVE data
    from the NVD API first, falling back to the bundled local list when
    the API is unreachable and no local cache exists.

    Returns a list of advisory dicts that matched.
    """
    parsed_version = parse_vault_version(version)
    if parsed_version is None:
        if add_findings and version:
            add_finding(
                "LOW",
                "Vault version could not be matched against CVE rules",
                "The detected Vault version could not be parsed for CVE range matching.",
                recommendation="Validate the Vault version string and compare it manually against vendor advisories.",
                evidence=f"version: {version}",
                module=MODULE_NAME,
                target=target,
            )
        return []

    # Build the advisory pool: NVD live data → local cache → static fallback
    advisory_pool = _resolve_advisory_pool(use_nvd=use_nvd)

    matches = []
    for advisory in advisory_pool:
        if _version_in_any_range(parsed_version, advisory.get("affected_ranges", [])):
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


# ---------- advisory pool resolution ------------------------------------------

def _resolve_advisory_pool(use_nvd: bool = True) -> list[dict]:
    """Return the best available CVE advisory pool.

    Precedence:
    1. Fresh NVD API fetch (when *use_nvd*)
    2. Stale-but-valid local NVD cache
    3. Static ``KNOWN_VAULT_CVES`` fallback
    """
    if not use_nvd:
        return list(KNOWN_VAULT_CVES)

    try:
        from reconnaissance.nvd_client import (
            _load_cache,
            fetch_vault_cves_from_nvd,
        )

        # Try live NVD first
        live_cves = fetch_vault_cves_from_nvd(force_refresh=True)
        if live_cves:
            return live_cves

        # API failed — use cache if available
        cached = _load_cache().get("cves", [])
        if cached:
            return cached

    except ImportError:
        pass
    except Exception:
        pass

    # Ultimate fallback
    return list(KNOWN_VAULT_CVES)


# ---------- version range matching --------------------------------------------

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


# ---------- finding emission --------------------------------------------------

def _add_cve_finding(raw_version, parsed_version, advisory, target):
    severity = advisory.get("severity", "MEDIUM").upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        severity = "MEDIUM"

    add_finding(
        severity,
        f"Vault version matches known advisory: {advisory['cve_id']}",
        advisory.get("summary", "No description available."),
        recommendation=(
            f"Review {advisory['cve_id']} and upgrade to a fixed Vault version "
            f"or newer. Fixed versions: {advisory.get('fixed_versions', 'see references')}."
        ),
        evidence=(
            f"version: {raw_version}, parsed_version: {'.'.join(map(str, parsed_version))}, "
            f"cve: {advisory['cve_id']}, "
            f"references: {', '.join(advisory.get('references', []))}"
        ),
        module=MODULE_NAME,
        target=target,
    )
