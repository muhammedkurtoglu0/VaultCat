"""NVD API v2.0 client for live Vault CVE lookups with local cache.

Rate limiting
    Without API key: 5 requests / 30 s rolling window.
    With API key:    50 requests / 30 s rolling window.
    (per https://nvd.nist.gov/developers)

Cache
    A JSON file (``reports/nvd_vault_cve_cache.json``) stores previously
    fetched CVE records.  Entries older than CACHE_TTL_SECONDS are
    considered stale and trigger a fresh API call.

Offline fallback
    When the NVD API is unreachable *and* the local cache is empty,
    consumers should fall back to the hardcoded ``KNOWN_VAULT_CVES`` list
    in ``version_cve_matcher``.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"

CACHE_DIR = Path("reports")
CACHE_FILE = CACHE_DIR / "nvd_vault_cve_cache.json"
CACHE_TTL_SECONDS = 86_400  # 24 hours

# ---------- public helpers ----------------------------------------------------

def _nvd_api_key() -> Optional[str]:
    return os.getenv(NVD_API_KEY_ENV) or None


def nvd_rate_limit_delay() -> float:
    """Return the minimum delay (seconds) between API requests."""
    return 0.6 if _nvd_api_key() else 6.0


# ---------- cache -------------------------------------------------------------

def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {"cves": [], "last_fetched": None}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"cves": [], "last_fetched": None}
    if not isinstance(data, dict):
        return {"cves": [], "last_fetched": None}
    data.setdefault("cves", [])
    data.setdefault("last_fetched", None)
    return data


def _save_cache(cves: list[dict]):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = {
        "cves": cves,
        "last_fetched": datetime.now(timezone.utc).isoformat(),
    }
    CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")


def _cache_is_fresh() -> bool:
    cache = _load_cache()
    if not cache["cves"] or not cache["last_fetched"]:
        return False
    try:
        last = datetime.fromisoformat(cache["last_fetched"])
    except (ValueError, TypeError):
        return False
    age = (datetime.now(timezone.utc) - last).total_seconds()
    return age < CACHE_TTL_SECONDS


# ---------- API client --------------------------------------------------------

def fetch_vault_cves_from_nvd(force_refresh: bool = False) -> list[dict]:
    """Query the NVD API for HashiCorp Vault CVEs.

    Returns a list of dicts matching the existing ``KNOWN_VAULT_CVES``
    schema::

        {
            "cve_id": str,
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "summary": str,
            "fixed_versions": str,
            "references": list[str],
            "affected_ranges": [{"introduced": str|None, "fixed": str|None}],
        }
    """
    if not force_refresh and _cache_is_fresh():
        return _load_cache()["cves"]

    params = _build_query_params()
    all_cves = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        raw = _nvd_request(params)
        if raw is None:
            # API failed — return cached data if available, else empty
            return _load_cache()["cves"]

        vulnerabilities = raw.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            parsed = _parse_nvd_vulnerability(vuln)
            if parsed:
                all_cves.append(parsed)

        total = raw.get("totalResults", 0)
        per_page = raw.get("resultsPerPage", 2000)
        start_index += per_page
        if start_index >= total:
            break

    if all_cves:
        _save_cache(all_cves)
    return all_cves


# ---------- internal ----------------------------------------------------------

def _build_query_params() -> dict:
    """Build the NVD API query parameters for Vault CVEs.

    Strategy: search by keyword for 'hashicorp vault'.  Severity is
    filtered CLIENT-side — the NVD API 2.0 rejects comma-separated
    ``cvssV3Severity`` values with a 404, which previously made every
    fetch return zero results.
    """
    params: dict = {
        "keywordSearch": "hashicorp vault",
        "noRejected": "",  # flag parameter, no value needed
    }
    api_key = _nvd_api_key()
    if api_key:
        params["apiKey"] = api_key
    return params


def _nvd_request(params: dict) -> Optional[dict]:
    """Perform a single NVD API request with rate limiting."""
    _rate_limit_wait()
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        return resp.json()
    except ValueError:
        return None


# Severities kept after the client-side filter (see _build_query_params).
_KEEP_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}

_last_request_time: float = 0.0


def _rate_limit_wait():
    global _last_request_time
    now = time.monotonic()
    since_last = now - _last_request_time
    min_delay = nvd_rate_limit_delay()
    if since_last < min_delay:
        time.sleep(min_delay - since_last)
    _last_request_time = time.monotonic()


def _parse_nvd_vulnerability(vuln: dict) -> Optional[dict]:
    """Convert one NVD vulnerability object into our internal schema.

    Returns ``None`` when the entry cannot be matched to version ranges.
    """
    cve = vuln.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    summary = _english_description(cve.get("descriptions", []))
    severity = _cvss_severity(cve.get("metrics", {}))
    if severity not in _KEEP_SEVERITIES:
        return None

    references = _reference_urls(cve.get("references", []))
    affected_ranges = _extract_version_ranges(cve.get("configurations", []))

    if not affected_ranges:
        return None

    fixed_versions = _format_fixed_versions(affected_ranges)

    return {
        "cve_id": cve_id,
        "severity": severity,
        "summary": summary,
        "fixed_versions": fixed_versions,
        "references": references,
        "affected_ranges": affected_ranges,
    }


def _english_description(descriptions: list[dict]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")[:500]
    # fallback to first description
    if descriptions:
        return descriptions[0].get("value", "")[:500]
    return ""


def _cvss_severity(metrics: dict) -> str:
    """Extract CVSS v3.1 severity (preferred) or v3.0."""
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        for entry in entries:
            cvss = entry.get("cvssData", {})
            sev = cvss.get("baseSeverity", "")
            if sev:
                return sev.upper()
    return "MEDIUM"


def _reference_urls(references: list[dict]) -> list[str]:
    urls = []
    for ref in references:
        url = ref.get("url", "")
        if url:
            urls.append(url)
    return urls[:5]


def _extract_version_ranges(configurations: list[dict]) -> list[dict]:
    """Walk NVD configurations → nodes → cpeMatch to find Vault version ranges.

    Each entry returned::

        {"introduced": str | None, "fixed": str | None}
    """
    ranges: list[dict] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if not cpe.get("vulnerable", True):
                    continue
                criteria = cpe.get("criteria", "")
                # Match the Vault *server* product exactly.  A substring
                # check on "hashicorp:vault" would also match vault-action,
                # vault-ssh-helper etc. (e.g. CVE-2021-32074 is about the
                # GitHub Action, not the server).
                parts = criteria.lower().split(":")
                if len(parts) < 5 or parts[3] != "hashicorp" or parts[4] != "vault":
                    continue

                introduced = cpe.get("versionStartIncluding") or cpe.get(
                    "versionStartExcluding"
                )
                fixed = (
                    cpe.get("versionEndExcluding")
                    or cpe.get("versionEndIncluding")
                )

                # also try lessThan / lessThanOrEqual
                if not introduced:
                    introduced = cpe.get("versionStartIncluding")
                if not fixed:
                    fixed = cpe.get("versionEndExcluding")
                if not fixed:
                    fixed = cpe.get("versionEndIncluding")

                if introduced or fixed:
                    ranges.append({
                        "introduced": introduced,
                        "fixed": fixed,
                    })

    return _dedupe_ranges(ranges)


def _dedupe_ranges(ranges: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for r in ranges:
        key = (r.get("introduced"), r.get("fixed"))
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


def _format_fixed_versions(affected_ranges: list[dict]) -> str:
    parts = []
    for r in affected_ranges:
        if r.get("fixed"):
            parts.append(r["fixed"])
    if not parts:
        return "see references"
    return " and ".join(sorted(set(parts)))
