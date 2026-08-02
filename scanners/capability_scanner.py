"""Token capability audit via sys/capabilities-self.

Dynamically discovers secret engine mounts (unauthenticated via
``sys/internal/ui/mounts``) and includes them in the audit so that
environment-specific paths (e.g. ``secret-v2/data/admin/*``) are
not missed by a hardcoded path list.
"""

from __future__ import annotations

from core.report import add_finding
from core.tls_config import get_verify, vault_request
from core.logger import logger

MODULE = "capability_scanner"

# ── Wildcard deduplication ──────────────────────────────────────────────
# Paths that are covered by a wildcard parent should NOT generate
# separate findings — they inflate the report with duplicate spam.
_WILDCARD_PARENTS: list[tuple[str, list[str]]] = [
    # parent wildcard → children it covers (not worth separate findings)
    ("*", []),  # universal — everything else is a duplicate
    ("sys/*", ["sys/mounts", "sys/mounts/*", "sys/policies/*",
               "sys/policies/acl/*", "sys/auth/*", "sys/audit/*",
               "sys/seal", "sys/unseal", "sys/health"]),
    ("auth/*", ["auth/token/*", "auth/token/create", "auth/token/lookup",
                "auth/approle/*", "auth/userpass/*"]),
    ("database/*", ["database/config/*", "database/roles/*",
                    "database/creds/*", "database/static-roles/*"]),
    ("secret/*", ["secret/data/*", "secret/metadata/*",
                   "secret/data/admin/*", "secret/data/db/*",
                   "secret/data/production/*", "secret/data/staging/*"]),
    ("kv/*", ["kv/data/*", "kv/metadata/*"]),
]

# Per-mount wildcards: discovered dynamically for secret-X/*, secret-Y/* etc.
_wildcard_cache: dict[str, set[str]] = {}


def _is_covered_by_wildcard(path: str, wildcard_parents: list[str]) -> bool:
    """Return True if *path* is already covered by any wildcard parent.

    A path like ``secret/data/admin`` is covered by ``secret/*`` if the
    token already has a finding for the parent wildcard.
    """
    for parent in wildcard_parents:
        if parent.endswith("/*"):
            base = parent[:-2]  # e.g. "secret" from "secret/*"
            if path.startswith(base + "/") or path == base:
                return True
        elif parent == "*":
            return True  # root wildcard covers everything
    return False


def _findings_have_wildcard_parent(path: str, existing_findings_titles: list[str]) -> bool:
    """Check if existing findings already cover *path* via a wildcard.

    Specifically: if we already reported "sudo on secret/*", don't also
    report "sudo on secret/data/*" — it's the same finding.
    """
    for title in existing_findings_titles:
        # Extract the path from the finding title pattern
        # Titles look like: "Token has sudo capability on Vault path"
        if " on " not in title:
            continue
        reported_path = title.rsplit(" on ", 1)[-1].strip()
        if not reported_path:
            continue
        if reported_path.endswith("/*"):
            base = reported_path[:-2]
            if path.startswith(base + "/") or path == base:
                return True
        if reported_path == "*":
            return True
    return False

DANGEROUS_CAPABILITIES = {"sudo", "create", "update", "delete", "patch", "root"}
WRITE_CAPABILITIES = {"create", "update", "delete", "patch"}
CRITICAL_PATH_PREFIXES = (
    "sys/",
    "auth/",
    "identity/",
    "database/config/",
    "database/roles/",
    "database/static-roles/",
    "database/creds/",
)

# Static baseline — always checked
_BASELINE_PATHS = [
    "sys/*",
    "sys/mounts",
    "sys/mounts/*",
    "sys/policies/acl/*",
    "auth/*",
    "auth/token/*",
    "database/config/*",
    "database/roles/*",
    "database/static-roles/*",
    "database/creds/*",
    "secret/*",
    "secret/data/*",
    "secret/metadata/*",
    "kv/*",
    "kv/data/*",
    "kv/metadata/*",
    # Common alternative mount names (labs, demos, multi-engine setups)
    "secret-v1/*",
    "secret-v1/data/*",
    "secret-v1/metadata/*",
    "secret-v2/*",
    "secret-v2/data/*",
    "secret-v2/metadata/*",
    "secret-prod/*",
    "secret-prod/data/*",
    "secret-staging/*",
    "secret-staging/data/*",
]


def audit_token_capabilities(vault_addr, token, paths=None, namespace=None, timeout=5):
    """Audit a token's capabilities without reading or modifying secrets.

    Mount paths are discovered dynamically via ``sys/internal/ui/mounts``
    (unauthenticated) so that environment-specific KV engines are included.
    """
    logger.info("\n[+] Auditing token capabilities with sys/capabilities-self...")

    if not vault_addr or not token:
        logger.warning("[!] Capability audit requires both Vault address and token.")
        return []

    audit_paths = _normalize_paths(paths)
    if not audit_paths:
        audit_paths = list(_BASELINE_PATHS)
        # Dynamically discover mounts and add their paths
        dynamic = _discover_mount_paths(vault_addr, timeout)
        for p in dynamic:
            if p not in audit_paths:
                audit_paths.append(p)

    logger.info(f"[*] Auditing {len(audit_paths)} paths...")

    try:
        import hvac
    except ImportError:
        logger.warning("[!] Missing dependency: hvac. Install requirements before running capability audit.")
        add_finding(
            severity="LOW",
            title="Capability audit dependency missing",
            description="The hvac Python package is required to query sys/capabilities-self.",
            recommendation="Install project dependencies with pip install -r requirements.txt.",
            evidence="missing package: hvac",
            module=MODULE,
            target=vault_addr,
        )
        return []

    try:
        client = hvac.Client(
            url=vault_addr.rstrip("/"),
            token=token,
            namespace=namespace,
            timeout=timeout,
            verify=get_verify(),
        )
        response = _query_capabilities_self(client, audit_paths)
    except Exception as error:
        logger.warning(f"[!] Capability audit failed: {error}")
        add_finding(
            severity="LOW",
            title="Token capability audit failed",
            description="The tool could not query sys/capabilities-self for the supplied token.",
            recommendation="Confirm the Vault address, token validity, namespace, and network reachability.",
            evidence=f"error: {error}",
            module=MODULE,
            target=vault_addr,
        )
        return []

    results = _extract_capability_results(response, audit_paths)
    _report_capability_findings(results, vault_addr)

    if not _has_dangerous_capability(results):
        add_finding(
            severity="PASS",
            title="No dangerous token capabilities observed",
            description="The audited paths did not return sudo or write-like capabilities for the supplied token.",
            recommendation="Review the audited path list and add environment-specific paths for deeper coverage.",
            evidence=f"paths_checked: {len(audit_paths)}",
            module=MODULE,
            target=vault_addr,
        )

    # Auto-probe: try to read secrets from sudo+read paths
    _probe_sudo_secrets(vault_addr, token, results, namespace, timeout, get_verify())

    return results


# -----------------------------------------------------------------------
# Dynamic mount discovery
# -----------------------------------------------------------------------


def _discover_mount_paths(vault_addr: str, timeout: int = 5) -> list[str]:
    """Return capability-check paths for every discovered KV secrets engine."""
    paths: list[str] = []
    mounts = _fetch_mounts_unauthenticated(vault_addr, timeout)
    if not mounts:
        return paths

    for mount_path, mount_type in mounts.items():
        # Normalise: Vault returns "secret/" for mount paths
        mp = mount_path.rstrip("/") if mount_path.endswith("/") else mount_path
        if not mp:
            continue

        # KV mounts get full path coverage
        if mount_type in ("kv", "generic"):
            paths.append(f"{mp}/*")
            paths.append(f"{mp}/data/*")
            paths.append(f"{mp}/metadata/*")
        elif mount_type == "database":
            paths.append(f"{mp}/config/*")
            paths.append(f"{mp}/roles/*")
            paths.append(f"{mp}/creds/*")
        elif mount_type == "transit":
            paths.append(f"{mp}/*")
        elif mount_type in ("pki", "ssh"):
            paths.append(f"{mp}/*")

        # For any KV mount, also check common admin sub-paths
        if mount_type in ("kv", "generic"):
            for sub in ("admin", "production", "staging", "dev", "db", "app"):
                paths.append(f"{mp}/data/{sub}/*")
                paths.append(f"{mp}/data/{sub}")

    return paths


def _fetch_mounts_unauthenticated(vault_addr: str, timeout: int = 5) -> dict:
    """Read sys/internal/ui/mounts without authentication.

    Returns ``{mount_path: mount_type, ...}`` or an empty dict on failure.
    """
    url = f"{vault_addr.rstrip('/')}/v1/sys/internal/ui/mounts"
    try:
        resp = vault_request("GET", url, timeout=timeout)
    except Exception:
        return {}

    if resp.status_code != 200:
        return {}

    try:
        data = resp.json()
    except ValueError:
        return {}

    if not isinstance(data, dict):
        return {}

    secret = data.get("data", data).get("secret", {})
    if not isinstance(secret, dict):
        return {}

    mounts: dict[str, str] = {}
    for mount_path, info in secret.items():
        if isinstance(info, dict):
            mounts[mount_path] = info.get("type", "unknown")
    return mounts


# -----------------------------------------------------------------------
# Query helpers
# -----------------------------------------------------------------------


def _query_capabilities_self(client, paths):
    try:
        return client.sys.get_capabilities(paths=paths)
    except (AttributeError, TypeError):
        response = client.adapter.post(
            url="/v1/sys/capabilities-self",
            json={"paths": paths},
        )
        if isinstance(response, dict):
            return response
        if hasattr(response, "json"):
            return response.json()
        return response


def _extract_capability_results(response, requested_paths):
    if not isinstance(response, dict):
        data = {}
    else:
        data = response.get("data") if isinstance(response.get("data"), dict) else response

    results = []

    if "capabilities" in data and len(requested_paths) == 1:
        return [{
            "path": requested_paths[0],
            "capabilities": _normalize_capabilities(data.get("capabilities")),
        }]

    for path in requested_paths:
        capabilities = data.get(path)
        if capabilities is None:
            capabilities = data.get(path.lstrip("/"))

        results.append({
            "path": path,
            "capabilities": _normalize_capabilities(capabilities),
        })

    return results


# -----------------------------------------------------------------------
# Reporting
# -----------------------------------------------------------------------


def _report_capability_findings(results, vault_addr):
    """Report capability findings with wildcard deduplication.

    When a token has ``sudo`` on ``secret/*``, we do NOT also report
    separate findings for ``secret/data/*`` — the wildcard parent
    already covers those sub-paths.  This prevents the classic
    "50 identical findings spam" pentest report smell.
    """
    # ── Phase 1: collect raw findings by (type, path) ─────────────────
    raw: list[dict] = []
    for result in results:
        path = result["path"]
        capabilities = set(result["capabilities"])
        dangerous = capabilities.intersection(DANGEROUS_CAPABILITIES)
        if not dangerous:
            continue

        evidence = (
            f"path: {path}; "
            f"capabilities: {', '.join(sorted(capabilities))}"
        )
        if "root" in dangerous:
            raw.append({"type": "root", "severity": "CRITICAL",
                         "title": f"Token has root capability — {path}",
                         "desc": "ROOT means full control.", "rec": "Never expose root tokens.",
                         "evidence": evidence, "path": path})
        elif "sudo" in dangerous:
            raw.append({"type": "sudo", "severity": "CRITICAL",
                         "title": f"Token has sudo capability — {path}",
                         "desc": "Privileged sudo operations permitted.", "rec": "Restrict sudo to tightly controlled admin tokens.",
                         "evidence": evidence, "path": path})
        elif dangerous.intersection(WRITE_CAPABILITIES):
            raw.append({"type": "write", "severity": "HIGH",
                         "title": f"Token has write capability — {path}",
                         "desc": "Can modify data/configuration.", "rec": "Remove unnecessary write capabilities.",
                         "evidence": evidence, "path": path})
        elif _is_over_privileged(path, dangerous):
            raw.append({"type": "over_privileged", "severity": "HIGH",
                         "title": f"Over-privileged token capability — {path}",
                         "desc": "Sudo/write-like on critical path.", "rec": "Reduce policy scope.",
                         "evidence": f"{evidence}; {_over_privilege_evidence(path)}", "path": path})

    if not raw:
        return

    # ── Phase 2: deduplicate — wildcard parents cover children ─────────
    wildcard_paths = {f["path"] for f in raw if f["path"].endswith("/*") or f["path"] == "*"}
    skipped = 0
    emitted: set[tuple[str, str]] = set()  # (type, path)

    for f in sorted(raw, key=lambda x: (0 if x["path"].endswith("/*") else 1, x["path"])):
        p = f["path"]
        key = (f["type"], p)
        if key in emitted:
            continue

        # Skip if a wildcard parent already covers this path
        if not p.endswith("/*") and p != "*":
            if _is_covered_by_wildcard(p, list(wildcard_paths)):
                skipped += 1
                continue

        emitted.add(key)
        add_finding(
            severity=f["severity"],
            title=f["title"],
            description=f["desc"],
            recommendation=f["rec"],
            evidence=f["evidence"] + (
                f"; wildcard_covers_{skipped}_sub_paths" if skipped and p.endswith("/*") else ""
            ),
            module=MODULE,
            target=vault_addr,
        )


# -----------------------------------------------------------------------
# Auto-probe: read secrets from sudo+read paths
# -----------------------------------------------------------------------

# Wordlist of common secret names to probe under privileged paths
_SECRET_NAMES = [
    "config",
    "credentials",
    "creds",
    "token",
    "api-key",
    "api_key",
    "apikey",
    "master-key",
    "master_key",
    "secret",
    "secrets",
    "password",
    "passwd",
    "db-creds",
    "db_creds",
    "db-config",
    "db_config",
    "database",
    "aws-keys",
    "aws_keys",
    "aws-config",
    "aws_config",
    "ssh-key",
    "ssh_key",
    "cert",
    "certificate",
    "private-key",
    "private_key",
    "vault-config",
    "vault_config",
    "admin",
    "root",
    "backup",
    "backup-config",
    "backup_config",
]


def _probe_sudo_secrets(vault_addr, token, results, namespace, timeout, verify):
    """For every path with sudo+read, probe common secret names and read data."""
    # Find paths with both 'sudo'/'root' and 'read'
    sudo_read_paths = []
    for r in results:
        caps = set(r.get("capabilities", []))
        if ("sudo" in caps or "root" in caps) and "read" in caps and "*" in r.get("path", ""):
            sudo_read_paths.append(r["path"])

    if not sudo_read_paths:
        return

    logger.info(f"\n[*] Probing {len(sudo_read_paths)} privileged wildcard path(s) for secrets...")
    vault_addr = vault_addr.rstrip("/")

    for wildcard_path in sudo_read_paths:
        base = _wildcard_base_path(wildcard_path)
        if not base:
            continue

        # Convert policy path to data path: secret-v2/data/admin/* -> secret-v2/data/admin
        data_base = _to_data_path(base)

        found_any = False
        for name in _SECRET_NAMES:
            secret_path = f"{data_base}/{name}"
            url = f"{vault_addr}/v1/{secret_path}"
            try:
                resp = vault_request(
                    "GET", url,
                    headers={"X-Vault-Token": token},
                    timeout=timeout, verify=verify,
                )
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            try:
                body = resp.json()
            except ValueError:
                continue

            secret_data = body.get("data", {}).get("data", {})
            if not secret_data:
                continue

            found_any = True
            keys_found = list(secret_data.keys())
            logger.info(f"[+] SECRET FOUND: {secret_path} -> {keys_found}")

            add_finding(
                severity="CRITICAL",
                title=f"Secret exfiltrated from privileged path: {secret_path}",
                description=(
                    f"Token with sudo+read on '{wildcard_path}' was used to "
                    f"read secret at '{secret_path}'. Keys found: {keys_found}"
                ),
                evidence={
                    "wildcard_path": wildcard_path,
                    "secret_path": secret_path,
                    "keys": keys_found,
                    "data": dict(secret_data),
                },
                module=MODULE,
                target=vault_addr,
            )

        if not found_any:
            logger.info(f"    {wildcard_path} -> no secrets found under {data_base}")


def _wildcard_base_path(wildcard_path):
    """Strip the wildcard portion: 'secret-v2/data/admin/*' -> 'secret-v2/data/admin'"""
    idx = wildcard_path.find("*")
    if idx == -1:
        return wildcard_path.rstrip("/")
    return wildcard_path[:idx].rstrip("/")


def _to_data_path(base):
    """Ensure the path uses the data/ prefix for KV v2 reads.

    'secret-v2/admin' -> 'secret-v2/data/admin'
    'secret-v2/data/admin' -> 'secret-v2/data/admin'  (already correct)
    """
    parts = base.strip("/").split("/")
    # If it's already a data path, return as-is
    if "data" in parts:
        return base.strip("/")
    # Insert 'data' after mount name: secret-v2/admin -> secret-v2/data/admin
    if len(parts) >= 2:
        mount = parts[0]
        rest = "/".join(parts[1:])
        return f"{mount}/data/{rest}"
    return base.strip("/")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _normalize_paths(paths):
    if not paths:
        return []

    normalized = []
    for path in paths:
        if not path:
            continue
        clean_path = str(path).strip()
        if clean_path and clean_path not in normalized:
            normalized.append(clean_path)
    return normalized


def _normalize_capabilities(capabilities):
    if not capabilities:
        return []
    return sorted({str(capability).lower() for capability in capabilities})


def _has_dangerous_capability(results):
    for result in results:
        if set(result["capabilities"]).intersection(DANGEROUS_CAPABILITIES):
            return True
    return False


def _is_over_privileged(path, dangerous_capabilities):
    normalized_path = path.lstrip("/")
    is_critical_path = normalized_path.startswith(CRITICAL_PATH_PREFIXES)
    has_wildcard_scope = "*" in normalized_path
    has_sudo_or_write = bool(dangerous_capabilities)
    return has_sudo_or_write and (is_critical_path or has_wildcard_scope)


def _over_privilege_evidence(path):
    normalized_path = path.lstrip("/")
    evidence = []

    if normalized_path.startswith(CRITICAL_PATH_PREFIXES):
        evidence.append("critical_path: true")
    if "*" in normalized_path:
        evidence.append("audited_path_contains_wildcard: true")

    return "; ".join(evidence)
