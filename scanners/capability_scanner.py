"""Token capability audit via sys/capabilities-self.

Dynamically discovers secret engine mounts (unauthenticated via
``sys/internal/ui/mounts``) and includes them in the audit so that
environment-specific paths (e.g. ``secret-v2/data/admin/*``) are
not missed by a hardcoded path list.
"""

from __future__ import annotations

from core.report import add_finding
from core.tls_config import get_verify, vault_request

MODULE = "capability_scanner"

DANGEROUS_CAPABILITIES = {"sudo", "create", "update", "delete", "patch"}
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
    print("\n[+] Auditing token capabilities with sys/capabilities-self...")

    if not vault_addr or not token:
        print("[!] Capability audit requires both Vault address and token.")
        return []

    audit_paths = _normalize_paths(paths)
    if not audit_paths:
        audit_paths = list(_BASELINE_PATHS)
        # Dynamically discover mounts and add their paths
        dynamic = _discover_mount_paths(vault_addr, timeout)
        for p in dynamic:
            if p not in audit_paths:
                audit_paths.append(p)

    print(f"[*] Auditing {len(audit_paths)} paths...")

    try:
        import hvac
    except ImportError:
        print("[!] Missing dependency: hvac. Install requirements before running capability audit.")
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
        print(f"[!] Capability audit failed: {error}")
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

        if _is_over_privileged(path, dangerous):
            add_finding(
                severity="HIGH",
                title="Over-privileged token capability on critical Vault path",
                description=(
                    "The supplied token has sudo or write-like capabilities on a critical Vault path. "
                    "If the audited path contains a wildcard, the effective scope may be broader than least privilege."
                ),
                recommendation=(
                    "Reduce the token policy to the minimum required paths and capabilities. "
                    "Avoid wildcard access on system, auth, identity, and database role/config paths."
                ),
                evidence=f"{evidence}; {_over_privilege_evidence(path)}",
                module=MODULE,
                target=vault_addr,
            )

        if "sudo" in dangerous:
            add_finding(
                severity="CRITICAL",
                title="Token has sudo capability on Vault path",
                description="The supplied token can perform privileged sudo operations on the audited Vault path.",
                recommendation="Restrict sudo capabilities to tightly controlled administrative tokens and rotate exposed credentials.",
                evidence=evidence,
                module=MODULE,
                target=vault_addr,
            )

        write_caps = dangerous.intersection(WRITE_CAPABILITIES)
        if write_caps:
            add_finding(
                severity="HIGH",
                title="Token has write capability on Vault path",
                description="The supplied token can modify data or configuration on the audited Vault path.",
                recommendation="Review policy scope, remove unnecessary write capabilities, and rotate the exposed token if compromise is suspected.",
                evidence=evidence,
                module=MODULE,
                target=vault_addr,
            )


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
