from core.report import add_finding


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

DEFAULT_CAPABILITY_PATHS = [
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
]


def audit_token_capabilities(vault_addr, token, paths=None, namespace=None, timeout=5):
    """Audit a token's capabilities without reading or modifying secrets."""
    print("\n[+] Auditing token capabilities with sys/capabilities-self...")

    if not vault_addr or not token:
        print("[!] Capability audit requires both Vault address and token.")
        return []

    audit_paths = _normalize_paths(paths)
    if not audit_paths:
        audit_paths = DEFAULT_CAPABILITY_PATHS

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
