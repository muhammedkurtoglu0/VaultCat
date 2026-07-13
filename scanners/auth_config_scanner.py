import requests

from core.report import add_finding
from core.tls_config import get_verify


MODULE = "auth_config_scanner"
TIMEOUT = 5
SUPPORTED_AUTH_TYPES = {"kubernetes", "aws", "ldap"}


def scan_auth_config_security(vault_addr, token, namespace=None):
    print("\n[+] Auditing external auth method configuration...")

    if not vault_addr or not token:
        add_finding(
            "INFO",
            "Auth configuration audit skipped",
            "Auth configuration audit requires both --target and --token.",
            recommendation="Provide an authorized Vault target and token.",
            evidence="missing target or token",
            module=MODULE,
            target=vault_addr or "auth-config-audit",
        )
        return {"risk_score": 0, "checks": []}

    mounts_response = _vault_request("GET", vault_addr, "sys/auth", token, namespace)
    if not _is_success(mounts_response):
        add_finding(
            "LOW",
            "Auth mount discovery failed",
            "The scanner could not read sys/auth to discover configured auth methods.",
            recommendation="Run this audit with a token authorized to read auth mount metadata.",
            evidence=_response_evidence("GET", "sys/auth", mounts_response),
            module=MODULE,
            target=vault_addr,
        )
        return {"risk_score": 0, "checks": []}

    mounts = _extract_auth_mounts(mounts_response)
    checks = []
    for mount in mounts:
        if mount["type"] == "kubernetes":
            checks.extend(_audit_kubernetes_auth(vault_addr, token, namespace, mount))
        elif mount["type"] == "aws":
            checks.extend(_audit_aws_auth(vault_addr, token, namespace, mount))
        elif mount["type"] == "ldap":
            checks.extend(_audit_ldap_auth(vault_addr, token, namespace, mount))

    if not checks:
        add_finding(
            "PASS",
            "No supported external auth configs observed",
            "The scanner did not observe Kubernetes, AWS, or LDAP auth mounts from sys/auth.",
            recommendation="No action required for this specific auth configuration audit scope.",
            evidence="supported_auth_types: kubernetes, aws, ldap",
            module=MODULE,
            target=vault_addr,
        )

    risk_score = min(sum(check["risk_score"] for check in checks), 100)
    print(f"Auth Config Risk Score: {risk_score} / 100")
    return {"risk_score": risk_score, "checks": checks}


def _audit_kubernetes_auth(vault_addr, token, namespace, mount):
    checks = []
    mount_path = mount["path"]
    role_names = _list_role_names(vault_addr, token, namespace, mount_path)

    for role_name in role_names:
        role_path = f"auth/{mount_path}/role/{role_name}"
        response = _vault_request("GET", vault_addr, role_path, token, namespace)
        if not _is_success(response):
            checks.append(_record_inconclusive(
                vault_addr,
                "Kubernetes auth role could not be read",
                role_path,
                response,
            ))
            continue

        data = _response_data(response)
        names = _as_list(data.get("bound_service_account_names"))
        namespaces = _as_list(data.get("bound_service_account_namespaces"))
        has_name_wildcard = _has_wildcard(names)
        has_namespace_wildcard = _has_wildcard(namespaces)
        evidence = (
            f"mount: {mount_path}, role: {role_name}, "
            f"bound_service_account_names: {names}, "
            f"bound_service_account_namespaces: {namespaces}"
        )

        if has_name_wildcard and has_namespace_wildcard:
            checks.append(_record_risk(
                vault_addr,
                "CRITICAL",
                40,
                "Kubernetes auth role allows all service accounts",
                "A Kubernetes auth role is bound to wildcard service account names and namespaces.",
                "Restrict bound_service_account_names and bound_service_account_namespaces to specific workload identities.",
                evidence,
            ))
        elif has_name_wildcard:
            checks.append(_record_risk(
                vault_addr,
                "HIGH",
                25,
                "Kubernetes auth role uses wildcard service account names",
                "A Kubernetes auth role uses bound_service_account_names='*', which may allow overly broad workload authentication.",
                "Bind roles to explicit Kubernetes service account names.",
                evidence,
            ))
        elif has_namespace_wildcard:
            checks.append(_record_risk(
                vault_addr,
                "MEDIUM",
                10,
                "Kubernetes auth role uses wildcard namespace binding",
                "A Kubernetes auth role uses wildcard service account namespaces.",
                "Bind roles to explicit namespaces unless broad namespace trust is explicitly required.",
                evidence,
            ))
        else:
            checks.append(_record_pass(
                vault_addr,
                "Kubernetes auth role has scoped service account bindings",
                evidence,
            ))

    return checks


def _audit_aws_auth(vault_addr, token, namespace, mount):
    checks = []
    mount_path = mount["path"]
    role_names = _list_role_names(vault_addr, token, namespace, mount_path)

    for role_name in role_names:
        role_path = f"auth/{mount_path}/role/{role_name}"
        response = _vault_request("GET", vault_addr, role_path, token, namespace)
        if not _is_success(response):
            checks.append(_record_inconclusive(
                vault_addr,
                "AWS auth role could not be read",
                role_path,
                response,
            ))
            continue

        data = _response_data(response)
        principal_arns = _as_list(data.get("bound_iam_principal_arn"))
        account_ids = _as_list(data.get("bound_account_id"))
        wildcard_principals = [value for value in principal_arns if _contains_wildcard(value)]
        wildcard_accounts = [value for value in account_ids if _contains_wildcard(value)]
        evidence = (
            f"mount: {mount_path}, role: {role_name}, "
            f"bound_iam_principal_arn: {principal_arns}, "
            f"bound_account_id: {account_ids}"
        )

        if wildcard_principals:
            checks.append(_record_risk(
                vault_addr,
                "HIGH",
                25,
                "AWS auth role uses wildcard IAM principal binding",
                "An AWS auth role includes wildcard values in bound_iam_principal_arn.",
                "Bind AWS auth roles to explicit IAM principal ARNs and review whether wildcard trust is required.",
                evidence,
            ))
        elif wildcard_accounts:
            checks.append(_record_risk(
                vault_addr,
                "MEDIUM",
                10,
                "AWS auth role uses wildcard account binding",
                "An AWS auth role includes wildcard values in bound_account_id.",
                "Bind AWS auth roles to explicit AWS account IDs and principal constraints.",
                evidence,
            ))
        else:
            checks.append(_record_pass(
                vault_addr,
                "AWS auth role has scoped IAM bindings",
                evidence,
            ))

    return checks


def _audit_ldap_auth(vault_addr, token, namespace, mount):
    checks = []
    mount_path = mount["path"]
    config_path = f"auth/{mount_path}/config"
    tune_path = f"sys/auth/{mount_path}/tune"

    config_response = _vault_request("GET", vault_addr, config_path, token, namespace)
    tune_response = _vault_request("GET", vault_addr, tune_path, token, namespace)

    lockout_config = _extract_lockout_config(config_response, tune_response)
    evidence = (
        f"mount: {mount_path}, config_status: {_status(config_response)}, "
        f"tune_status: {_status(tune_response)}, lockout_config: {lockout_config or '<not-observed>'}"
    )

    if not lockout_config:
        checks.append(_record_risk(
            vault_addr,
            "INFO",
            1,
            "LDAP lockout configuration not observable",
            "The scanner could not observe LDAP lockout or rate-limit configuration from the available API responses.",
            "Confirm LDAP user lockout settings through Vault server configuration, auth tune settings, or administrative review.",
            evidence,
        ))
        return checks

    if _is_truthy(lockout_config.get("disable_lockout")):
        checks.append(_record_risk(
            vault_addr,
            "HIGH",
            25,
            "LDAP user lockout appears disabled",
            "LDAP auth lockout configuration indicates disable_lockout is enabled.",
            "Enable user lockout for LDAP auth or document compensating controls.",
            evidence,
        ))
    elif _is_zero(lockout_config.get("lockout_threshold")):
        checks.append(_record_risk(
            vault_addr,
            "HIGH",
            25,
            "LDAP lockout threshold appears disabled",
            "LDAP auth lockout threshold appears to be zero or disabled.",
            "Configure a positive lockout threshold and review rate-limiting controls.",
            evidence,
        ))
    else:
        checks.append(_record_pass(
            vault_addr,
            "LDAP user lockout configuration observed",
            evidence,
        ))

    return checks


def _extract_auth_mounts(response):
    mounts = []
    data = _response_data(response)
    for path, metadata in data.items():
        if not isinstance(metadata, dict):
            continue
        mount_type = metadata.get("type")
        if mount_type not in SUPPORTED_AUTH_TYPES:
            continue
        mounts.append({
            "path": path.strip("/"),
            "type": mount_type,
        })
    return mounts


def _list_role_names(vault_addr, token, namespace, mount_path):
    role_path = f"auth/{mount_path}/role"
    response = _vault_request("LIST", vault_addr, role_path, token, namespace)
    if not _is_success(response):
        add_finding(
            "INFO",
            "Auth role list unavailable",
            "The scanner could not list roles for an external auth mount.",
            recommendation="Run this audit with a token authorized to list auth roles, or provide role-specific review evidence.",
            evidence=_response_evidence("LIST", role_path, response),
            module=MODULE,
            target=vault_addr,
        )
        return []
    return [key.strip("/") for key in _response_data(response).get("keys", [])]


def _extract_lockout_config(config_response, tune_response):
    for response in (tune_response, config_response):
        if not _is_success(response):
            continue
        data = _response_data(response)
        for key in ("user_lockout", "lockout", "rate_limit"):
            value = data.get(key)
            if isinstance(value, dict):
                return value
        lockout_fields = {
            key: data[key]
            for key in (
                "disable_lockout",
                "lockout_threshold",
                "lockout_duration",
                "lockout_counter_reset_duration",
            )
            if key in data
        }
        if lockout_fields:
            return lockout_fields
    return {}


def _record_risk(vault_addr, severity, risk_score, title, description, recommendation, evidence):
    finding = add_finding(
        severity,
        title,
        description,
        recommendation=recommendation,
        evidence=f"{evidence}, risk_score: {risk_score}",
        module=MODULE,
        target=vault_addr,
    )
    return {"severity": severity, "risk_score": risk_score, "title": title, "finding": finding}


def _record_pass(vault_addr, title, evidence):
    finding = add_finding(
        "PASS",
        title,
        "The observed auth configuration did not match the risky patterns checked by this module.",
        recommendation="Continue enforcing explicit bindings and periodic configuration review.",
        evidence=f"{evidence}, risk_score: 0",
        module=MODULE,
        target=vault_addr,
    )
    return {"severity": "PASS", "risk_score": 0, "title": title, "finding": finding}


def _record_inconclusive(vault_addr, title, path, response):
    finding = add_finding(
        "INFO",
        title,
        "The scanner could not read an auth configuration endpoint required for this check.",
        recommendation="Confirm token permissions and review the auth role manually if needed.",
        evidence=_response_evidence("GET", path, response),
        module=MODULE,
        target=vault_addr,
    )
    return {"severity": "INFO", "risk_score": 1, "title": title, "finding": finding}


def _vault_request(method, vault_addr, path, token, namespace=None):
    headers = {"X-Vault-Token": token}
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    try:
        return requests.request(
            method,
            f"{vault_addr.rstrip('/')}/v1/{path.lstrip('/')}",
            headers=headers,
            timeout=TIMEOUT,
            verify=get_verify(),
        )
    except requests.exceptions.RequestException as error:
        return error


def _is_success(response):
    return hasattr(response, "status_code") and 200 <= response.status_code < 300


def _status(response):
    return response.status_code if hasattr(response, "status_code") else "request_error"


def _response_data(response):
    if not _is_success(response):
        return {}
    try:
        body = response.json()
    except ValueError:
        return {}
    data = body.get("data", {}) if isinstance(body, dict) else {}
    return data if isinstance(data, dict) else {}


def _response_evidence(method, path, response):
    if hasattr(response, "status_code"):
        return f"method: {method}, path: {path}, status_code: {response.status_code}"
    return f"method: {method}, path: {path}, error: {response}"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]
        return [value]
    return [str(value)]


def _has_wildcard(values):
    return any(value.strip() == "*" for value in values)


def _contains_wildcard(value):
    return "*" in str(value)


def _is_truthy(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def _is_zero(value):
    try:
        return int(value) == 0
    except (TypeError, ValueError):
        return False
