import re

import requests

from core.report import add_finding


MODULE = "ttl_scanner"
TIMEOUT = 5
DEFAULT_MAX_MOUNT_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_MAX_PKI_CERT_TTL_SECONDS = 90 * 24 * 60 * 60
DURATION_PATTERN = re.compile(r"(\d+)\s*([smhd])", re.IGNORECASE)


def scan_ttl_governance(
    vault_addr,
    token,
    namespace=None,
    max_mount_ttl_seconds=DEFAULT_MAX_MOUNT_TTL_SECONDS,
    max_pki_cert_ttl_seconds=DEFAULT_MAX_PKI_CERT_TTL_SECONDS,
):
    print("\n[+] Auditing Vault mount and PKI TTL governance...")

    if not vault_addr or not token:
        add_finding(
            "INFO",
            "TTL governance audit skipped",
            "TTL governance audit requires both --target and --token.",
            recommendation="Provide an authorized Vault target and token.",
            evidence="missing target or token",
            module=MODULE,
            target=vault_addr or "ttl-governance-audit",
        )
        return {"risk_score": 0, "checks": []}

    response = _vault_request("GET", vault_addr, "sys/mounts", token, namespace)
    if not _is_success(response):
        add_finding(
            "LOW",
            "Secrets engine mount TTL discovery failed",
            "The scanner could not read sys/mounts to inspect secrets engine TTL configuration.",
            recommendation="Run this audit with a token authorized to read sys/mounts.",
            evidence=_response_evidence("GET", "sys/mounts", response),
            module=MODULE,
            target=vault_addr,
        )
        return {"risk_score": 0, "checks": []}

    mounts = _extract_mounts(response)
    checks = []
    for mount_path, mount_data in mounts.items():
        checks.extend(_audit_mount_ttl(
            vault_addr,
            mount_path,
            mount_data,
            max_mount_ttl_seconds,
        ))
        if mount_data.get("type") == "pki":
            checks.extend(_audit_pki_roles(
                vault_addr,
                token,
                namespace,
                mount_path,
                max_pki_cert_ttl_seconds,
            ))

    if not checks:
        add_finding(
            "PASS",
            "No secrets engine TTL findings observed",
            "The scanner did not identify mount TTL or PKI role TTL governance issues.",
            recommendation="Continue periodic TTL governance review.",
            evidence=f"mounts_checked: {len(mounts)}",
            module=MODULE,
            target=vault_addr,
        )

    risk_score = min(sum(check["risk_score"] for check in checks), 100)
    print(f"TTL Governance Risk Score: {risk_score} / 100")
    return {"risk_score": risk_score, "checks": checks}


def _audit_mount_ttl(vault_addr, mount_path, mount_data, max_mount_ttl_seconds):
    checks = []
    config = mount_data.get("config", {}) if isinstance(mount_data, dict) else {}
    max_ttl_raw = config.get("max_lease_ttl")
    max_ttl_seconds = parse_duration_seconds(max_ttl_raw)
    evidence = (
        f"mount: {mount_path}, type: {mount_data.get('type')}, "
        f"max_lease_ttl: {max_ttl_raw}, threshold_seconds: {max_mount_ttl_seconds}"
    )

    if _is_unlimited_ttl(max_ttl_raw, max_ttl_seconds):
        checks.append(_record_risk(
            vault_addr,
            "HIGH",
            25,
            "Secrets engine max lease TTL appears unlimited",
            "A secrets engine mount reports max_lease_ttl as zero or unset-equivalent.",
            "Set an explicit max_lease_ttl aligned with corporate secret lifetime policy.",
            evidence,
        ))
    elif max_ttl_seconds and max_ttl_seconds > max_mount_ttl_seconds:
        checks.append(_record_risk(
            vault_addr,
            "MEDIUM",
            10,
            "Secrets engine max lease TTL exceeds policy threshold",
            "A secrets engine mount has a max_lease_ttl longer than the configured corporate threshold.",
            "Tune the secrets engine max lease TTL to the smallest operationally required value.",
            f"{evidence}, max_lease_ttl_seconds: {max_ttl_seconds}",
        ))

    return checks


def _audit_pki_roles(vault_addr, token, namespace, mount_path, max_pki_cert_ttl_seconds):
    checks = []
    base = mount_path.strip("/")
    role_names = _list(vault_addr, token, namespace, f"{base}/roles")
    if role_names is None:
        checks.append(_record_inconclusive(
            vault_addr,
            "PKI role list unavailable",
            f"{base}/roles",
        ))
        return checks

    for role_name in role_names:
        response = _vault_request("GET", vault_addr, f"{base}/roles/{role_name}", token, namespace)
        if not _is_success(response):
            checks.append(_record_inconclusive(
                vault_addr,
                "PKI role TTL metadata unavailable",
                f"{base}/roles/{role_name}",
            ))
            continue

        data = _response_data(response)
        checks.extend(_audit_pki_role_ttl(
            vault_addr,
            mount_path,
            role_name,
            data,
            max_pki_cert_ttl_seconds,
        ))

    return checks


def _audit_pki_role_ttl(vault_addr, mount_path, role_name, role_data, max_pki_cert_ttl_seconds):
    checks = []
    for field in ("max_ttl", "ttl"):
        raw_value = role_data.get(field)
        seconds = parse_duration_seconds(raw_value)
        evidence = (
            f"mount: {mount_path}, role: {role_name}, field: {field}, "
            f"value: {raw_value}, threshold_seconds: {max_pki_cert_ttl_seconds}"
        )

        if raw_value is None or raw_value == "":
            continue

        if _is_unlimited_ttl(raw_value, seconds):
            checks.append(_record_risk(
                vault_addr,
                "HIGH",
                25,
                "PKI certificate role TTL appears unlimited",
                "A PKI role appears to allow an unlimited or unset-equivalent certificate lifetime.",
                "Set explicit ttl and max_ttl values for PKI roles.",
                evidence,
            ))
        elif seconds and seconds > max_pki_cert_ttl_seconds:
            checks.append(_record_risk(
                vault_addr,
                "MEDIUM",
                10,
                "PKI certificate role TTL exceeds policy threshold",
                "A PKI role permits certificate lifetimes longer than the configured corporate threshold.",
                "Reduce PKI role ttl/max_ttl values to meet certificate lifecycle policy.",
                f"{evidence}, seconds: {seconds}",
            ))

    return checks


def parse_duration_seconds(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value

    text = str(value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return int(text)

    total = 0
    matched = False
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    for amount, unit in DURATION_PATTERN.findall(text):
        matched = True
        total += int(amount) * multipliers[unit.lower()]
    return total if matched else None


def _extract_mounts(response):
    data = _response_data(response)
    return {
        path: mount_data
        for path, mount_data in data.items()
        if isinstance(mount_data, dict)
    }


def _list(vault_addr, token, namespace, path):
    response = _vault_request("LIST", vault_addr, path, token, namespace)
    if response is not None and getattr(response, "status_code", None) == 405:
        response = _vault_request("GET", vault_addr, path.rstrip("/") + "?list=true", token, namespace)
    if not _is_success(response):
        return None
    return [key.strip("/") for key in _response_data(response).get("keys", [])]


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
        )
    except requests.exceptions.RequestException as error:
        return error


def _is_success(response):
    return hasattr(response, "status_code") and 200 <= response.status_code < 300


def _response_data(response):
    if not _is_success(response):
        return {}
    try:
        body = response.json()
    except ValueError:
        return {}
    data = body.get("data", body) if isinstance(body, dict) else {}
    return data if isinstance(data, dict) else {}


def _response_evidence(method, path, response):
    if hasattr(response, "status_code"):
        return f"method: {method}, path: {path}, status_code: {response.status_code}"
    return f"method: {method}, path: {path}, error: {response}"


def _is_unlimited_ttl(raw_value, seconds):
    if raw_value is None:
        return False
    if seconds == 0:
        return True
    return str(raw_value).strip().lower() in {"0", "0s", "0m", "0h", "0d"}


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


def _record_inconclusive(vault_addr, title, path):
    finding = add_finding(
        "INFO",
        title,
        "The scanner could not read TTL metadata required for this check.",
        recommendation="Confirm token permissions and review this TTL configuration manually if needed.",
        evidence=f"path: {path}, risk_score: 1",
        module=MODULE,
        target=vault_addr,
    )
    return {"severity": "INFO", "risk_score": 1, "title": title, "finding": finding}
