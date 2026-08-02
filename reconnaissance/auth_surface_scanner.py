from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request
from core.logger import logger


MODULE_NAME = "auth_surface_scanner"

AUTH_METHODS = {
    "userpass": "LOW",
    "approle": "LOW",
    "oidc": "INFO",
    "jwt": "INFO",
    "ldap": "LOW",
    "github": "INFO",
    "kubernetes": "INFO",
    "token": "INFO",
    "cert": "LOW",
}

AUTH_ENDPOINTS = (
    "/v1/sys/internal/ui/mounts",
    "/ui/",
    "/ui/vault/auth",
)


def scan_auth_surface(target, context=None):
    findings = []
    detected_mounts = {}

    logger.info("\n[+] Scanning authentication surface...")

    for endpoint in AUTH_ENDPOINTS:
        response = (
            context.request_once("GET", endpoint)
            if context else safe_request("GET", target, endpoint)
        )

        if not isinstance(response, Response):
            logger.warning(f"[-] {endpoint} request failed: {response}")
            continue

        logger.info(f"{endpoint} -> HTTP {response.status_code}")

        if endpoint == "/v1/sys/internal/ui/mounts":
            detected_mounts.update(_parse_ui_mounts_response(response, endpoint))

    for method, evidence in sorted(detected_mounts.items()):
        severity = AUTH_METHODS[method]
        findings.append(add_finding(
            severity,
            f"Detected auth mount: {method}",
            f"The target appears to expose or reference the {method} authentication method.",
            recommendation=(
                "Confirm that this authentication method is intentionally exposed and protected "
                "by proper controls."
            ),
            evidence=evidence,
            module=MODULE_NAME,
            target=target
        ))

    if not findings:
        findings.append(add_finding(
            "PASS",
            "No auth methods exposed",
            "The scanner did not identify supported auth method signals from unauthenticated endpoints.",
            recommendation="Continue validating auth surface exposure from trusted and untrusted networks.",
            evidence="Checked /v1/sys/internal/ui/mounts, /ui/, and /ui/vault/auth.",
            module=MODULE_NAME,
            target=target
        ))

    return findings


def _parse_ui_mounts_response(response, endpoint):
    try:
        data = response.json()
    except ValueError:
        return {}

    auth_mounts = data.get("data", {}).get("auth", {})
    if not isinstance(auth_mounts, dict):
        return {}

    discovered_methods = {}
    for path, mount_data in auth_mounts.items():
        if not isinstance(mount_data, dict):
            continue

        method = mount_data.get("type") or _method_from_path(path)
        if method not in AUTH_METHODS:
            continue

        discovered_methods[method] = (
            f"endpoint: {endpoint}, auth_path: {path}, mount_type: {method}"
        )

    return discovered_methods


def _method_from_path(path):
    normalized_path = path.strip("/").lower()
    first_segment = normalized_path.split("/", 1)[0]

    if first_segment in AUTH_METHODS:
        return first_segment

    return None
