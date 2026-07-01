from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "deployment_scanner"

DEVELOPMENT_PHRASES = (
    "development mode",
    "dev mode",
    "vault dev",
    "docker",
)


def scan_deployment(target):
    findings = []

    print("\n[+] Assessing deployment-level security indicators...")

    health_response = safe_request("GET", target, "/v1/sys/health")
    if isinstance(health_response, Response):
        print(f"/v1/sys/health -> HTTP {health_response.status_code}")
        _check_reverse_proxy_headers(findings, target, health_response)
        _check_development_indicators(findings, target, health_response, "/v1/sys/health")

    ui_response = safe_request("GET", target, "/ui/", allow_redirects=False)
    if isinstance(ui_response, Response):
        print(f"/ui/ -> HTTP {ui_response.status_code}")
        _check_development_indicators(findings, target, ui_response, "/ui/")

    return findings

def _check_reverse_proxy_headers(findings, target, response):
    server_header = response.headers.get("Server")
    if not server_header:
        return

    if "nginx" in server_header.lower() or "apache" in server_header.lower():
        findings.append(add_finding(
            "LOW",
            "Reverse proxy server header exposed",
            "The deployment exposes a reverse proxy Server header.",
            recommendation="Minimize infrastructure-identifying headers on externally exposed Vault deployments.",
            evidence=f"endpoint: /v1/sys/health, Server: {server_header}",
            module=MODULE_NAME,
            target=target
        ))


def _check_development_indicators(findings, target, response, endpoint):
    observed_indicators = []

    for header_name, header_value in response.headers.items():
        header_text = f"{header_name}: {header_value}".lower()
        observed_indicators.extend(_matched_development_phrases(header_text))

    content_type = response.headers.get("Content-Type", "")
    if "text/" in content_type or "json" in content_type:
        body_sample = response.text[:5000].lower()
        observed_indicators.extend(_matched_development_phrases(body_sample))

    unique_indicators = sorted(set(observed_indicators))
    if unique_indicators:
        findings.append(add_finding(
            "LOW",
            "Deployment development indicator observed",
            "The response contains explicit wording associated with Docker or development environments.",
            recommendation="Remove development indicators from externally exposed responses and confirm the deployment is production hardened.",
            evidence=f"endpoint: {endpoint}, indicators: {', '.join(unique_indicators)}",
            module=MODULE_NAME,
            target=target
        ))


def _matched_development_phrases(text):
    return [
        phrase for phrase in DEVELOPMENT_PHRASES
        if phrase in text
    ]
