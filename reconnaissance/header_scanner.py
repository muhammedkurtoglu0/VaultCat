from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "header_scanner"


def scan_headers(target, context=None):
    findings = []

    print("\n[+] Analyzing HTTP response headers...")

    response = context.fetch_health_once() if context else safe_request("GET", target, "/v1/sys/health")
    if not isinstance(response, Response):
        findings.append(add_finding(
            "INFO",
            "Header analysis unavailable",
            "The scanner could not retrieve HTTP headers from the health endpoint.",
            recommendation="Confirm target reachability and repeat header analysis.",
            evidence=str(response),
            module=MODULE_NAME,
            target=target
        ))
        return findings

    headers = response.headers
    security_headers = {
        "Strict-Transport-Security": "Use HSTS on HTTPS deployments to reduce downgrade risk.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
        "X-Frame-Options": "Set X-Frame-Options or a CSP frame-ancestors directive where appropriate.",
        "Content-Security-Policy": "Set a restrictive Content-Security-Policy for browser-exposed routes.",
        "Referrer-Policy": "Set Referrer-Policy to reduce metadata leakage.",
    }

    for header_name, recommendation in security_headers.items():
        if header_name not in headers:
            findings.append(add_finding(
                "LOW",
                f"Missing {header_name} header",
                f"The response did not include the {header_name} security header.",
                recommendation=recommendation,
                evidence=f"endpoint: /v1/sys/health, status_code: {response.status_code}",
                module=MODULE_NAME,
                target=target
            ))

    server_header = headers.get("Server")
    if server_header:
        findings.append(add_finding(
            "LOW",
            "Server header exposed",
            "The response includes a Server header that may disclose platform details.",
            recommendation="Suppress or minimize infrastructure-identifying response headers where possible.",
            evidence=f"Server: {server_header}",
            module=MODULE_NAME,
            target=target
        ))

    cors_origin = headers.get("Access-Control-Allow-Origin")
    if cors_origin:
        severity = "MEDIUM" if cors_origin == "*" else "LOW"
        findings.append(add_finding(
            severity,
            "CORS header exposed",
            "The response includes an Access-Control-Allow-Origin header.",
            recommendation="Restrict CORS origins to explicitly trusted applications.",
            evidence=f"Access-Control-Allow-Origin: {cors_origin}",
            module=MODULE_NAME,
            target=target
        ))

    if not findings:
        findings.append(add_finding(
            "PASS",
            "No weak headers detected",
            "The checked response did not expose the curated weak header conditions.",
            recommendation="Continue reviewing headers across externally exposed Vault routes.",
            evidence="endpoint: /v1/sys/health",
            module=MODULE_NAME,
            target=target
        ))

    return findings
