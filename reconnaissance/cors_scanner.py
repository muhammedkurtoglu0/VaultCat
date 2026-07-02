from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "cors_scanner"
ENDPOINT = "/v1/sys/health"


def scan_cors(target, context=None):
    findings = []

    print("\n[+] Analyzing CORS behavior...")

    response = context.fetch_health_once() if context else safe_request("GET", target, ENDPOINT)
    if not isinstance(response, Response):
        return findings

    findings.extend(_analyze_cors_headers(target, response, "GET"))

    options_response = (
        context.request_once("OPTIONS", ENDPOINT)
        if context else safe_request("OPTIONS", target, ENDPOINT)
    )
    if isinstance(options_response, Response):
        print(f"OPTIONS {ENDPOINT} -> HTTP {options_response.status_code}")
        if options_response.status_code in (200, 204):
            findings.append(add_finding(
                "INFO",
                "CORS preflight supported",
                "The endpoint responds successfully to an OPTIONS preflight request.",
                recommendation="Confirm that preflight support is intentional for the exposed Vault API endpoint.",
                evidence=_header_evidence(options_response, "OPTIONS"),
                module=MODULE_NAME,
                target=target
            ))

        if options_response.headers.get("Access-Control-Allow-Origin"):
            findings.extend(_analyze_cors_headers(target, options_response, "OPTIONS"))

    return findings


def _analyze_cors_headers(target, response, method):
    findings = []
    headers = response.headers

    allow_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials")

    if not allow_origin:
        findings.append(add_finding(
            "PASS",
            "No CORS policy observed",
            "The response did not include an Access-Control-Allow-Origin header.",
            recommendation="No action required unless cross-origin browser access is expected.",
            evidence=_header_evidence(response, method),
            module=MODULE_NAME,
            target=target
        ))
        return findings

    if allow_origin.strip() == "*":
        findings.append(add_finding(
            "LOW",
            "Wildcard CORS origin observed",
            "The server allows requests from any origin.",
            recommendation="Review whether unrestricted cross-origin access is necessary.",
            evidence=_header_evidence(response, method),
            module=MODULE_NAME,
            target=target
        ))
    else:
        findings.append(add_finding(
            "INFO",
            "Specific CORS origin configured",
            "The server returned a specific Access-Control-Allow-Origin value.",
            recommendation="Confirm that the configured origin is trusted and intentionally allowed.",
            evidence=_header_evidence(response, method),
            module=MODULE_NAME,
            target=target
        ))

    if _is_true(allow_credentials) and allow_origin.strip() == "*":
        findings.append(add_finding(
            "HIGH",
            "Potentially unsafe CORS configuration",
            "Access-Control-Allow-Credentials is enabled together with a wildcard origin.",
            recommendation="Avoid combining wildcard origins with credentialed cross-origin requests.",
            evidence=_header_evidence(response, method),
            module=MODULE_NAME,
            target=target
        ))

    return findings


def _header_evidence(response, method):
    evidence_parts = [
        f"method: {method}",
        f"endpoint: {ENDPOINT}",
        f"status_code: {response.status_code}",
    ]

    for header_name in (
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Credentials",
        "Vary",
    ):
        header_value = response.headers.get(header_name)
        if header_value:
            evidence_parts.append(f"{header_name}: {header_value}")

    return ", ".join(evidence_parts)


def _is_true(value):
    return isinstance(value, str) and value.strip().lower() == "true"
