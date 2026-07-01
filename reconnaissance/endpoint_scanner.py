from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "endpoint_scanner"

ENDPOINTS = (
    ("/v1/sys/health", "Vault health endpoint"),
    ("/v1/sys/seal-status", "Vault seal status endpoint"),
    ("/v1/sys/internal/ui/mounts", "Vault UI mounts endpoint"),
    ("/ui/", "Vault UI route"),
)


def scan_endpoints(target):
    findings = []

    print("\n[+] Probing curated unauthenticated Vault endpoints...")

    for path, label in ENDPOINTS:
        response = safe_request("GET", target, path, allow_redirects=False)

        if not isinstance(response, Response):
            findings.append(add_finding(
                "INFO",
                f"{label} unavailable",
                f"The scanner could not reach {path}.",
                recommendation="Confirm target reachability if this endpoint is expected to be exposed.",
                evidence=str(response),
                module=MODULE_NAME,
                target=target
            ))
            continue

        evidence_parts = [f"path: {path}", f"status_code: {response.status_code}"]
        location = response.headers.get("Location")
        if location:
            evidence_parts.append(f"location: {location}")

        print(f"{path} -> HTTP {response.status_code}")

        severity = "INFO"
        title = f"Endpoint status: {path}"
        description = f"The curated endpoint probe received HTTP {response.status_code}."
        recommendation = "Use this endpoint status as supporting evidence for attack surface mapping."

        if response.status_code in (401, 403, 404):
            severity = "PASS"
            description = "The endpoint did not return openly accessible data to an unauthenticated request."
            recommendation = "No action required for this endpoint based on this status probe."

        findings.append(add_finding(
            severity,
            title,
            description,
            recommendation=recommendation,
            evidence=", ".join(evidence_parts),
            module=MODULE_NAME,
            target=target
        ))

    return findings
