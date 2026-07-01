from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "ui_scanner"


def scan_ui(target):
    findings = []
    ui_reachable = False

    print("\n[+] Checking Vault UI exposure...")

    for path in ("/ui/", "/ui"):
        response = safe_request("GET", target, path, allow_redirects=False)

        if not isinstance(response, Response):
            print(f"[-] {path} request failed: {response}")
            continue

        location = response.headers.get("Location")
        evidence = f"path: {path}, status_code: {response.status_code}"
        if location:
            evidence += f", location: {location}"

        print(f"{path} -> HTTP {response.status_code}")

        if response.status_code == 200:
            ui_reachable = True
            findings.append(add_finding(
                "LOW",
                "Vault UI externally reachable",
                "The Vault web UI is reachable without prior authentication.",
                recommendation="Confirm that exposing the Vault UI to this network is intended and protected by access controls.",
                evidence=evidence,
                module=MODULE_NAME,
                target=target
            ))
            break

        if response.status_code in (301, 302, 307, 308):
            ui_reachable = True
            findings.append(add_finding(
                "INFO",
                "Vault UI redirect observed",
                "The target redirects requests for the Vault UI path.",
                recommendation="Review whether the UI route should be externally discoverable.",
                evidence=evidence,
                module=MODULE_NAME,
                target=target
            ))
            break

    login_response = safe_request("GET", target, "/ui/vault/auth", allow_redirects=False)
    if isinstance(login_response, Response):
        print(f"/ui/vault/auth -> HTTP {login_response.status_code}")
        if login_response.status_code == 200:
            findings.append(add_finding(
                "INFO",
                "Vault login UI reachable",
                "The Vault login UI is reachable without authentication.",
                recommendation="Confirm that exposing the Vault login UI to this network is intended.",
                evidence="path: /ui/vault/auth, status_code: 200",
                module=MODULE_NAME,
                target=target
            ))

    if not ui_reachable and not findings:
        findings.append(add_finding(
            "PASS",
            "Vault UI not directly exposed",
            "The scanner did not observe a directly reachable Vault UI at /ui or /ui/.",
            recommendation="Keep UI exposure limited to trusted networks where possible.",
            evidence="Checked /ui and /ui/.",
            module=MODULE_NAME,
            target=target
        ))

    return findings
