from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request


MODULE_NAME = "fingerprint_scanner"


def scan_fingerprint(target):
    findings = []
    signals = []

    print("\n[+] Fingerprinting target...")

    health_response = safe_request("GET", target, "/v1/sys/health")
    if isinstance(health_response, Response):
        try:
            data = health_response.json()
        except ValueError:
            data = {}

        vault_fields = {
            "initialized",
            "sealed",
            "standby",
            "performance_standby",
            "replication_performance_mode",
            "replication_dr_mode",
            "cluster_name",
            "cluster_id",
            "version",
        }
        matched_fields = sorted(vault_fields.intersection(data.keys()))

        if matched_fields:
            signals.append("Vault-like /v1/sys/health JSON fields: " + ", ".join(matched_fields))

        if health_response.headers.get("X-Vault-Index"):
            signals.append("X-Vault-Index response header present")

    mounts_response = safe_request("GET", target, "/v1/sys/internal/ui/mounts")
    if isinstance(mounts_response, Response):
        if mounts_response.status_code in (200, 403):
            signals.append(
                f"Vault UI internal mounts endpoint returned HTTP {mounts_response.status_code}"
            )
        try:
            mounts_data = mounts_response.json()
            if "errors" in mounts_data or "data" in mounts_data:
                signals.append("Vault-style JSON body from UI internal mounts endpoint")
        except ValueError:
            pass

    ui_response = safe_request("GET", target, "/ui/", allow_redirects=False)
    if isinstance(ui_response, Response):
        location = ui_response.headers.get("Location", "")
        if ui_response.status_code in (200, 301, 302, 307, 308) and "/ui" in location.lower():
            signals.append(f"Vault UI redirect behavior observed: {location}")
        elif ui_response.status_code == 200 and "vault" in ui_response.text[:2000].lower():
            signals.append("Vault UI content marker observed")

    if signals:
        print("[+] Vault fingerprint signals found.")
        for signal in signals:
            print(f"    - {signal}")

        findings.append(add_finding(
            "INFO",
            "Target appears to be HashiCorp Vault",
            "The target returned one or more Vault-specific fingerprint signals.",
            recommendation="Continue with safe Vault-specific reconnaissance and validate exposure boundaries.",
            evidence="; ".join(signals),
            module=MODULE_NAME,
            target=target
        ))
    else:
        print("[-] No strong Vault fingerprint signals found.")
        findings.append(add_finding(
            "INFO",
            "Vault fingerprint not confirmed",
            "The scanner did not observe strong unauthenticated Vault fingerprint signals.",
            recommendation="Verify the target URL, reverse proxy path, and network access before deeper testing.",
            evidence="No curated Vault fingerprint signals matched.",
            module=MODULE_NAME,
            target=target
        ))

    return findings

