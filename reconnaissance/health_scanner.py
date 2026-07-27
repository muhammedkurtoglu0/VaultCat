from requests import Response
from core.report import add_finding
from core.tls_config import get_verify
from reconnaissance.http_utils import safe_request


MODULE_NAME = "health_scanner"


def scan_health(target, context=None):
    findings = []
    print("\n[+] Scanning Vault health endpoint...")

    if context:
        response = context.fetch_health_once()
    else:
        response = safe_request("GET", target, "/v1/sys/health")

    if not isinstance(response, Response):
        print(f"[-] Could not connect to health endpoint: {response}")
        findings.append(add_finding(
            "HIGH",
            "Vault health endpoint unreachable",
            "The target did not respond to /v1/sys/health.",
            recommendation="Confirm the target URL, network route, and whether Vault is externally reachable.",
            evidence=str(response),
            module=MODULE_NAME,
            target=target
        ))
        return findings

    print(f"Status Code : {response.status_code}")

    try:
        data = response.json()
        print(f"Response    : {data}")
    except ValueError:
        print("[-] Response is not JSON.")
        findings.append(add_finding(
            "LOW",
            "Unexpected health response",
            "The health endpoint did not return JSON.",
            recommendation="Verify whether the target is HashiCorp Vault or a proxy returning a custom response.",
            evidence=f"status_code: {response.status_code}",
            module=MODULE_NAME,
            target=target
        ))
        return findings

    initialized = data.get("initialized")
    sealed = data.get("sealed")
    standby = data.get("standby")
    performance_standby = data.get("performance_standby")
    replication_performance_mode = data.get("replication_performance_mode")
    replication_dr_mode = data.get("replication_dr_mode")
    version = data.get("version")
    cluster_name = data.get("cluster_name")
    cluster_id = data.get("cluster_id")

    print("\n[+] Vault Health")
    print(f"Initialized  : {initialized}")
    print(f"Sealed       : {sealed}")
    print(f"Standby      : {standby}")
    print(f"Perf Standby : {performance_standby}")
    print(f"Perf Repl    : {replication_performance_mode}")
    print(f"DR Repl      : {replication_dr_mode}")
    print(f"Version      : {version}")
    print(f"Cluster Name : {cluster_name}")
    print(f"Cluster ID   : {cluster_id}")

    findings.append(add_finding(
        "INFO",
        "Vault health endpoint exposed",
        "/v1/sys/health is reachable without authentication.",
        recommendation="Review whether exposing this endpoint externally is intended for the deployment.",
        evidence=f"status_code: {response.status_code}",
        module=MODULE_NAME,
        target=target
    ))

    if version:
        findings.append(add_finding(
            "LOW",
            "Vault version disclosed",
            "The health endpoint disclosed the Vault version.",
            recommendation="Avoid exposing unnecessary version information to unauthenticated users.",
            evidence=f"version: {version}",
            module=MODULE_NAME,
            target=target
        ))

    if cluster_name:
        findings.append(add_finding(
            "LOW",
            "Vault cluster name disclosed",
            "The health endpoint disclosed the Vault cluster name.",
            recommendation="Avoid exposing internal cluster identifiers to unauthenticated users.",
            evidence=f"cluster_name: {cluster_name}",
            module=MODULE_NAME,
            target=target
        ))

    if cluster_id:
        findings.append(add_finding(
            "LOW",
            "Vault cluster ID disclosed",
            "The health endpoint disclosed the Vault cluster ID.",
            recommendation="Avoid exposing internal cluster identifiers to unauthenticated users.",
            evidence=f"cluster_id: {cluster_id}",
            module=MODULE_NAME,
            target=target
        ))

    if initialized is False:
        findings.append(add_finding(
            "CRITICAL",
            "Vault is not initialized",
            "An exposed uninitialized Vault may allow takeover by the first party that initializes it.",
            recommendation="Immediately restrict network access and initialize Vault through an authorized administrative process.",
            evidence="initialized: false",
            module=MODULE_NAME,
            target=target
        ))

    if replication_performance_mode or replication_dr_mode:
        findings.append(add_finding(
            "INFO",
            "Vault replication status disclosed",
            "The health endpoint disclosed Vault replication status information.",
            recommendation="Review whether exposing replication topology hints externally is intended.",
            evidence=(
                f"replication_performance_mode: {replication_performance_mode}, "
                f"replication_dr_mode: {replication_dr_mode}"
            ),
            module=MODULE_NAME,
            target=target
        ))

    return findings
