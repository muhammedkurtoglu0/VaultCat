import re

from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request
from core.logger import logger


MODULE_NAME = "version_risk_scanner"
MIN_RECOMMENDED_VERSION = "1.15.0"
# Vault has never shipped a 2.x release — every real deployment reports 1.x.
# A higher major version means the health endpoint is lying (mock, honeypot,
# or a non-Vault service imitating the Vault API).
LATEST_KNOWN_MAJOR_VERSION = 1
VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
RECOMMENDATION = (
    "Review the detected Vault version against HashiCorp security advisories and upgrade policy."
)


def scan_version_risk(target, context=None):
    findings = []

    logger.info("\n[+] Assessing Vault version risk...")

    response = context.fetch_health_once() if context else safe_request("GET", target, "/v1/sys/health")
    if not isinstance(response, Response):
        return findings

    try:
        data = response.json()
    except ValueError:
        return findings

    version = data.get("version")
    if not version:
        return findings

    enterprise = data.get("enterprise")
    evidence = _build_evidence(version, enterprise)
    parsed_version = _parse_version(version)

    if parsed_version is None:
        findings.append(add_finding(
            "LOW",
            "Vault version format could not be parsed",
            "The health endpoint returned a Vault version string that the scanner could not parse for baseline comparison.",
            recommendation=RECOMMENDATION,
            evidence=evidence,
            module=MODULE_NAME,
            target=target
        ))
        return findings

    findings.append(add_finding(
        "INFO",
        "Vault version identified",
        "The scanner identified a parseable Vault version for baseline risk review.",
        recommendation=RECOMMENDATION,
        evidence=evidence,
        module=MODULE_NAME,
        target=target
    ))

    if parsed_version[0] > LATEST_KNOWN_MAJOR_VERSION:
        findings.append(add_finding(
            "HIGH",
            "Vault reports an impossible version — possible fake or honeypot",
            "The health endpoint reports a Vault major version that has never "
            "been released (Vault has only shipped 1.x). This target is likely "
            "a mock, honeypot, or a non-Vault service imitating the Vault API. "
            "Treat all other signals from this target with suspicion.",
            recommendation="Verify the target's identity out-of-band before trusting any response from it.",
            evidence=evidence,
            module=MODULE_NAME,
            target=target
        ))

    baseline_version = _parse_version(MIN_RECOMMENDED_VERSION)
    if baseline_version and parsed_version < baseline_version:
        findings.append(add_finding(
            "MEDIUM",
            "Vault version below recommended baseline",
            "The detected Vault version is below the scanner's configured minimum recommended baseline.",
            recommendation=RECOMMENDATION,
            evidence=f"{evidence}, minimum_recommended_version: {MIN_RECOMMENDED_VERSION}",
            module=MODULE_NAME,
            target=target
        ))

    return findings


def _parse_version(version):
    if not isinstance(version, str):
        return None

    match = VERSION_PATTERN.match(version.strip())
    if not match:
        return None

    return tuple(int(part) for part in match.groups())


def _build_evidence(version, enterprise):
    evidence_parts = [
        "endpoint: /v1/sys/health",
        f"version: {version}",
    ]

    if enterprise is not None:
        evidence_parts.append(f"enterprise: {enterprise}")

    return ", ".join(evidence_parts)
