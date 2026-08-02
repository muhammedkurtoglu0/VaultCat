import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

from requests import Response

from core.report import add_finding
from reconnaissance.http_utils import safe_request
from core.logger import logger


MODULE_NAME = "tls_scanner"
TIMEOUT = 5
EXPIRY_WARNING_DAYS = 30


def scan_tls(target):
    findings = []

    logger.info("\n[+] Assessing TLS/HTTPS configuration...")

    parsed_target = urlparse(target)
    scheme = parsed_target.scheme.lower()

    if scheme == "http":
        findings.append(add_finding(
            "HIGH",
            "Vault served over HTTP",
            "The Vault target is reachable over unencrypted HTTP.",
            recommendation="Expose Vault only over HTTPS with properly configured TLS.",
            evidence="scheme: http",
            module=MODULE_NAME,
            target=target
        ))
        return findings

    if scheme != "https":
        return findings

    hostname = parsed_target.hostname
    if not hostname:
        return findings

    port = parsed_target.port or 443
    cert_info = _get_certificate_info(hostname, port)

    if cert_info.get("error"):
        findings.append(add_finding(
            "HIGH",
            "TLS handshake failed",
            "The target uses HTTPS but TLS handshake failed.",
            recommendation="Review TLS listener, certificate and reverse proxy configuration.",
            evidence=cert_info["error"],
            module=MODULE_NAME,
            target=target
        ))
        return findings

    decoded_cert = cert_info["decoded_cert"]
    evidence = _certificate_evidence(decoded_cert)

    findings.append(add_finding(
        "PASS",
        "HTTPS enabled",
        "The target accepted a TLS handshake and presented a certificate.",
        recommendation="Continue to review certificate trust, expiry and protocol policy.",
        evidence=evidence,
        module=MODULE_NAME,
        target=target
    ))

    not_after = _parse_cert_datetime(decoded_cert.get("notAfter"))
    if not_after:
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        if not_after <= now:
            findings.append(add_finding(
                "HIGH",
                "TLS certificate expired",
                "The target presented an expired TLS certificate.",
                recommendation="Renew and deploy a valid TLS certificate.",
                evidence=f"{evidence}, days_remaining: {days_remaining}",
                module=MODULE_NAME,
                target=target
            ))
        elif days_remaining <= EXPIRY_WARNING_DAYS:
            findings.append(add_finding(
                "MEDIUM",
                "TLS certificate expires soon",
                "The target TLS certificate expires within 30 days.",
                recommendation="Renew the TLS certificate before expiration.",
                evidence=f"{evidence}, days_remaining: {days_remaining}",
                module=MODULE_NAME,
                target=target
            ))

    if _appears_self_signed(decoded_cert):
        findings.append(add_finding(
            "MEDIUM",
            "Self-signed TLS certificate detected",
            "The target certificate appears to be self-signed because subject and issuer match.",
            recommendation="Use a certificate issued by a trusted internal or public certificate authority.",
            evidence=evidence,
            module=MODULE_NAME,
            target=target
        ))

    _check_http_redirect(findings, target, parsed_target)

    return findings


def _get_certificate_info(hostname, port):
    context = ssl._create_unverified_context()

    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
                der_cert = tls_socket.getpeercert(binary_form=True)
    except Exception as error:
        return {"error": str(error)}

    cert_path = None
    try:
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as cert_file:
            cert_file.write(pem_cert)
            cert_path = cert_file.name
        decoded_cert = ssl._ssl._test_decode_cert(cert_path)
    except Exception as error:
        return {"error": str(error)}
    finally:
        if cert_path:
            try:
                os.unlink(cert_path)
            except OSError:
                pass

    return {"decoded_cert": decoded_cert}


def _certificate_evidence(decoded_cert):
    evidence_parts = [
        f"subject: {_format_name(decoded_cert.get('subject'))}",
        f"issuer: {_format_name(decoded_cert.get('issuer'))}",
    ]

    not_before = decoded_cert.get("notBefore")
    not_after = decoded_cert.get("notAfter")
    if not_before:
        evidence_parts.append(f"not_before: {not_before}")
    if not_after:
        evidence_parts.append(f"not_after: {not_after}")

    san = _format_san(decoded_cert.get("subjectAltName"))
    if san:
        evidence_parts.append(f"san: {san}")

    return ", ".join(evidence_parts)


def _format_name(name_parts):
    if not name_parts:
        return "unknown"

    formatted_parts = []
    for group in name_parts:
        for key, value in group:
            formatted_parts.append(f"{key}={value}")

    return "/".join(formatted_parts)


def _format_san(subject_alt_names):
    if not subject_alt_names:
        return None

    return "; ".join(f"{name_type}:{name_value}" for name_type, name_value in subject_alt_names)


def _parse_cert_datetime(value):
    if not value:
        return None

    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None

    return parsed.replace(tzinfo=timezone.utc)


def _appears_self_signed(decoded_cert):
    subject = decoded_cert.get("subject")
    issuer = decoded_cert.get("issuer")
    return bool(subject and issuer and subject == issuer)


def _check_http_redirect(findings, target, parsed_target):
    http_target = urlunparse(parsed_target._replace(scheme="http"))
    response = safe_request("GET", http_target, "/", allow_redirects=False)

    if not isinstance(response, Response):
        return

    location = response.headers.get("Location", "")
    if response.status_code in (301, 302, 307, 308) and location.lower().startswith("https://"):
        return

    findings.append(add_finding(
        "LOW",
        "HTTP does not redirect to HTTPS",
        "The HTTP endpoint did not redirect clients to HTTPS.",
        recommendation="Redirect HTTP requests to HTTPS or disable the HTTP listener.",
        evidence=f"http_target: {http_target}, status_code: {response.status_code}",
        module=MODULE_NAME,
        target=target
    ))
