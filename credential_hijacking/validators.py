from core.report import add_finding
from credential_hijacking.file_secret_scanner import mask_value
from credential_hijacking.impact_analyzer import analyze_token_metadata
from scanners.capability_scanner import audit_token_capabilities


MODULE_NAME = "hijack_validator"
TIMEOUT = 5


def validate_discovered_tokens(matches, vault_addr):
    if not vault_addr:
        add_finding(
            "INFO",
            "Token validation skipped",
            "Token validation was requested but no Vault target was provided.",
            recommendation="Provide --target with the authorized Vault address when using --validate-token.",
            evidence="missing target",
            module=MODULE_NAME,
            target="token-validation",
        )
        return

    for match in _token_matches(matches):
        token = match["value"]
        masked_token = mask_value(token)
        response = _request(
            "GET",
            _url(vault_addr, "/v1/auth/token/lookup-self"),
            headers={"X-Vault-Token": token},
        )

        evidence = f"file: {match['file']}, token: {masked_token}"
        if response is None:
            add_finding(
                "INFO",
                "Vault token validation inconclusive",
                "The scanner could not validate a discovered Vault token due to a request error.",
                recommendation="Confirm network reachability and repeat validation in an authorized environment.",
                evidence=evidence,
                module=MODULE_NAME,
                target=vault_addr,
            )
            continue

        if response.status_code == 200:
            add_finding(
                "HIGH",
                "Discovered Vault token is valid",
                "A discovered Vault token was accepted by the token lookup endpoint.",
                recommendation="Revoke or rotate the exposed token and investigate possible unauthorized disclosure.",
                evidence=f"{evidence}, status_code: 200",
                module=MODULE_NAME,
                target=vault_addr,
            )
            try:
                analyze_token_metadata(response.json(), vault_addr, evidence)
            except ValueError:
                pass
        elif response.status_code in (400, 403):
            add_finding(
                "INFO",
                "Discovered Vault token was not accepted",
                "A discovered Vault token was rejected by the token lookup endpoint.",
                recommendation="Keep the evidence for exposure review and confirm whether the token was already revoked or expired.",
                evidence=f"{evidence}, status_code: {response.status_code}",
                module=MODULE_NAME,
                target=vault_addr,
            )


def validate_discovered_approles(matches, vault_addr):
    if not vault_addr:
        add_finding(
            "INFO",
            "AppRole validation skipped",
            "AppRole validation was requested but no Vault target was provided.",
            recommendation="Provide --target with the authorized Vault address when using --validate-approle.",
            evidence="missing target",
            module=MODULE_NAME,
            target="approle-validation",
        )
        return

    for pair in _approle_pairs(matches):
        role_id = pair["role_id"]["value"]
        secret_id = pair["secret_id"]["value"]
        evidence = (
            f"file: {pair['file']}, role_id: {mask_value(role_id)}, "
            f"secret_id: {mask_value(secret_id)}"
        )
        response = _request(
            "POST",
            _url(vault_addr, "/v1/auth/approle/login"),
            json={"role_id": role_id, "secret_id": secret_id},
        )

        if response is None:
            add_finding(
                "INFO",
                "AppRole validation inconclusive",
                "The scanner could not validate discovered AppRole material due to a request error.",
                recommendation="Confirm network reachability and repeat validation in an authorized environment.",
                evidence=evidence,
                module=MODULE_NAME,
                target=vault_addr,
            )
            continue

        if response.status_code == 200:
            add_finding(
                "HIGH",
                "Discovered AppRole credentials are valid",
                "Discovered Role ID and Secret ID were accepted by the AppRole login endpoint.",
                recommendation="Rotate the exposed Secret ID and review AppRole policies, TTL, and binding constraints.",
                evidence=f"{evidence}, status_code: 200",
                module=MODULE_NAME,
                target=vault_addr,
            )
            _analyze_approle_login_response(response, vault_addr, evidence)
        elif response.status_code in (400, 403):
            add_finding(
                "INFO",
                "Discovered AppRole credentials were not accepted",
                "Discovered AppRole material was rejected by the AppRole login endpoint.",
                recommendation="Keep the exposure finding for review and confirm whether Secret ID rotation already occurred.",
                evidence=f"{evidence}, status_code: {response.status_code}",
                module=MODULE_NAME,
                target=vault_addr,
            )


def validate_approle_credentials(
    role_id,
    secret_id,
    vault_addr,
    mount_point="approle",
    capability_paths=None,
    namespace=None,
):
    if not vault_addr:
        add_finding(
            "INFO",
            "AppRole validation skipped",
            "AppRole validation was requested but no Vault target was provided.",
            recommendation="Provide --target with the authorized Vault address when validating AppRole material.",
            evidence="missing target",
            module=MODULE_NAME,
            target="approle-validation",
        )
        return None

    if not role_id or not secret_id:
        add_finding(
            "INFO",
            "AppRole validation skipped",
            "AppRole validation requires both role_id and secret_id.",
            recommendation="Provide both --role-id and --secret-id for authorized AppRole validation.",
            evidence="missing role_id or secret_id",
            module=MODULE_NAME,
            target=vault_addr,
        )
        return None

    evidence = (
        f"mount: {mount_point}, role_id: {mask_value(role_id)}, "
        f"secret_id: {mask_value(secret_id)}"
    )

    try:
        import hvac
    except ImportError:
        add_finding(
            "LOW",
            "AppRole validation dependency missing",
            "The hvac Python package is required to validate AppRole credentials.",
            recommendation="Install project dependencies with pip install -r requirements.txt.",
            evidence="missing package: hvac",
            module=MODULE_NAME,
            target=vault_addr,
        )
        return None

    try:
        client = hvac.Client(
            url=vault_addr.rstrip("/"),
            namespace=namespace,
            timeout=TIMEOUT,
        )
        response = client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id,
            use_token=False,
            mount_point=mount_point,
        )
    except Exception as error:
        add_finding(
            "INFO",
            "AppRole validation inconclusive",
            "The scanner could not validate supplied AppRole material due to a request or authentication error.",
            recommendation="Confirm the Vault address, AppRole mount path, namespace, and credential validity.",
            evidence=f"{evidence}, error: {error}",
            module=MODULE_NAME,
            target=vault_addr,
        )
        return None

    auth = response.get("auth", {}) if isinstance(response, dict) else {}
    client_token = auth.get("client_token")

    if not client_token:
        add_finding(
            "INFO",
            "AppRole login returned no client token",
            "The AppRole login response did not include a client token to analyze.",
            recommendation="Review the AppRole auth response and Vault audit logs in the authorized environment.",
            evidence=evidence,
            module=MODULE_NAME,
            target=vault_addr,
        )
        return response

    add_finding(
        "HIGH",
        "Supplied AppRole credentials are valid",
        "The supplied Role ID and Secret ID were accepted by the AppRole login endpoint.",
        recommendation="Rotate the Secret ID if it was exposed and review AppRole token policies, TTL, and binding constraints.",
        evidence=evidence,
        module=MODULE_NAME,
        target=vault_addr,
    )

    _analyze_approle_auth(auth, vault_addr, evidence)
    audit_token_capabilities(
        vault_addr,
        client_token,
        paths=capability_paths,
        namespace=namespace,
    )
    return response


def _analyze_approle_login_response(response, vault_addr, evidence):
    try:
        auth = response.json().get("auth", {})
    except ValueError:
        return

    _analyze_approle_auth(auth, vault_addr, evidence)


def _analyze_approle_auth(auth, vault_addr, evidence):
    token_data = {
        "data": {
            "policies": auth.get("policies") or [],
            "ttl": auth.get("lease_duration"),
            "renewable": auth.get("renewable"),
        }
    }
    analyze_token_metadata(token_data, vault_addr, evidence)


def _token_matches(matches):
    seen = set()
    for match in matches:
        if match["pattern"] not in ("vault_token_value", "vault_token_assignment"):
            continue
        if not match.get("material", True):
            continue
        if match["value"] in seen:
            continue
        seen.add(match["value"])
        yield match


def _approle_pairs(matches):
    by_file = {}
    for match in matches:
        by_file.setdefault(match["file"], []).append(match)

    for file_path, file_matches in by_file.items():
        role_ids = [
            m for m in file_matches
            if m["pattern"] == "vault_role_id" and m.get("material", True)
        ]
        secret_ids = [
            m for m in file_matches
            if m["pattern"] == "vault_secret_id" and m.get("material", True)
        ]

        for role_id in role_ids:
            for secret_id in secret_ids:
                yield {
                    "file": file_path,
                    "role_id": role_id,
                    "secret_id": secret_id,
                }


def _request(method, url, **kwargs):
    try:
        import requests
    except ImportError:
        return None

    try:
        return requests.request(method, url, timeout=TIMEOUT, **kwargs)
    except requests.exceptions.RequestException:
        return None


def _url(vault_addr, path):
    return vault_addr.rstrip("/") + path
