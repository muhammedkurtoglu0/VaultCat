from core.report import add_finding
from core.tls_config import get_verify


MODULE_NAME = "db_secrets_validator"
TIMEOUT = 5


def validate_database_secrets_engine(vault_addr, token):
    if not vault_addr or not token:
        add_finding(
            "INFO",
            "Database secrets validation skipped",
            "Database secrets validation requires both --target and --token.",
            recommendation="Provide an authorized Vault token when using --validate-db.",
            evidence="missing target or token",
            module=MODULE_NAME,
            target="database-validation",
        )
        return

    mounts = _get_json(vault_addr, token, "/v1/sys/mounts")
    if not mounts:
        add_finding(
            "INFO",
            "Database secrets engine validation inconclusive",
            "The scanner could not read Vault mounts with the provided token.",
            recommendation="Confirm the token has permission to read sys/mounts for assessment purposes.",
            evidence="endpoint: /v1/sys/mounts",
            module=MODULE_NAME,
            target=vault_addr,
        )
        return

    database_mounts = _database_mounts(mounts)
    if not database_mounts:
        add_finding(
            "INFO",
            "No database secrets engine mount visible",
            "No database secrets engine mount was visible to the provided token.",
            recommendation="Confirm whether database secrets engines are expected in this Vault namespace.",
            evidence="endpoint: /v1/sys/mounts, database_mounts: 0",
            module=MODULE_NAME,
            target=vault_addr,
        )
        return

    for mount_path, mount_data in database_mounts.items():
        add_finding(
            "INFO",
            "Database secrets engine mount visible",
            "A database secrets engine mount is visible to the provided token.",
            recommendation="Review who can access credential generation paths under this mount.",
            evidence=f"mount: {mount_path}, type: {mount_data.get('type')}",
            module=MODULE_NAME,
            target=vault_addr,
        )
        _validate_database_mount(vault_addr, token, mount_path)


def _validate_database_mount(vault_addr, token, mount_path):
    base = mount_path.strip("/")
    configs = _list(vault_addr, token, f"/v1/{base}/config")
    roles = _list(vault_addr, token, f"/v1/{base}/roles")
    static_roles = _list(vault_addr, token, f"/v1/{base}/static-roles")

    if configs is not None:
        add_finding(
            "INFO",
            "Database connection configurations listable",
            "The provided token can list database connection names.",
            recommendation="Ensure only administrators can list database connection configuration names.",
            evidence=f"mount: {mount_path}, endpoint: /v1/{base}/config, count: {len(configs)}",
            module=MODULE_NAME,
            target=vault_addr,
        )
        for config_name in configs:
            _inspect_capabilities(
                vault_addr,
                token,
                f"{base}/config/{config_name}",
                "database connection configuration",
            )

    if roles is not None:
        add_finding(
            "LOW",
            "Database dynamic roles listable",
            "The provided token can list database dynamic role names.",
            recommendation="Restrict role listing if role names reveal sensitive application or environment details.",
            evidence=f"mount: {mount_path}, endpoint: /v1/{base}/roles, count: {len(roles)}",
            module=MODULE_NAME,
            target=vault_addr,
        )
        for role_name in roles:
            _inspect_capabilities(
                vault_addr,
                token,
                f"{base}/roles/{role_name}",
                "database dynamic role",
            )
            _inspect_dynamic_role(vault_addr, token, base, role_name)

    if static_roles is not None:
        add_finding(
            "LOW",
            "Database static roles listable",
            "The provided token can list database static role names.",
            recommendation="Restrict static role listing if role names reveal sensitive application or environment details.",
            evidence=f"mount: {mount_path}, endpoint: /v1/{base}/static-roles, count: {len(static_roles)}",
            module=MODULE_NAME,
            target=vault_addr,
        )
        for role_name in static_roles:
            _inspect_capabilities(
                vault_addr,
                token,
                f"{base}/static-roles/{role_name}",
                "database static role",
            )


def _inspect_dynamic_role(vault_addr, token, base, role_name):
    role = _get_json(vault_addr, token, f"/v1/{base}/roles/{role_name}")
    if not role:
        return

    data = role.get("data", {})
    default_ttl = data.get("default_ttl")
    max_ttl = data.get("max_ttl")
    creation_statements = data.get("creation_statements")
    revocation_statements = data.get("revocation_statements")

    add_finding(
        "INFO",
        "Database dynamic role metadata readable",
        "The provided token can read metadata for a database dynamic role.",
        recommendation="Ensure role metadata read access is limited to operators who need it.",
        evidence=f"role: {role_name}, default_ttl: {default_ttl}, max_ttl: {max_ttl}",
        module=MODULE_NAME,
        target=vault_addr,
    )

    for label, value in (("default_ttl", default_ttl), ("max_ttl", max_ttl)):
        seconds = _duration_to_seconds(value)
        if seconds and seconds > 3600:
            add_finding(
                "LOW",
                "Live Vault database role TTL exceeds one hour",
                "A readable Vault database role has a TTL longer than one hour.",
                recommendation="Prefer short TTLs for generated database users and align max TTL with business need.",
                evidence=f"role: {role_name}, {label}: {value}",
                module=MODULE_NAME,
                target=vault_addr,
            )

    statements_text = " ".join(_as_list(creation_statements))
    if _has_broad_database_privilege(statements_text):
        add_finding(
            "MEDIUM",
            "Live Vault database role may grant broad privileges",
            "A readable database role creation statement appears to grant broad database privileges.",
            recommendation="Avoid GRANT ALL, SUPERUSER, CREATEDB, or CREATEROLE for generated database users.",
            evidence=f"role: {role_name}, broad_privilege_pattern: observed",
            module=MODULE_NAME,
            target=vault_addr,
        )

    if creation_statements and not revocation_statements:
        add_finding(
            "LOW",
            "Live Vault database role lacks visible revocation statements",
            "A readable database role has creation statements but no visible revocation statements.",
            recommendation="Confirm revocation behavior is reliable for generated database users.",
            evidence=f"role: {role_name}, creation_statements: present, revocation_statements: not observed",
            module=MODULE_NAME,
            target=vault_addr,
        )


def _inspect_capabilities(vault_addr, token, path, path_type):
    capabilities = _capabilities_self(vault_addr, token, path)
    if capabilities is None:
        return

    dangerous_capabilities = [
        capability
        for capability in capabilities
        if capability in ("create", "update", "delete", "sudo")
    ]
    if not dangerous_capabilities:
        return

    add_finding(
        "HIGH",
        "Token can modify Vault database role or config path",
        "The provided token has write-level capabilities on a Vault database role, static role, or config path.",
        recommendation="Remove create, update, delete, and sudo capabilities from application or low-trust tokens for database role/config paths.",
        evidence=(
            f"path: {path}, type: {path_type}, "
            f"capabilities: {','.join(dangerous_capabilities)}"
        ),
        module=MODULE_NAME,
        target=vault_addr,
    )


def _capabilities_self(vault_addr, token, path):
    response = _request(
        "POST",
        vault_addr,
        token,
        "/v1/sys/capabilities-self",
        json={"paths": [path]},
    )
    if response is None or response.status_code != 200:
        return None

    try:
        data = response.json().get("data", {})
    except ValueError:
        return None

    capabilities = data.get(path)
    if isinstance(capabilities, list):
        return capabilities

    capabilities = data.get("capabilities")
    if isinstance(capabilities, list):
        return capabilities

    return None


def _database_mounts(mounts):
    data = mounts.get("data", mounts)
    return {
        path: mount_data
        for path, mount_data in data.items()
        if isinstance(mount_data, dict) and mount_data.get("type") == "database"
    }


def _list(vault_addr, token, path):
    response = _request("LIST", vault_addr, token, path)
    if response is None or response.status_code in (403, 404):
        return None

    if response.status_code == 405:
        response = _request("GET", vault_addr, token, path.rstrip("/") + "?list=true")
    if response is None or response.status_code != 200:
        return None

    try:
        return response.json().get("data", {}).get("keys", [])
    except ValueError:
        return None


def _get_json(vault_addr, token, path):
    response = _request("GET", vault_addr, token, path)
    if response is None or response.status_code != 200:
        return None

    try:
        return response.json()
    except ValueError:
        return None


def _request(method, vault_addr, token, path, **kwargs):
    try:
        import requests
    except ImportError:
        return None

    headers = {"X-Vault-Token": token}
    url = vault_addr.rstrip("/") + path
    try:
        return requests.request(method, url, headers=headers, timeout=TIMEOUT, verify=get_verify(), **kwargs)
    except requests.exceptions.RequestException:
        return None


def _duration_to_seconds(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value

    text = str(value).strip().lower()
    if text.isdigit():
        return int(text)
    if len(text) < 2:
        return None

    unit = text[-1]
    try:
        amount = int(text[:-1])
    except ValueError:
        return None

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return amount * multipliers.get(unit, 0)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _has_broad_database_privilege(statements):
    lowered = statements.lower()
    broad_terms = (
        "grant all",
        "all privileges",
        " superuser",
        " createdb",
        " createrole",
    )
    return any(term in lowered for term in broad_terms)
