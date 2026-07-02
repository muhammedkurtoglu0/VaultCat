from collections import defaultdict

from core.report import add_finding


MODULE_NAME = "hijack_analyzer"


def analyze_hijack_findings(matches):
    grouped_matches = defaultdict(list)

    for match in matches:
        grouped_matches[match["file"]].append(match)

    for file_path, file_matches in grouped_matches.items():
        patterns = {match["pattern"] for match in file_matches}
        material_patterns = {
            match["pattern"]
            for match in file_matches
            if match.get("material", True)
        }

        has_role_id = "vault_role_id" in material_patterns
        has_secret_id = "vault_secret_id" in material_patterns
        has_token = bool({
            "vault_response_wrapped_token",
            "vault_token_value",
            "vault_token_assignment",
        } & material_patterns)
        has_addr = bool({"vault_addr_assignment", "vault_8200_url"} & patterns)
        has_approle_flow = bool({
            "approle_login",
            "approle_cli_login",
            "approle_role_id_path",
            "approle_secret_id_path",
        } & patterns)
        has_aws_login = "aws_iam_login" in patterns
        has_aws_flow = bool({
            "aws_iam_login",
            "aws_cli_login",
            "aws_auth_role_config",
            "vault_aws_auth_reference",
            "aws_bound_iam_principal",
            "vault_aws_iam_server_id",
        } & patterns)
        has_aws_key = "aws_access_key_id" in material_patterns
        has_aws_secret = "aws_secret_access_key" in material_patterns
        has_aws_session = "aws_session_token" in material_patterns
        has_aws_role = "aws_role_arn" in patterns
        has_database_dynamic_creds = "vault_database_creds_path" in patterns
        has_database_config = "vault_database_config_path" in patterns
        has_database_role = "vault_database_role_path" in patterns
        has_database_plugin = "vault_database_plugin" in patterns
        has_database_connection = "vault_database_connection_url" in patterns
        has_database_creation = "vault_database_creation_statements" in patterns
        has_database_revocation = "vault_database_revocation_statements" in patterns
        has_database_static_user = "database_static_username" in material_patterns
        has_database_static_password = "database_static_password" in material_patterns
        has_dynamic_db_username = "dynamic_database_username" in patterns
        has_database_destructive_sql = "vault_database_destructive_statement" in patterns
        has_database_admin_policy_path = "vault_policy_database_role_admin_path" in patterns
        has_policy_write_capability = "vault_policy_write_capabilities" in patterns

        if has_role_id and has_secret_id:
            add_finding(
                "HIGH",
                "AppRole credential pair discovered",
                "Role ID and Secret ID appear to be present in the same file.",
                recommendation="Treat this as a potential Vault authentication path and rotate exposed AppRole Secret IDs.",
                evidence=f"file: {file_path}, role_id: present, secret_id: present",
                module=MODULE_NAME,
                target=file_path,
            )
        elif has_role_id:
            add_finding(
                "MEDIUM",
                "AppRole Role ID discovered without Secret ID",
                "A Role ID appears to be present without a matching Secret ID in the same file.",
                recommendation="Confirm whether the Role ID is intended to be public and search related artifacts for paired Secret IDs.",
                evidence=f"file: {file_path}, role_id: present",
                module=MODULE_NAME,
                target=file_path,
            )
        elif has_secret_id:
            add_finding(
                "HIGH",
                "AppRole Secret ID discovered without Role ID",
                "A Secret ID appears to be present without a matching Role ID in the same file.",
                recommendation="Rotate the exposed Secret ID and search related artifacts for the corresponding Role ID.",
                evidence=f"file: {file_path}, secret_id: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_addr and has_token:
            add_finding(
                "HIGH",
                "Vault address and token discovered together",
                "A Vault address and token-like value appear to be present in the same file.",
                recommendation="Rotate exposed tokens and review whether the discovered address is reachable from attacker-controlled networks.",
                evidence=f"file: {file_path}, vault_addr: present, token: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_approle_flow:
            add_finding(
                "INFO",
                "AppRole login flow reference observed",
                "The file references AppRole authentication, Role ID retrieval, or Secret ID generation flow.",
                recommendation="Use this as context when investigating discovered AppRole credential material.",
                evidence=f"file: {file_path}, approle_flow_reference: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_aws_login:
            add_finding(
                "INFO",
                "AWS IAM Vault login flow reference observed",
                "The file references the Vault AWS auth login endpoint.",
                recommendation="Use this as context when investigating AWS IAM based Vault authentication exposure.",
                evidence=f"file: {file_path}, endpoint: auth/aws/login",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_aws_key and has_aws_secret:
            add_finding(
                "HIGH",
                "AWS credential pair discovered",
                "AWS access key ID and secret access key appear to be present in the same file.",
                recommendation="Rotate exposed AWS credentials and review whether they can authenticate to Vault AWS auth.",
                evidence=f"file: {file_path}, aws_access_key_id: present, aws_secret_access_key: present",
                module=MODULE_NAME,
                target=file_path,
            )
        elif has_aws_secret:
            add_finding(
                "HIGH",
                "AWS secret access key discovered without access key ID",
                "An AWS secret access key appears to be present without a matching access key ID in the same file.",
                recommendation="Rotate exposed AWS credentials and search related artifacts for paired access key IDs.",
                evidence=f"file: {file_path}, aws_secret_access_key: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_aws_flow and (has_aws_key or has_aws_secret or has_aws_session or has_aws_role):
            add_finding(
                "HIGH",
                "Vault AWS IAM authentication chain material discovered",
                "Vault AWS auth references and AWS credential or role material appear in the same file.",
                recommendation="Review whether this artifact can be used to authenticate to Vault via AWS IAM auth.",
                evidence=(
                    f"file: {file_path}, aws_auth_reference: present, "
                    f"aws_credential_or_role_material: present"
                ),
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_config and has_database_static_password:
            add_finding(
                "HIGH",
                "Vault database configuration and static DB password discovered together",
                "Vault database configuration references and a static database password appear in the same file.",
                recommendation="Rotate the static database credential and ensure Vault database plugin users are least-privileged.",
                evidence=f"file: {file_path}, database_config: present, static_db_password: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_static_user and has_database_static_password:
            add_finding(
                "HIGH",
                "Static database credential pair discovered",
                "A database username and password appear to be present in the same file.",
                recommendation="Rotate exposed database credentials and assess whether they can administer Vault dynamic database roles.",
                evidence=f"file: {file_path}, db_username: present, db_password: present",
                module=MODULE_NAME,
                target=file_path,
            )
        elif has_database_static_password:
            add_finding(
                "HIGH",
                "Static database password discovered without username",
                "A database password appears to be present without a matching username in the same file.",
                recommendation="Rotate the exposed database password and search related artifacts for the corresponding username and host.",
                evidence=f"file: {file_path}, db_password: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_dynamic_creds:
            add_finding(
                "INFO",
                "Vault dynamic database credential generation path observed",
                "The file references a Vault database credentials endpoint that can generate short-lived database users when authorized.",
                recommendation="Confirm policies restrict access to required roles and review TTL/max TTL for generated users.",
                evidence=f"file: {file_path}, endpoint: database/creds/*",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_role and has_database_creation:
            add_finding(
                "LOW",
                "Vault dynamic database role definition observed",
                "The file references a Vault database role and its creation statements.",
                recommendation="Review creation statements for least-privilege grants and avoid broad database privileges.",
                evidence=f"file: {file_path}, database_role: present, creation_statements: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_role and has_database_destructive_sql:
            add_finding(
                "HIGH",
                "Destructive SQL observed in Vault database role template",
                "A Vault database role template appears to include destructive or high-risk SQL that would run when credentials are generated.",
                recommendation="Remove destructive SQL from database role templates and restrict role update permissions to trusted administrators.",
                evidence=f"file: {file_path}, database_role: present, destructive_sql: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_admin_policy_path and has_policy_write_capability:
            add_finding(
                "HIGH",
                "Vault policy can modify database role or config definitions",
                "A Vault policy appears to grant write-level capability on database role, static role, or connection configuration paths.",
                recommendation="Restrict create, update, delete, and sudo on database/roles, database/static-roles, and database/config paths to tightly controlled administrators.",
                evidence=f"file: {file_path}, database_admin_path: present, write_capability: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_admin_policy_path and has_database_destructive_sql:
            add_finding(
                "HIGH",
                "Database role tampering scenario observed in artifacts",
                "Artifacts include both database role administration context and destructive SQL indicators.",
                recommendation="Review whether any token or policy can update the affected database role templates and enforce change control.",
                evidence=f"file: {file_path}, database_admin_path: present, destructive_sql: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if has_database_creation and not has_database_revocation:
            add_finding(
                "LOW",
                "Vault database creation statement without visible revocation statement",
                "A database credential creation statement was observed without a nearby revocation statement in the same file.",
                recommendation="Confirm Vault can reliably revoke or expire generated database users for this role.",
                evidence=f"file: {file_path}, creation_statements: present, revocation_statements: not observed",
                module=MODULE_NAME,
                target=file_path,
            )

        for ttl_match in _ttl_matches(file_matches):
            seconds = _duration_to_seconds(ttl_match["value"])
            if seconds and seconds > 3600:
                add_finding(
                    "LOW",
                    "Vault database dynamic credential TTL exceeds one hour",
                    "A Vault database role TTL longer than one hour was observed.",
                    recommendation="Prefer short TTLs for dynamic database users and align max TTL with operational need.",
                    evidence=(
                        f"file: {file_path}, pattern: {ttl_match['pattern']}, "
                        f"ttl: {ttl_match['masked_value']}"
                    ),
                    module=MODULE_NAME,
                    target=file_path,
                )

        if has_dynamic_db_username:
            add_finding(
                "INFO",
                "Vault dynamic database username appears in artifact",
                "A username resembling a Vault-generated dynamic database user was observed in an artifact.",
                recommendation="Avoid logging generated database credentials; verify generated passwords are not stored nearby.",
                evidence=f"file: {file_path}, dynamic_db_username: present",
                module=MODULE_NAME,
                target=file_path,
            )

        if (has_database_plugin or has_database_connection or has_database_config) and (
            has_database_role or has_database_dynamic_creds
        ):
            add_finding(
                "INFO",
                "Vault database secrets engine integration observed",
                "Database secrets engine configuration and role or credentials references appear in the same file.",
                recommendation="Review database plugin user privilege, TTLs, revocation behavior, and policy access to database/creds paths.",
                evidence=f"file: {file_path}, database_config_or_plugin: present, dynamic_role_or_creds: present",
                module=MODULE_NAME,
                target=file_path,
            )

    _analyze_cross_file_chains(matches)


def _analyze_cross_file_chains(matches):
    patterns = {match["pattern"] for match in matches}
    material_patterns = {
        match["pattern"]
        for match in matches
        if match.get("material", True)
    }

    has_vault_addr = bool({"vault_addr_assignment", "vault_8200_url"} & patterns)
    has_approle_pair = (
        "vault_role_id" in material_patterns
        and "vault_secret_id" in material_patterns
    )
    has_aws_auth = bool({
        "aws_iam_login",
        "aws_cli_login",
        "aws_auth_role_config",
        "vault_aws_auth_reference",
        "vault_aws_iam_server_id",
        "aws_bound_iam_principal",
    } & patterns)
    has_aws_material = bool({
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
    } & material_patterns) or "aws_role_arn" in patterns
    has_database_context = bool({
        "vault_database_config_path",
        "vault_database_role_path",
        "vault_database_creds_path",
        "vault_database_plugin",
        "vault_database_connection_url",
    } & patterns)
    has_database_static_password = "database_static_password" in material_patterns
    has_database_static_user = "database_static_username" in material_patterns
    has_database_destructive_sql = "vault_database_destructive_statement" in patterns
    has_database_admin_policy_path = "vault_policy_database_role_admin_path" in patterns
    has_policy_write_capability = "vault_policy_write_capabilities" in patterns

    if has_vault_addr and has_approle_pair:
        add_finding(
            "HIGH",
            "Cross-file AppRole Vault access chain discovered",
            "Vault address, AppRole Role ID, and AppRole Secret ID were discovered within the scanned scope.",
            recommendation="Treat this as a potential Vault authentication chain and rotate exposed Secret IDs.",
            evidence="scope: scanned path, vault_addr: present, role_id: present, secret_id: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )

    if has_vault_addr and has_aws_auth and has_aws_material:
        add_finding(
            "HIGH",
            "Cross-file AWS IAM Vault access chain discovered",
            "Vault address, AWS IAM Vault auth references, and AWS credential or role material were discovered within the scanned scope.",
            recommendation="Review whether the discovered AWS material can authenticate to Vault and rotate exposed credentials where needed.",
            evidence="scope: scanned path, vault_addr: present, aws_auth_reference: present, aws_material: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )

    if has_vault_addr and has_database_context and has_database_static_password:
        add_finding(
            "HIGH",
            "Cross-file Vault database access chain discovered",
            "Vault address, database secrets engine references, and static database password material were discovered within the scanned scope.",
            recommendation="Treat this as a potential path to database access or dynamic user generation and rotate exposed database credentials.",
            evidence="scope: scanned path, vault_addr: present, database_context: present, static_db_password: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )

    if has_database_context and has_database_static_user and has_database_static_password:
        add_finding(
            "HIGH",
            "Cross-file static DB credential and Vault database context discovered",
            "Static database credentials and Vault database secrets engine context were discovered within the scanned scope.",
            recommendation="Review whether the static credential is the Vault database plugin user and enforce least privilege.",
            evidence="scope: scanned path, database_context: present, db_username: present, db_password: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )

    if has_database_context and has_database_destructive_sql:
        add_finding(
            "HIGH",
            "Cross-file destructive Vault database role template risk discovered",
            "Database secrets engine context and destructive SQL indicators were discovered within the scanned scope.",
            recommendation="Review database role templates before credential generation and restrict role update permissions.",
            evidence="scope: scanned path, database_context: present, destructive_sql: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )

    if has_database_admin_policy_path and has_policy_write_capability and has_database_context:
        add_finding(
            "HIGH",
            "Cross-file Vault database role tampering path discovered",
            "Vault database role/config context and policy write capabilities were discovered within the scanned scope.",
            recommendation="Confirm that no application or low-trust token can create, update, delete, or sudo Vault database role/config paths.",
            evidence="scope: scanned path, database_context: present, database_admin_path: present, write_capability: present",
            module=MODULE_NAME,
            target="scanned-scope",
        )


def _ttl_matches(file_matches):
    return [
        match for match in file_matches
        if match["pattern"] in ("vault_database_default_ttl", "vault_database_max_ttl")
    ]


def _duration_to_seconds(value):
    if not value:
        return None

    unit = value[-1].lower()
    try:
        amount = int(value[:-1])
    except ValueError:
        return None

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
    }
    return amount * multipliers.get(unit, 0)


def run_hijack_scan(
    path,
    vault_addr=None,
    token=None,
    validate_token=False,
    validate_approle=False,
    validate_db=False,
    include_git_history=True,
    max_file_size_bytes=None,
    excluded_dirs=None,
):
    from credential_hijacking.db_validator import validate_database_secrets_engine
    from credential_hijacking.file_secret_scanner import scan_files
    from credential_hijacking.validators import (
        validate_discovered_approles,
        validate_discovered_tokens,
    )

    matches = scan_files(
        path,
        include_git_history=include_git_history,
        max_file_size_bytes=max_file_size_bytes,
        excluded_dirs=excluded_dirs,
    )
    analyze_hijack_findings(matches)
    if validate_token:
        validate_discovered_tokens(matches, vault_addr)
    if validate_approle:
        validate_discovered_approles(matches, vault_addr)
    if validate_db:
        validate_database_secrets_engine(vault_addr, token)
    return matches
