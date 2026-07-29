import re


PATTERNS = {
    "vault_response_wrapped_token": re.compile(
        r"\bhvs\.CAES[A-Za-z0-9._=-]{12,}\b"
    ),
    "vault_token_value": re.compile(r"\b(?:hvs|hvc)\.[A-Za-z0-9._-]{8,}\b"),
    "vault_token_assignment": re.compile(
        r"\b(?:VAULT_TOKEN|vault_token)[ \t]*[:=][ \t]*[\"']?([^\s\"']+)",
        re.IGNORECASE,
    ),
    "vault_role_id": re.compile(
        r"\b(?:VAULT_ROLE_ID|role_id|role-id|roleId)[ \t]*[:=][ \t]*[\"']?([^\s\"',}]+)",
        re.IGNORECASE,
    ),
    "vault_secret_id": re.compile(
        r"\b(?:VAULT_SECRET_ID|secret_id|secret-id|secretId)[ \t]*[:=][ \t]*[\"']?([^\s\"',}]+)",
        re.IGNORECASE,
    ),
    "vault_addr_assignment": re.compile(
        r"\b(?:VAULT_ADDR|vault_addr)[ \t]*[:=][ \t]*[\"']?([^\s\"']+)",
        re.IGNORECASE,
    ),
    "vault_8200_url": re.compile(r"\bhttps?://[^\s\"']+:8200\b", re.IGNORECASE),
    "vault_api_path": re.compile(r"/v1/(?:secret|sys|auth|kv)/[^\s\"']*", re.IGNORECASE),
    "vault_database_creds_path": re.compile(
        r"(?:/v1/)?database/creds/[A-Za-z0-9._/-]+\b",
        re.IGNORECASE,
    ),
    "vault_database_config_path": re.compile(
        r"(?:/v1/)?database/config/[A-Za-z0-9._/-]+\b",
        re.IGNORECASE,
    ),
    "vault_database_role_path": re.compile(
        r"(?:/v1/)?database/(?:roles|static-roles)/[A-Za-z0-9._/-]+\b",
        re.IGNORECASE,
    ),
    "vault_database_plugin": re.compile(
        r"\b(?:postgresql|mysql|mysql-aurora|mysql-rds|mssql|mongodb|redis|"
        r"redshift|snowflake|oracle|cassandra|elasticsearch)-database-plugin\b",
        re.IGNORECASE,
    ),
    "vault_database_connection_url": re.compile(
        r"\b(?:connection_url|connection-url|url|jdbcUrl|jdbc_url)[ \t]*[:=][ \t]*[\"']?"
        r"((?:postgresql|postgres|mysql|mariadb|sqlserver|mongodb|redis|jdbc):[^\s\"']+)",
        re.IGNORECASE,
    ),
    "vault_database_creation_statements": re.compile(
        r"\b(?:creation_statements|creation-statements)[ \t]*[:=][ \t]*[\"']?([^\"'\n\r]+)",
        re.IGNORECASE,
    ),
    "vault_database_broad_privilege_statement": re.compile(
        r"\b(?:GRANT\s+ALL|ALL\s+PRIVILEGES|WITH\s+SUPERUSER|"
        r"\bSUPERUSER\b|\bCREATEDB\b|\bCREATEROLE\b)",
        re.IGNORECASE,
    ),
    "vault_database_destructive_statement": re.compile(
        r"\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE|ROLE|USER)|"
        r"TRUNCATE\s+TABLE|ALTER\s+SYSTEM|COPY\s+.+\s+PROGRAM|"
        r"pg_read_file|pg_write_file|pg_execute_server_program|"
        r"CREATE\s+EXTENSION\s+dblink|dblink_connect|"
        r"GRANT\s+.+(?:pg_read_server_files|pg_write_server_files|"
        r"pg_execute_server_program))\b",
        re.IGNORECASE,
    ),
    "vault_database_revocation_statements": re.compile(
        r"\b(?:revocation_statements|revocation-statements)[ \t]*[:=][ \t]*[\"']?([^\"'\n\r]+)",
        re.IGNORECASE,
    ),
    "vault_database_default_ttl": re.compile(
        r"\bdefault_ttl[ \t]*[:=][ \t]*[\"']?([0-9]+[smhd])",
        re.IGNORECASE,
    ),
    "vault_database_max_ttl": re.compile(
        r"\bmax_ttl[ \t]*[:=][ \t]*[\"']?([0-9]+[smhd])",
        re.IGNORECASE,
    ),
    "database_static_username": re.compile(
        r"\b(?:DB_USERNAME|DATABASE_USERNAME|POSTGRES_USER|POSTGRES_USERNAME|"
        r"MYSQL_USER|MYSQL_USERNAME|MSSQL_USER|PGUSER|db_user|db_username|"
        r"database_user|database_username|username)[ \t]*[:=][ \t]*[\"']?([^\s\"',}]+)",
        re.IGNORECASE,
    ),
    "database_static_password": re.compile(
        r"\b(?:"
        r"DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|DATABASE_PASS|"
        r"POSTGRES_PASSWORD|POSTGRES_PASS|POSTGRESQL_PASSWORD|POSTGRESQL_PASS|"
        r"PGPASSWORD|PG_PASSWORD|PG_PASS|"
        r"MYSQL_PASSWORD|MYSQL_PASS|MYSQL_ROOT_PASSWORD|MYSQL_ROOT_PASS|"
        r"MSSQL_PASSWORD|MSSQL_PASS|SQLSERVER_PASSWORD|SQLSERVER_PASS|"
        r"db_password|db_pass|database_password|database_pass|"
        r"postgres_password|postgres_pass|postgresql_password|postgresql_pass|"
        r"pg_password|pg_pass|mysql_password|mysql_pass|mysql_root_password|"
        r"mysql_root_pass|mssql_password|mssql_pass|sqlserver_password|sqlserver_pass"
        r")[ \t]*[:=][ \t]*[\"']?([^\s\"',}]+)",
        re.IGNORECASE,
    ),
    "dynamic_database_username": re.compile(
        r"\bv-(?:token|approle|userpass|ldap|jwt|oidc|github|kubernetes)-"
        r"[A-Za-z0-9._-]+-[A-Za-z0-9._-]{6,}\b",
        re.IGNORECASE,
    ),
    "vault_policy_database_role_admin_path": re.compile(
        r"path\s+\"[^\"]*database/(?:roles|static-roles|config)/[^\"]*\"\s*\{",
        re.IGNORECASE,
    ),
    "vault_policy_write_capabilities": re.compile(
        r"capabilities\s*=\s*\[[^\]]*\"(?:create|update|delete|sudo)\"[^\]]*\]",
        re.IGNORECASE | re.DOTALL,
    ),
    "approle_login": re.compile(r"(?:/v1/)?auth/approle/login\b", re.IGNORECASE),
    "approle_cli_login": re.compile(r"\bvault\s+login\s+-method=approle\b", re.IGNORECASE),
    "approle_role_id_path": re.compile(
        r"auth/approle/role/[A-Za-z0-9._/-]+/role-id\b",
        re.IGNORECASE,
    ),
    "approle_secret_id_path": re.compile(
        r"auth/approle/role/[A-Za-z0-9._/-]+/(?:secret-id|custom-secret-id)\b",
        re.IGNORECASE,
    ),
    "aws_iam_login": re.compile(r"(?:/v1/)?auth/aws/login\b", re.IGNORECASE),
    "aws_cli_login": re.compile(r"\bvault\s+login\s+-method=aws\b", re.IGNORECASE),
    "aws_auth_role_config": re.compile(
        r"auth/aws/role/[A-Za-z0-9._/-]+\b",
        re.IGNORECASE,
    ),
    "vault_aws_auth_reference": re.compile(
        r"\b(?:VAULT_AUTH_METHOD|vault_auth_method|auth_method)[ \t]*[:=][ \t]*[\"']?(aws|iam)[\"']?",
        re.IGNORECASE,
    ),
    "aws_access_key_id": re.compile(
        r"\b(?:AWS_ACCESS_KEY_ID|aws_access_key_id)[ \t]*[:=][ \t]*[\"']?((?:AKIA|ASIA)[A-Z0-9]{16})",
        re.IGNORECASE,
    ),
    "aws_secret_access_key": re.compile(
        r"\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9/+=]{20,})",
        re.IGNORECASE,
    ),
    "aws_session_token": re.compile(
        r"\b(?:AWS_SESSION_TOKEN|aws_session_token)[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9/+=._-]{20,})",
        re.IGNORECASE,
    ),
    "aws_role_arn": re.compile(
        r"\b(?:AWS_ROLE_ARN|aws_role_arn|role_arn)[ \t]*[:=][ \t]*[\"']?(arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+)",
        re.IGNORECASE,
    ),
    "vault_aws_iam_server_id": re.compile(
        r"\b(?:X-Vault-AWS-IAM-Server-ID|iam_server_id_header_value|"
        r"VAULT_AWS_IAM_SERVER_ID)[ \t]*[:=][ \t]*[\"']?([^\s\"',}]+)",
        re.IGNORECASE,
    ),
    "aws_bound_iam_principal": re.compile(
        r"\bbound_iam_principal_arn[ \t]*[:=][ \t]*[\"']?"
        r"(arn:aws:iam::\d{12}:[A-Za-z0-9+=,.@_/-]+)",
        re.IGNORECASE,
    ),
    "vault_namespace": re.compile(
        r"\b(?:VAULT_NAMESPACE|vault_namespace|vault\.namespace)[ \t]*[:=][ \t]*[\"']?([^\s\"',}]*)",
        re.IGNORECASE,
    ),
    "vault_skip_verify": re.compile(
        r"\b(?:VAULT_SKIP_VERIFY|vault_skip_verify)[ \t]*[:=][ \t]*[\"']?(true|1|yes)",
        re.IGNORECASE,
    ),
    "vault_agent_auto_auth": re.compile(r"\bauto_auth\s*\{", re.IGNORECASE),
    "vault_agent_file_sink": re.compile(r"\bsink\s+\"file\"\s*\{", re.IGNORECASE),
    "vault_agent_sink_path": re.compile(
        r'sink\s+"file"\s*\{[^}]*path\s*=\s*"([^"]+)"[^}]*\}',
        re.IGNORECASE | re.DOTALL,
    ),
    "vault_agent_exit_after_auth": re.compile(
        r'exit_after_auth\s*=\s*true', re.IGNORECASE,
    ),
    "vault_agent_template_config": re.compile(
        r'template\s*\{[^}]*destination\s*=\s*"([^"]+)"[^}]*\}',
        re.IGNORECASE | re.DOTALL,
    ),
    "vault_agent_role_id_file": re.compile(
        r'role_id_file_path\s*=\s*"([^"]+)"', re.IGNORECASE,
    ),
    "vault_agent_secret_id_file": re.compile(
        r'secret_id_file_path\s*=\s*"([^"]+)"', re.IGNORECASE,
    ),
    "vault_agent_hcl_block": re.compile(
        r'vault\s*\{[^}]*address\s*=\s*"([^"]+)"[^}]*\}',
        re.IGNORECASE | re.DOTALL,
    ),
}


FINDING_METADATA = {
    "vault_response_wrapped_token": {
        "severity": "HIGH",
        "title": "Potential Vault response-wrapped token exposure",
        "description": "A Vault response-wrapped token-like value was discovered in an accessible file.",
        "recommendation": "Treat wrapped tokens as sensitive, verify whether they were unwrapped, and rotate or revoke affected credentials where appropriate.",
    },
    "vault_token_value": {
        "severity": "HIGH",
        "title": "Potential Vault token exposure",
        "description": "A Vault token-like value was discovered in an accessible file.",
        "recommendation": "Remove exposed Vault tokens, rotate affected credentials, and avoid storing tokens in files or logs.",
    },
    "vault_token_assignment": {
        "severity": "HIGH",
        "title": "Potential Vault token exposure",
        "description": "A Vault token assignment was discovered in an accessible file.",
        "recommendation": "Remove exposed Vault tokens, rotate affected credentials, and avoid storing tokens in files or logs.",
    },
    "vault_role_id": {
        "severity": "MEDIUM",
        "title": "Potential AppRole Role ID exposure",
        "description": "An AppRole Role ID-like value was discovered in an accessible file.",
        "recommendation": "Confirm whether this Role ID is intended to be distributed and review AppRole access controls.",
    },
    "vault_secret_id": {
        "severity": "HIGH",
        "title": "Potential AppRole Secret ID exposure",
        "description": "An AppRole Secret ID-like value was discovered in an accessible file.",
        "recommendation": "Rotate exposed Secret IDs and ensure Secret IDs are not stored in files, logs, or artifacts.",
    },
    "vault_addr_assignment": {
        "severity": "INFO",
        "title": "Vault address discovered",
        "description": "A Vault address reference was discovered in an accessible file.",
        "recommendation": "Use this address as context when assessing whether discovered credentials can reach Vault.",
    },
    "vault_8200_url": {
        "severity": "INFO",
        "title": "Vault address discovered",
        "description": "A URL using Vault's common listener port was discovered in an accessible file.",
        "recommendation": "Use this address as context when assessing whether discovered credentials can reach Vault.",
    },
    "approle_login": {
        "severity": "INFO",
        "title": "AppRole login endpoint reference discovered",
        "description": "A reference to the AppRole login endpoint was discovered in an accessible file.",
        "recommendation": "Review whether application artifacts expose AppRole authentication flow details.",
    },
    "approle_cli_login": {
        "severity": "INFO",
        "title": "AppRole CLI login reference discovered",
        "description": "A Vault CLI AppRole login reference was discovered in an accessible file.",
        "recommendation": "Use this as context when investigating discovered AppRole credential material.",
    },
    "approle_role_id_path": {
        "severity": "INFO",
        "title": "AppRole Role ID retrieval path discovered",
        "description": "An AppRole Role ID retrieval path was discovered in an accessible file.",
        "recommendation": "Review whether artifacts reveal how applications obtain AppRole Role IDs.",
    },
    "approle_secret_id_path": {
        "severity": "INFO",
        "title": "AppRole Secret ID operation path discovered",
        "description": "An AppRole Secret ID generation or custom Secret ID path was discovered in an accessible file.",
        "recommendation": "Review whether artifacts reveal how applications obtain or set AppRole Secret IDs.",
    },
    "vault_api_path": {
        "severity": "INFO",
        "title": "Vault API path reference discovered",
        "description": "A Vault API path reference was discovered in an accessible file.",
        "recommendation": "Use this path as context when assessing application interaction with Vault.",
    },
    "vault_database_creds_path": {
        "severity": "INFO",
        "title": "Vault dynamic database credential endpoint discovered",
        "description": "A Vault database dynamic credentials endpoint reference was discovered.",
        "recommendation": "Review whether access to this role can generate database users and confirm TTL and policy controls.",
    },
    "vault_database_config_path": {
        "severity": "INFO",
        "title": "Vault database connection configuration path discovered",
        "description": "A Vault database connection configuration path was discovered.",
        "recommendation": "Review whether artifacts expose database plugin configuration or privileged connection details.",
    },
    "vault_database_role_path": {
        "severity": "INFO",
        "title": "Vault database role configuration path discovered",
        "description": "A Vault database role or static role configuration path was discovered.",
        "recommendation": "Review dynamic database role TTL, SQL statements, and policy access to credential generation paths.",
    },
    "vault_database_plugin": {
        "severity": "INFO",
        "title": "Vault database secrets engine plugin reference discovered",
        "description": "A Vault database secrets engine plugin reference was discovered.",
        "recommendation": "Use this to identify the database platform and review least-privilege configuration for the plugin user.",
    },
    "vault_database_connection_url": {
        "severity": "LOW",
        "title": "Database connection URL discovered",
        "description": "A database connection URL was discovered in an accessible file.",
        "recommendation": "Avoid exposing database connection details and confirm no static credentials are embedded in the URL.",
    },
    "vault_database_creation_statements": {
        "severity": "INFO",
        "title": "Vault database creation statement discovered",
        "description": "A Vault database role creation statement was discovered.",
        "recommendation": "Review generated database user privileges and ensure statements grant least privilege.",
    },
    "vault_database_broad_privilege_statement": {
        "severity": "MEDIUM",
        "title": "Potentially broad dynamic database privilege statement observed",
        "description": "A database role statement appears to grant broad privileges to a generated or configured database user.",
        "recommendation": "Avoid broad grants such as GRANT ALL, SUPERUSER, CREATEDB, or CREATEROLE for Vault-generated database users.",
    },
    "vault_database_destructive_statement": {
        "severity": "HIGH",
        "title": "Potentially destructive SQL in Vault database role template",
        "description": "A Vault database role statement appears to contain destructive or high-risk SQL.",
        "recommendation": "Remove destructive SQL from Vault database role templates and restrict who can update database role definitions.",
    },
    "vault_database_revocation_statements": {
        "severity": "INFO",
        "title": "Vault database revocation statement discovered",
        "description": "A Vault database role revocation statement was discovered.",
        "recommendation": "Confirm revocation statements reliably remove or disable generated database users.",
    },
    "vault_database_default_ttl": {
        "severity": "INFO",
        "title": "Vault database role default TTL discovered",
        "description": "A default TTL for a Vault database role was discovered.",
        "recommendation": "Confirm the default TTL matches the intended short-lived access window.",
    },
    "vault_database_max_ttl": {
        "severity": "INFO",
        "title": "Vault database role max TTL discovered",
        "description": "A max TTL for a Vault database role was discovered.",
        "recommendation": "Confirm the max TTL is not longer than business requirements.",
    },
    "database_static_username": {
        "severity": "LOW",
        "title": "Potential static database username exposure",
        "description": "A database username-like value was discovered in an accessible file.",
        "recommendation": "Review whether this static database identity is used by Vault or applications and avoid exposing it in artifacts.",
    },
    "database_static_password": {
        "severity": "HIGH",
        "title": "Potential static database password exposure",
        "description": "A database password-like value was discovered in an accessible file.",
        "recommendation": "Rotate exposed database passwords and verify whether the credential can configure or access Vault dynamic database roles.",
    },
    "dynamic_database_username": {
        "severity": "INFO",
        "title": "Vault-generated dynamic database username observed",
        "description": "A username resembling a Vault-generated dynamic database credential was discovered.",
        "recommendation": "Use this as evidence that dynamic database credentials may be generated or logged; avoid logging generated usernames and passwords together.",
    },
    "vault_policy_database_role_admin_path": {
        "severity": "INFO",
        "title": "Vault policy references database role administration path",
        "description": "A Vault policy path references database role, static role, or database connection administration.",
        "recommendation": "Confirm only trusted administrators can create, update, delete, or sudo database role and config paths.",
    },
    "vault_policy_write_capabilities": {
        "severity": "INFO",
        "title": "Vault policy write capability observed",
        "description": "A Vault policy capability block includes create, update, delete, or sudo.",
        "recommendation": "Correlate this capability with sensitive Vault paths and enforce least privilege.",
    },
    "aws_iam_login": {
        "severity": "INFO",
        "title": "AWS IAM Vault login reference discovered",
        "description": "A reference to the Vault AWS auth login endpoint was discovered in an accessible file.",
        "recommendation": "Review whether artifacts expose the AWS IAM Vault authentication flow.",
    },
    "aws_cli_login": {
        "severity": "INFO",
        "title": "AWS IAM Vault CLI login reference discovered",
        "description": "A Vault CLI AWS auth login reference was discovered in an accessible file.",
        "recommendation": "Use this as context when investigating AWS IAM based Vault authentication exposure.",
    },
    "aws_auth_role_config": {
        "severity": "INFO",
        "title": "Vault AWS auth role configuration reference discovered",
        "description": "A Vault AWS auth role configuration path was discovered in an accessible file.",
        "recommendation": "Review whether artifacts reveal AWS principals mapped to Vault roles.",
    },
    "vault_aws_auth_reference": {
        "severity": "INFO",
        "title": "Vault AWS auth method reference discovered",
        "description": "A Vault AWS/IAM auth method reference was discovered in an accessible file.",
        "recommendation": "Use this as context when assessing AWS IAM based Vault authentication exposure.",
    },
    "aws_access_key_id": {
        "severity": "HIGH",
        "title": "Potential AWS access key ID exposure",
        "description": "An AWS access key ID was discovered in an accessible file.",
        "recommendation": "Review and rotate exposed AWS credentials according to incident response policy.",
    },
    "aws_secret_access_key": {
        "severity": "HIGH",
        "title": "Potential AWS secret access key exposure",
        "description": "An AWS secret access key-like value was discovered in an accessible file.",
        "recommendation": "Rotate exposed AWS credentials and investigate whether they can authenticate to Vault AWS auth.",
    },
    "aws_session_token": {
        "severity": "HIGH",
        "title": "Potential AWS session token exposure",
        "description": "An AWS session token-like value was discovered in an accessible file.",
        "recommendation": "Treat exposed temporary AWS session material as sensitive and verify expiration and use.",
    },
    "aws_role_arn": {
        "severity": "INFO",
        "title": "AWS role ARN discovered",
        "description": "An AWS IAM role ARN was discovered in an accessible file.",
        "recommendation": "Use this role ARN as context when reviewing Vault AWS auth role mappings.",
    },
    "vault_aws_iam_server_id": {
        "severity": "INFO",
        "title": "Vault AWS IAM server ID reference discovered",
        "description": "A Vault AWS IAM server ID header value was discovered in an accessible file.",
        "recommendation": "Review whether this value reveals AWS IAM Vault auth configuration details.",
    },
    "aws_bound_iam_principal": {
        "severity": "INFO",
        "title": "Vault AWS bound IAM principal discovered",
        "description": "A Vault AWS auth bound IAM principal ARN was discovered in an accessible file.",
        "recommendation": "Use this ARN as context when reviewing Vault AWS auth role mappings.",
    },
    "vault_namespace": {
        "severity": "INFO",
        "title": "Vault namespace reference discovered",
        "description": "A Vault namespace reference was discovered in an accessible file.",
        "recommendation": "Use this namespace as context when validating discovered Vault credential material.",
    },
    "vault_skip_verify": {
        "severity": "LOW",
        "title": "Vault TLS verification disabled",
        "description": "A configuration value indicates Vault TLS certificate verification may be disabled.",
        "recommendation": "Avoid disabling TLS verification except in controlled local labs.",
    },
    "vault_agent_auto_auth": {
        "severity": "INFO",
        "title": "Vault Agent auto-auth configuration discovered",
        "description": "A Vault Agent auto-auth configuration block was discovered in an accessible file.",
        "recommendation": "Review the auto-auth method and token sink configuration for credential exposure risk.",
    },
    "vault_agent_file_sink": {
        "severity": "LOW",
        "title": "Vault Agent file token sink discovered",
        "description": "A Vault Agent file sink configuration was discovered, which may write Vault tokens to disk.",
        "recommendation": "Protect token sink files with strict permissions and avoid exposing them in artifacts.",
    },
    "vault_agent_sink_path": {
        "severity": "MEDIUM",
        "title": "Vault Agent sink file path exposed",
        "description": "A Vault Agent file sink path was discovered, revealing where cached tokens are written.",
        "recommendation": "Ensure sink file paths are protected with restrictive filesystem permissions (chmod 600).",
    },
    "vault_agent_exit_after_auth": {
        "severity": "INFO",
        "title": "Vault Agent exit_after_auth enabled",
        "description": "Vault Agent is configured to exit after initial authentication — short credential window.",
        "recommendation": "While this limits token exposure, ensure the agent is supervised for automatic restarts.",
    },
    "vault_agent_template_config": {
        "severity": "MEDIUM",
        "title": "Vault Agent template block discovered",
        "description": "A Vault Agent template block was discovered — rendered secrets may be written to disk.",
        "recommendation": "Audit template destinations for excessive permissions and secret exposure.",
    },
    "vault_agent_role_id_file": {
        "severity": "HIGH",
        "title": "Vault Agent AppRole Role ID file path exposed",
        "description": "The path to an AppRole Role ID file was discovered in an agent configuration.",
        "recommendation": "Protect Role ID files with restrictive permissions and avoid exposing paths in artifacts.",
    },
    "vault_agent_secret_id_file": {
        "severity": "HIGH",
        "title": "Vault Agent AppRole Secret ID file path exposed",
        "description": "The path to an AppRole Secret ID file was discovered in an agent configuration.",
        "recommendation": "Protect Secret ID files with restrictive permissions and rotate exposed credentials.",
    },
    "vault_agent_hcl_block": {
        "severity": "INFO",
        "title": "Vault Agent HCL configuration discovered",
        "description": "A Vault Agent HCL configuration block was discovered specifying the Vault address.",
        "recommendation": "Use this address as context for credential validation and attack surface mapping.",
    },
}
