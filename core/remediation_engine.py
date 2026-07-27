"""Remediation knowledge base — maps finding patterns to actionable fix steps.

Each entry provides root cause analysis, exact Vault CLI/API commands,
and a priority ranking.  Used by the PDF report and the interactive
``fix`` chat command.

Design principle: every rule is a function that receives the finding dict
and returns a :class:`RemediationAdvice` (or ``None`` if it doesn't match).
This makes the engine extensible — new scanners can register new rules
without touching existing code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RemediationAdvice:
    """Actionable fix for a single finding or group of findings."""

    category: str          # e.g. "TLS", "Authentication", "Policy"
    title: str             # short heading
    root_cause: str        # why this happened
    fix_steps: list[str]   # concrete CLI / API commands
    priority: int = 5      # 1 (urgent) to 5 (cosmetic)
    references: list[str] = field(default_factory=list)  # Vault docs URLs


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

# Each rule: (title_substring, severity_min, handler_function)
# Rules are checked in order; first match wins per finding.
_RULES: list = []


def register_rule(title_contains: str, severity_min: str = "INFO"):
    """Decorator: register a remediation rule.

    The decorated function receives the full finding dict and returns
    ``RemediationAdvice | None``.
    """
    def decorator(fn):
        _RULES.append((title_contains.lower(), severity_min, fn))
        return fn
    return decorator


_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "PASS": 0}


def _sev_met(finding_severity: str, min_severity: str) -> bool:
    return _SEVERITY_RANK.get(finding_severity, 0) >= _SEVERITY_RANK.get(min_severity, 0)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_remediation(findings: list[dict]) -> list[RemediationAdvice]:
    """Match *findings* against all registered rules.

    Returns a deduplicated, priority-sorted list of remediation advice.
    """
    matched: list[RemediationAdvice] = []
    seen_titles: set[str] = set()

    for finding in findings:
        ftitle = finding.get("title", "").lower()
        fsev = finding.get("severity", "INFO")

        for substr, min_sev, handler in _RULES:
            if substr in ftitle and _sev_met(fsev, min_sev):
                try:
                    advice = handler(finding)
                    if advice and advice.title not in seen_titles:
                        seen_titles.add(advice.title)
                        matched.append(advice)
                        break  # first matching rule wins per finding
                except Exception:
                    continue

    # Sort by priority (lower = more urgent)
    matched.sort(key=lambda a: a.priority)
    return matched


def group_by_category(advice_list: list[RemediationAdvice]) -> dict[str, list[RemediationAdvice]]:
    """Group remediation items by category for structured reporting."""
    groups: dict[str, list[RemediationAdvice]] = {}
    for a in advice_list:
        groups.setdefault(a.category, []).append(a)
    return groups


def generate_priority_action_plan(advice_list: list[RemediationAdvice]) -> list[str]:
    """Produce a step-by-step priority action plan from the advice list."""
    plan: list[str] = []
    critical = [a for a in advice_list if a.priority <= 2]
    high = [a for a in advice_list if a.priority == 3]
    medium = [a for a in advice_list if a.priority == 4]
    low = [a for a in advice_list if a.priority >= 5]

    step = 1
    if critical:
        plan.append("── CRITICAL (immediate action required) ──")
        for a in critical:
            plan.append(f"  {step}. {a.title}")
            step += 1
    if high:
        plan.append("── HIGH (address within 7 days) ──")
        for a in high:
            plan.append(f"  {step}. {a.title}")
            step += 1
    if medium:
        plan.append("── MEDIUM (address within 30 days) ──")
        for a in medium:
            plan.append(f"  {step}. {a.title}")
            step += 1
    if low:
        plan.append("── LOW (review and schedule) ──")
        for a in low:
            plan.append(f"  {step}. {a.title}")
            step += 1

    if not plan:
        plan.append("No remediation items identified — security posture appears strong.")
    return plan


# ===================================================================
# REMEDIATION RULES
# ===================================================================
# Priority scale: 1 = immediate (CRITICAL), 2 = urgent (HIGH),
# 3 = important (MEDIUM), 4 = routine (LOW), 5 = cosmetic (INFO/PASS)
# ===================================================================

# ── TLS ──────────────────────────────────────────────────────────────


@register_rule("self-signed tls certificate", "MEDIUM")
def _fix_self_signed_tls(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="TLS",
        title="Replace self-signed certificate with a trusted CA certificate",
        root_cause=(
            "Vault is configured with a self-signed TLS certificate. "
            "Clients connecting to Vault cannot verify the server's identity, "
            "making them vulnerable to man-in-the-middle attacks."
        ),
        fix_steps=[
            "# 1. Obtain a certificate from a trusted CA (or internal PKI)",
            "# 2. Update Vault listener configuration in config.hcl:",
            'listener "tcp" {',
            '  address     = "0.0.0.0:8200"',
            '  tls_cert_file = "/vault/config/trusted-cert.pem"',
            '  tls_key_file  = "/vault/config/trusted-key.pem"',
            "}",
            "# 3. Reload Vault or send SIGHUP:",
            "kill -HUP $(pgrep vault)",
        ],
        priority=3,
        references=["https://developer.hashicorp.com/vault/docs/configuration/listener/tcp"],
    )


@register_rule("http does not redirect to https", "LOW")
def _fix_https_redirect(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="TLS",
        title="Configure HTTP-to-HTTPS redirect",
        root_cause=(
            "Vault's HTTP listener is accessible but does not redirect to HTTPS. "
            "Accidental plaintext connections may leak tokens and secrets."
        ),
        fix_steps=[
            "# Option 1: Disable plaintext listener, enable HTTPS only",
            "# In config.hcl, remove any non-TLS listener block.",
            "# Option 2: Place a reverse proxy (nginx/HAProxy) in front",
            "# that redirects HTTP → HTTPS:",
            "# nginx: return 301 https://$host$request_uri;",
        ],
        priority=5,
        references=["https://developer.hashicorp.com/vault/docs/configuration/listener/tcp"],
    )


# ── Health / Information Disclosure ───────────────────────────────────


@register_rule("vault version disclosed", "LOW")
def _fix_version_disclosure(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Information Disclosure",
        title="Hide Vault version from health endpoint",
        root_cause=(
            "The /v1/sys/health endpoint is exposed without authentication "
            "and reveals the exact Vault version, aiding attackers in "
            "targeting version-specific CVEs."
        ),
        fix_steps=[
            "# 1. Place a reverse proxy in front of Vault",
            "# 2. Block or rewrite /v1/sys/health:",
            "# nginx example:",
            "location /v1/sys/health {",
            "    deny all;",
            "}",
            "# 3. Or use Vault's built-in listener properties:",
            'listener "tcp" {',
            '  telemetry {',
            '    unauthenticated_metrics_access = false',
            "  }",
            "}",
        ],
        priority=4,
        references=["https://developer.hashicorp.com/vault/docs/configuration/listener/tcp"],
    )


@register_rule("health endpoint exposed", "INFO")
def _fix_health_exposure(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Information Disclosure",
        title="Restrict unauthenticated access to health endpoint",
        root_cause=(
            "The /v1/sys/health endpoint returns detailed cluster information "
            "without requiring a token."
        ),
        fix_steps=[
            "# Block via reverse proxy (recommended):",
            "location /v1/sys/health { allow 10.0.0.0/8; deny all; }",
            "# Or use Vault Enterprise's control group policies.",
        ],
        priority=4,
    )


@register_rule("cluster name disclosed", "LOW")
def _fix_cluster_disclosure(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Information Disclosure",
        title="Restrict cluster metadata exposure",
        root_cause="The health endpoint reveals internal cluster identifiers.",
        fix_steps=[
            "# Block /v1/sys/health and /v1/sys/seal-status externally:",
            "location ~ ^/v1/sys/(health|seal-status) { deny all; }",
        ],
        priority=5,
    )


# ── CORS ─────────────────────────────────────────────────────────────


@register_rule("wildcard cors", "HIGH")
def _fix_cors_wildcard(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="CORS",
        title="Remove wildcard CORS configuration",
        root_cause=(
            "Vault's CORS settings allow any origin (Access-Control-Allow-Origin: *). "
            "Malicious websites can make cross-origin requests to Vault using "
            "the victim's browser session."
        ),
        fix_steps=[
            "# Disable wildcard CORS:",
            "vault write sys/config/cors \\",
            '  allowed_origins="https://trusted-app.example.com" \\',
            '  allowed_headers="X-Vault-Token,Content-Type"',
            "# Verify:",
            "vault read sys/config/cors",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/api-docs/system/config-cors"],
    )


# ── Authentication ────────────────────────────────────────────────────


@register_rule("no auth methods", "HIGH")
def _fix_auth_methods(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Authentication",
        title="Enable and configure authentication methods securely",
        root_cause=(
            "Vault has no authentication methods configured or only token-based "
            "auth, which lacks integration with enterprise identity providers."
        ),
        fix_steps=[
            "# Enable and configure auth methods:",
            "vault auth enable oidc           # OpenID Connect",
            "vault auth enable ldap           # LDAP",
            "vault auth enable kubernetes     # K8s service accounts",
            "# For each, disable default mount access:",
            "vault auth tune -default-lease-ttl=1h -max-lease-ttl=12h oidc/",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/auth"],
    )


@register_rule("userpass", "MEDIUM")
def _fix_userpass_auth(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Authentication",
        title="Migrate from userpass to OIDC/LDAP or enforce MFA",
        root_cause=(
            "The userpass auth method stores static credentials in Vault. "
            "Without MFA or password rotation, compromised passwords grant "
            "long-lived access."
        ),
        fix_steps=[
            "# Option 1: Migrate to OIDC:",
            "vault auth enable oidc",
            "vault write auth/oidc/config \\",
            '  oidc_discovery_url="https://idp.example.com" \\',
            '  oidc_client_id="vault" \\',
            '  oidc_client_secret="..."',
            "# Option 2: Enable MFA on userpass:",
            "vault write sys/mfa/method/totp/my-totp \\",
            '  issuer="Vault" \\',
            '  algorithm="SHA256"',
        ],
        priority=3,
        references=["https://developer.hashicorp.com/vault/docs/auth/userpass"],
    )


@register_rule("approle secret_id", "MEDIUM")
def _fix_approle_secret_id_abuse(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Authentication",
        title="Harden AppRole secret_id configuration",
        root_cause=(
            "AppRole secret_id has excessive use-count, long TTL, or is stored "
            "in plaintext. This enables credential replay and lateral movement."
        ),
        fix_steps=[
            "# Tighten secret_id constraints:",
            "vault write auth/approle/role/<role-name> \\",
            "  secret_id_num_uses=1 \\",
            "  secret_id_ttl=10m \\",
            "  token_ttl=1h \\",
            "  token_max_ttl=4h \\",
            "  bind_secret_id=true",
            "# Rotate any leaked secret_id:",
            "vault write -f auth/approle/role/<role-name>/secret-id",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/auth/approle"],
    )


# ── Policy / ACL ──────────────────────────────────────────────────────


@register_rule("wildcard", "HIGH")
def _fix_wildcard_policy(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Replace wildcard paths with explicit least-privilege paths",
        root_cause=(
            "A policy contains wildcard path patterns (e.g. secret/*, sys/*) "
            "that grant far more access than needed. A compromised token with "
            "this policy can read or modify all secrets under that path."
        ),
        fix_steps=[
            "# 1. Audit what the application actually accesses:",
            "vault audit enable file file_path=/var/log/vault/audit.log",
            "# 2. Replace wildcard paths with explicit paths:",
            '# BEFORE:  path "secret/*" { capabilities = ["read","list"] }',
            '# AFTER:   path "secret/data/app/{config,keys}" { capabilities = ["read"] }',
            "# 3. Update the policy:",
            "vault policy write app-policy app-policy.hcl",
            "# 4. Verify with a test token:",
            "vault token create -policy=app-policy -ttl=5m",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/concepts/policies"],
    )


@register_rule("sudo", "CRITICAL")
def _fix_sudo_policy(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Remove sudo capability from non-administrative policies",
        root_cause=(
            "A non-root policy grants sudo access. sudo allows users to perform "
            "privileged operations including root credential generation and "
            "auth method modification."
        ),
        fix_steps=[
            "# 1. Identify the offending policy:",
            "vault policy list",
            "vault policy read <policy-name>",
            "# 2. Remove sudo from non-admin paths:",
            '# Change:  path "sys/*" { capabilities = ["create","read","update","delete","list","sudo"] }',
            '# To:      path "sys/mounts/*" { capabilities = ["read","list"] }',
            "# 3. Update the policy:",
            "vault policy write <policy-name> <fixed-file>.hcl",
            "# 4. Revoke all tokens with the old policy:",
            "vault lease revoke -prefix auth/token/",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/concepts/policies#sudo"],
    )


@register_rule("root policy", "CRITICAL")
def _fix_root_policy(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Restrict root token usage and implement break-glass procedure",
        root_cause=(
            "Root policy access was detected. Root tokens have unlimited "
            "capabilities — if compromised, the entire Vault instance is lost."
        ),
        fix_steps=[
            "# 1. NEVER use root token for day-to-day operations",
            "# 2. Create named administrative policies instead:",
            "vault policy write admin admin-policy.hcl",
            "# 3. Revoke the root token if possible:",
            "vault token revoke <root-token>",
            "# 4. Implement break-glass procedure for root access:",
            "vault operator generate-root -init",
            "vault operator generate-root",
            "# 5. Enable multi-party unseal / auto-unseal where available",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/concepts/tokens#root-tokens"],
    )


@register_rule("denied", "MEDIUM")
def _fix_policy_read_denied(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Ensure tokens have policy:read for accountability",
        root_cause=(
            "The token cannot list or read some policies. While this limits "
            "reconnaissance, it also means you cannot audit what the token "
            "can actually access — making security review impossible."
        ),
        fix_steps=[
            "# Grant policy read to auditor role:",
            'path "sys/policies/acl/*" { capabilities = ["read","list"] }',
            "vault policy write auditor auditor.hcl",
        ],
        priority=3,
    )


# ── Token Management ──────────────────────────────────────────────────


@register_rule("orphan", "MEDIUM")
def _fix_orphan_tokens(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Token Management",
        title="Prevent orphan token creation and audit existing orphans",
        root_cause=(
            "Orphan tokens are not revoked when their parent token is revoked. "
            "They can persist indefinitely, creating unmanaged access paths."
        ),
        fix_steps=[
            "# 1. List all tokens and identify orphans:",
            "vault list auth/token/accessors",
            "# 2. Revoke orphan tokens:",
            "vault token revoke <token-accessor>",
            "# 3. Disable orphan token creation in roles:",
            "vault write auth/token/roles/<role-name> orphan=false",
        ],
        priority=3,
        references=["https://developer.hashicorp.com/vault/docs/concepts/tokens#token-hierarchy"],
    )


@register_rule("infinite ttl", "HIGH")
def _fix_infinite_ttl(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Token Management",
        title="Eliminate infinite TTL tokens and enforce maximum TTLs",
        root_cause=(
            "Tokens with TTL=0 (infinite) never expire. A leaked infinite TTL "
            "token grants permanent access with no rotation mechanism."
        ),
        fix_steps=[
            "# 1. Set max_lease_ttl on the auth mount:",
            "vault auth tune -max-lease-ttl=720h token/",
            "# 2. Set default_ttl for token roles:",
            "vault write auth/token/roles/<role> ttl=24h max_ttl=168h",
            "# 3. Revoke existing infinite TTL tokens:",
            "vault token revoke <token>",
            "# 4. Set global max:",
            "vault write sys/config/state/max-lease-ttl 720h",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live"],
    )


# ── Secrets / KV ──────────────────────────────────────────────────────


@register_rule("long-lived ttl", "HIGH")
def _fix_long_lived_secret_ttl(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Reduce secret engine mount and role TTLs to production-safe values",
        root_cause=(
            "Secrets engine mounts or roles have excessively long TTLs "
            "(or unlimited/max TTL). Long-lived credentials increase blast "
            "radius if compromised."
        ),
        fix_steps=[
            "# 1. Tune mount-level TTLs:",
            "vault secrets tune -default-lease-ttl=1h -max-lease-ttl=24h secret/",
            "# 2. For database roles:",
            "vault write database/roles/<role> default_ttl=1h max_ttl=12h",
            "# 3. For PKI roles:",
            "vault write pki/roles/<role> max_ttl=720h",
            "# 4. Audit all TTLs:",
            "vault read sys/mounts | jq '.data | to_entries[] | {path: .key, config: .value.config}'",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/concepts/lease"],
    )


@register_rule("secret data", "HIGH")
def _fix_exposed_secrets(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Rotate exposed secrets and implement dynamic secrets where possible",
        root_cause=(
            "Static secrets are stored in KV engines and were readable by the "
            "tested token. Static secrets do not auto-rotate and may be stale."
        ),
        fix_steps=[
            "# 1. Rotate the exposed static secrets immediately",
            "# 2. Migrate to dynamic secrets where possible:",
            "vault secrets enable database       # dynamic DB credentials",
            "vault secrets enable aws            # dynamic AWS IAM keys",
            "vault secrets enable gcp            # dynamic GCP service accounts",
            "# 3. For secrets that must remain static:",
            "vault write secret/rotated/creds password=$(openssl rand -base64 32)",
            "# 4. Use KV v2 with versioning and check-and-set:",
            "vault kv metadata put secret/app cas_required=true",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/secrets"],
    )


@register_rule("kv enumeration", "MEDIUM")
def _fix_kv_enumeration(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Restrict KV listing capabilities to least-privilege paths",
        root_cause=(
            "The token can LIST secrets across broad paths. LIST capability "
            "enables discovery of all available secret paths."
        ),
        fix_steps=[
            "# Limit LIST to only required paths:",
            'path "secret/data/app/*" { capabilities = ["read","list"] }',
            '# NOT: path "secret/*" { capabilities = ["read","list"] }',
            "vault policy write app-policy app-policy.hcl",
        ],
        priority=3,
    )


# ── Credential Leaks / Hijack ─────────────────────────────────────────


@register_rule("vault token found", "CRITICAL")
def _fix_leaked_vault_token(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Revoke leaked Vault tokens immediately and scan all repositories",
        root_cause=(
            "A Vault token (hvs. or hvb.) was found in files or git history. "
            "Anyone with access to the repository can use this token to "
            "authenticate to Vault."
        ),
        fix_steps=[
            "# 1. REVOKE THE LEAKED TOKEN IMMEDIATELY:",
            "vault token revoke <leaked-token>",
            "# 2. Check if the token was used:",
            "vault read sys/internal/counters/tokens",
            "# 3. Remove from git history:",
            "git filter-branch --force --index-filter \\",
            '  "git rm --cached --ignore-unmatch <file>" --prune-empty -- --all',
            "# 4. Scan the entire repo:",
            "git log -p | grep -E 'hvs\\.|hvb\\.'",
            "# 5. Implement pre-commit hooks:",
            "pip install detect-secrets && detect-secrets scan",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/concepts/tokens#token-leakage"],
    )


@register_rule("approle credential", "CRITICAL")
def _fix_leaked_approle(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Rotate leaked AppRole credentials and harden secret_id handling",
        root_cause=(
            "AppRole role_id and/or secret_id were found in files. These "
            "can be used to generate Vault tokens with the role's policies."
        ),
        fix_steps=[
            "# 1. Destroy the leaked secret_id:",
            "vault write auth/approle/role/<role>/secret-id/destroy \\",
            "  secret_id=<leaked-secret-id>",
            "# 2. Generate a fresh secret_id with limited uses:",
            "vault write -f auth/approle/role/<role>/secret-id \\",
            "  secret_id_num_uses=1 secret_id_ttl=10m",
            "# 3. Rotate role_id if it was also leaked:",
            "vault write auth/approle/role/<role>/role-id",
            "# 4. Use response wrapping for secret_id delivery:",
            "vault write -wrap-ttl=120s -f \\",
            "  auth/approle/role/<role>/secret-id",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/auth/approle"],
    )


@register_rule("aws access key", "CRITICAL")
def _fix_leaked_aws_keys(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Deactivate leaked AWS IAM keys and rotate immediately",
        root_cause=(
            "AWS AKIA/ASIA access keys were found in files. These keys can "
            "be used to access AWS resources with the associated IAM permissions."
        ),
        fix_steps=[
            "# 1. DEACTIVATE the key in AWS IAM IMMEDIATELY:",
            "aws iam update-access-key --access-key-id <KEY> \\",
            "  --status Inactive --user-name <user>",
            "# 2. Delete if not needed:",
            "aws iam delete-access-key --access-key-id <KEY> \\",
            "  --user-name <user>",
            "# 3. Create new key pair:",
            "aws iam create-access-key --user-name <user>",
            "# 4. Use Vault AWS secrets engine for dynamic keys:",
            "vault secrets enable aws",
            "vault write aws/roles/ec2-read credential_type=iam_user \\",
            "  policy_document=@ec2-read-policy.json",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/secrets/aws"],
    )


@register_rule("database password", "CRITICAL")
def _fix_leaked_db_password(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Rotate leaked database passwords and use dynamic database credentials",
        root_cause=(
            "Database connection strings with passwords were found in files. "
            "Static DB credentials in code/config enable direct database access."
        ),
        fix_steps=[
            "# 1. Change the leaked database password IMMEDIATELY:",
            "ALTER USER <username> WITH PASSWORD '<new-strong-password>';",
            "# 2. Enable Vault database secrets engine:",
            "vault secrets enable database",
            "vault write database/config/postgres \\",
            "  plugin_name=postgresql-database-plugin \\",
            '  connection_url="postgresql://{{username}}:{{password}}@host:5432/db" \\',
            "  username=vault_admin password=<admin-password>",
            "# 3. Create dynamic roles:",
            "vault write database/roles/app \\",
            "  db_name=postgres \\",
            "  creation_statements='CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\\''{{password}}'\\'' VALID UNTIL '\\''{{expiration}}'\\'';' \\",
            "  default_ttl=1h max_ttl=12h",
            "# 4. Use Vault Agent or Consul Template for credential injection",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/secrets/databases"],
    )


@register_rule("private key", "CRITICAL")
def _fix_leaked_private_key(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Revoke and rotate leaked private keys",
        root_cause=(
            "A private key (PEM format) was found in scanned files. "
            "Private keys grant cryptographic identity — if compromised, "
            "all systems trusting the corresponding public key are at risk."
        ),
        fix_steps=[
            "# 1. Identify what the key is used for (TLS, SSH, JWT signing, etc.)",
            "# 2. Generate a new key pair:",
            "openssl genrsa -out new-key.pem 4096",
            "# 3. Update all systems that trust the old public key",
            "# 4. Revoke old certificates if this is a TLS key",
            "# 5. Use Vault Transit for key management going forward:",
            "vault secrets enable transit",
            "vault write -f transit/keys/app-key",
        ],
        priority=1,
    )


@register_rule("vault token file", "MEDIUM")
def _fix_token_file(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Remove ~/.vault-token and use token helpers or environment variables",
        root_cause=(
            "The ~/.vault-token file stores the current Vault token in plaintext "
            "on disk. Any process running as the user can read it."
        ),
        fix_steps=[
            "# 1. Remove the token file:",
            "rm ~/.vault-token",
            "# 2. Use a token helper for secure storage:",
            "vault token helper enable",
            "# Or use environment variable per session:",
            "export VAULT_TOKEN=$(vault login -method=oidc -token-only)",
            "# 3. Set short TTLs and rotate frequently",
        ],
        priority=3,
        references=["https://developer.hashicorp.com/vault/docs/commands/token-helper"],
    )


# ── Environment ───────────────────────────────────────────────────────


@register_rule("environment variable", "MEDIUM")
def _fix_env_vault_vars(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Environment Security",
        title="Remove Vault tokens from environment variables",
        root_cause=(
            "VAULT_TOKEN or related Vault credentials were found in environment "
            "variables. Environment variables can be leaked via /proc, ps, "
            "crash dumps, CI logs, or child process inheritance."
        ),
        fix_steps=[
            "# 1. Unset the environment variable:",
            "unset VAULT_TOKEN",
            "# 2. Use Vault Agent for automatic authentication:",
            "vault agent -config=agent.hcl",
            "# 3. Or use a token helper:",
            "vault login -method=oidc",
            "# 4. In CI/CD, use short-lived wrapped tokens:",
            "vault write -wrap-ttl=300s -f auth/approle/login \\",
            "  role_id=$ROLE_ID secret_id=$SECRET_ID",
        ],
        priority=3,
    )


# ── Audit ─────────────────────────────────────────────────────────────


@register_rule("audit device", "MEDIUM")
def _fix_audit_disabled(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Audit & Monitoring",
        title="Enable audit logging for all Vault operations",
        root_cause=(
            "No audit device is enabled. Without audit logs, there is no "
            "record of who accessed what, making incident investigation "
            "and compliance reporting impossible."
        ),
        fix_steps=[
            "# 1. Enable file audit device:",
            "vault audit enable file file_path=/var/log/vault/audit.log",
            "# 2. For production, use socket audit:",
            "vault audit enable socket address=syslog.example.com:514 socket_type=tcp",
            "# 3. Protect audit logs from tampering:",
            "chmod 640 /var/log/vault/audit.log",
            "chown vault:vault /var/log/vault/audit.log",
            "# 4. Set up log rotation:",
            "# /etc/logrotate.d/vault-audit",
        ],
        priority=3,
        references=["https://developer.hashicorp.com/vault/docs/audit"],
    )


@register_rule("audit backdoor", "HIGH")
def _fix_audit_backdoor(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Audit & Monitoring",
        title="Detect and remove audit backdoors — re-enable tamper-proof logging",
        root_cause=(
            "An audit device may have been disabled or tampered with. "
            "Disabling audit is a common attacker technique to cover tracks."
        ),
        fix_steps=[
            "# 1. Check current audit devices:",
            "vault audit list -detailed",
            "# 2. Re-enable audit if disabled:",
            "vault audit enable file file_path=/var/log/vault/audit.log",
            "# 3. Use Sentinel/OPA policies to prevent audit disabling:",
            'import "sentinel"',
            '# Or use Vault policy: path "sys/audit/*" { capabilities = ["deny"] }',
            "# 4. Set up alerting when audit devices change",
        ],
        priority=2,
    )


# ── Seal / Unseal ─────────────────────────────────────────────────────


@register_rule("unseal key", "CRITICAL")
def _fix_unseal_key_exposure(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Seal / Unseal",
        title="Protect unseal keys — implement auto-unseal or HSM-based unsealing",
        root_cause=(
            "Unseal keys were found or are handled insecurely. Unseal keys "
            "can decrypt the entire Vault storage backend — they are the "
            "ultimate crown jewels."
        ),
        fix_steps=[
            "# 1. Implement auto-unseal using a cloud KMS:",
            "# In config.hcl:",
            "seal \"awskms\" {",
            "  region     = \"us-east-1\"",
            "  kms_key_id = \"alias/vault-unseal\"",
            "}",
            "# 2. Or use Transit auto-unseal (Vault Enterprise):",
            "# 3. If manual unseal is required, distribute keys to",
            "#    multiple trusted operators (threshold > 1)",
            "# 4. NEVER store unseal keys in the same location",
        ],
        priority=1,
    )


# ── Version / CVE ─────────────────────────────────────────────────────


@register_rule("vault cve", "HIGH")
def _fix_vault_cve(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Patch Management",
        title="Upgrade Vault to the latest patched version",
        root_cause=(
            "The target Vault version matches known CVEs. Vulnerable Vault "
            "versions may allow authentication bypass, privilege escalation, "
            "or denial of service."
        ),
        fix_steps=[
            "# 1. Check current version:",
            "vault version",
            "# 2. Review the changelog for breaking changes:",
            "# https://developer.hashicorp.com/vault/docs/release-notes",
            "# 3. Upgrade:",
            "# - Stop Vault service",
            "# - Replace binary",
            "# - Run: vault operator migrate",
            "# - Start Vault service",
            "# 4. Verify after upgrade:",
            "vault status",
            "vault operator diagnosis",
        ],
        priority=1,
        references=["https://developer.hashicorp.com/vault/docs/upgrading"],
    )


@register_rule("outdated version", "HIGH")
def _fix_outdated_vault(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Patch Management",
        title="Upgrade Vault — current version is outdated",
        root_cause=(
            "The Vault version is significantly behind the current stable release. "
            "Older versions lack security fixes, performance improvements, and "
            "new secret engine types."
        ),
        fix_steps=[
            "# 1. Plan upgrade path (e.g., 1.15.x → 1.16.x → 1.17.latest)",
            "# 2. Test upgrade on staging first",
            "# 3. Follow the official upgrade guide",
            "vault operator migrate",
            "# 4. Verify health:",
            "vault status && vault operator diagnosis",
        ],
        priority=2,
        references=["https://developer.hashicorp.com/vault/docs/upgrading"],
    )


# ── Vault Seal Manipulation ────────────────────────────────────────────


@register_rule("seal", "HIGH")
def _fix_seal_manipulation(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Seal / Unseal",
        title="Restrict seal/unseal operations to break-glass procedures only",
        root_cause=(
            "The token can seal or unseal Vault. Sealing Vault causes a "
            "complete denial of service for all clients. Only root tokens "
            "or tokens with explicitly granted seal capabilities should "
            "have this power."
        ),
        fix_steps=[
            "# 1. Remove seal capabilities from non-root policies",
            "# 2. Implement break-glass SOP for seal operations",
            "# 3. Use auto-unseal to eliminate manual unseal entirely",
            "# 4. Monitor for unexpected seal events:",
            "vault audit list",
        ],
        priority=1,
    )


# ── Active Execution: Persistence ─────────────────────────────────────


@register_rule("persistence installed", "CRITICAL")
def _fix_persistence_backdoor(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Authentication",
        title="Remove attacker-installed persistence backdoors immediately",
        root_cause=(
            "A backdoor auth method (AppRole, userpass, or Kubernetes role) "
            "was installed. Attackers use these to maintain access after the "
            "initial compromise is detected and remediated."
        ),
        fix_steps=[
            "# 1. List all auth methods — look for unfamiliar entries:",
            "vault auth list -detailed",
            "# 2. Disable the backdoor auth method:",
            "vault auth disable <backdoor-path>",
            "# 3. List and revoke tokens from that auth method:",
            "vault list auth/token/accessors",
            "vault token revoke <accessor>",
            "# 4. Audit who created the backdoor:",
            "vault audit list -detailed",
        ],
        priority=1,
    )


@register_rule("multi-persistence", "CRITICAL")
def _fix_multi_persistence(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Authentication",
        title="Multiple persistence mechanisms detected — full auth method audit required",
        root_cause=(
            "Multiple backdoor auth methods were installed across different "
            "auth types. This indicates a coordinated attacker establishing "
            "redundant access paths."
        ),
        fix_steps=[
            "# 1. IMMEDIATE: Disable ALL non-standard auth mounts",
            "vault auth list -detailed",
            "vault auth disable <each-backdoor>",
            "# 2. Rotate root token:",
            "vault operator generate-root -init",
            "# 3. Review all policies:",
            "vault policy list",
            "# 4. Implement Sentinel/OPA policies to block unauthorized auth changes",
        ],
        priority=1,
    )


# ── Active Execution: Secret Exfiltration ──────────────────────────────


@register_rule("secret exfiltration successful", "CRITICAL")
def _fix_secret_exfil_success(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="All exfiltrated secrets must be rotated — secrets engine audit required",
        root_cause=(
            "The tested token successfully read secrets from KV, Transit, "
            "and/or PKI engines. These secrets should be considered compromised "
            "and rotated immediately."
        ),
        fix_steps=[
            "# 1. Identify all secrets the token could access:",
            "vault kv list secret/",
            "# 2. Rotate each leaked secret:",
            "vault kv patch secret/admin/creds password=$(openssl rand -base64 32)",
            "# 3. Rotate Transit keys if exfiltrated:",
            "vault write -f transit/keys/my-key/rotate",
            "# 4. Revoke and reissue PKI certificates if exfiltrated:",
            "vault write pki/revoke serial_number=<serial>",
            "# 5. Tighten the token's policy to least privilege:",
            "vault policy write <role> <fixed-policy>.hcl",
        ],
        priority=1,
    )


@register_rule("transit keys discovered", "HIGH")
def _fix_transit_keys_exposed(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Rotate exposed Transit encryption keys",
        root_cause=(
            "Transit encryption key metadata was enumerated. While Transit "
            "keys cannot be exported, knowledge of key names and versions "
            "aids attackers in crafting targeted requests."
        ),
        fix_steps=[
            "# 1. Rotate affected Transit keys:",
            "vault write -f transit/keys/<key>/rotate",
            "# 2. Restrict LIST on transit endpoints:",
            'path "transit/keys/*" { capabilities = ["read"] }',
        ],
        priority=2,
    )


# ── Active Execution: Seal Manipulation ────────────────────────────────


@register_rule("vault sealed", "CRITICAL")
def _fix_vault_sealed_dos(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Seal / Unseal",
        title="Vault was sealed — unseal immediately and restrict seal permissions",
        root_cause=(
            "Vault was sealed by an attacker with seal privileges. This causes "
            "a complete denial of service — no secrets can be read, no "
            "authentication works."
        ),
        fix_steps=[
            "# 1. Unseal Vault immediately:",
            "vault operator unseal <unseal-key>",
            "# 2. Remove seal capability from non-root policies",
            "# 3. Implement auto-unseal with cloud KMS",
            "# 4. Monitor for seal events via audit log",
        ],
        priority=1,
    )


@register_rule("vault unsealed", "HIGH")
def _fix_vault_unsealed_warning(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Seal / Unseal",
        title="Monitor unseal events — verify no unauthorized unsealing occurred",
        root_cause=(
            "Vault was recently unsealed. Verify this was an authorized "
            "operation and not an attacker gaining access after a DoS attack."
        ),
        fix_steps=[
            "# 1. Check audit logs for unseal events:",
            "grep 'unseal' /var/log/vault/audit.log",
            "# 2. Verify unseal key holders",
            "# 3. Implement auto-unseal to eliminate manual unseal",
        ],
        priority=2,
    )


# ── Active Execution: Token Exploit ────────────────────────────────────


@register_rule("token created", "CRITICAL")
def _fix_unauthorized_token_creation(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Token Management",
        title="Revoke unauthorized tokens and restrict token creation capabilities",
        root_cause=(
            "An attacker-created token was detected. Tokens created without "
            "authorization represent active persistent access to Vault."
        ),
        fix_steps=[
            "# 1. Revoke the unauthorized token immediately:",
            "vault token revoke <token>",
            "# 2. Audit all recent token creations:",
            "vault list auth/token/accessors",
            "# 3. Restrict token creation to break-glass procedures only:",
            '# Remove "create" from auth/token/create paths in non-admin policies',
            "# 4. Set max TTL on token roles:",
            "vault write auth/token/roles/<role> max_ttl=24h",
        ],
        priority=1,
    )


# ── Active Execution: CVE Scanner ──────────────────────────────────────


@register_rule("cve taramasi", "HIGH")
def _fix_cve_scan_findings(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Patch Management",
        title="Address CVE findings — prioritize by CVSS score",
        root_cause=(
            "CVE scanning identified known vulnerabilities in the target "
            "Vault deployment. CVEs can lead to authentication bypass, "
            "privilege escalation, or data exposure."
        ),
        fix_steps=[
            "# 1. Review each CVE finding and its CVSS score",
            "# 2. For Vault CVEs: upgrade to the latest patched version",
            "vault version",
            "# https://developer.hashicorp.com/vault/docs/release-notes",
            "# 3. For configuration-based CVEs: apply hardening steps",
            "# 4. Re-scan after remediation to verify fixes",
        ],
        priority=1,
    )


@register_rule("sql injection", "CRITICAL")
def _fix_sql_injection_vault(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Patch Management",
        title="Patch Vault immediately — SQL injection vulnerability in Vault DB engine",
        root_cause=(
            "A SQL injection vulnerability was detected in the Vault database "
            "secrets engine. This can allow attackers to execute arbitrary SQL "
            "on the backend database via Vault API calls."
        ),
        fix_steps=[
            "# 1. Upgrade Vault to the latest version immediately:",
            "vault version  # check current",
            "# 2. Audit database roles for suspicious creation statements",
            "# 3. Restrict database role creation to trusted admins only",
            "# 4. Enable audit logging to detect exploitation attempts",
        ],
        priority=1,
    )


@register_rule("path traversal", "HIGH")
def _fix_path_traversal_vault(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Patch Management",
        title="Patch Vault — path traversal vulnerability detected",
        root_cause=(
            "A path traversal CVE was detected in the target Vault version. "
            "Attackers can read files outside the intended directory."
        ),
        fix_steps=[
            "# 1. Upgrade Vault to the latest patched version",
            "# 2. Verify no unauthorized file access in audit logs",
            "# 3. Restrict Vault process file system access via SELinux/AppArmor",
        ],
        priority=1,
    )


# ── Active Execution: Unseal Key Exfiltration ──────────────────────────


@register_rule("unseal keys discovered", "HIGH")
def _fix_unseal_key_discovery(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Seal / Unseal",
        title="Unseal keys exposed — rekey Vault immediately",
        root_cause=(
            "Unseal key material was discovered. Anyone with unseal keys can "
            "decrypt Vault's storage backend and access all secrets."
        ),
        fix_steps=[
            "# 1. IMMEDIATE: Rekey Vault with new unseal keys:",
            "vault operator rekey -init -key-shares=5 -key-threshold=3",
            "vault operator rekey  # for each unseal key holder",
            "# 2. Distribute new keys to trusted operators",
            "# 3. Implement auto-unseal to eliminate manual keys:",
            "seal \"awskms\" { kms_key_id = \"alias/vault-unseal\" }",
            "# 4. Verify old unseal keys are destroyed",
        ],
        priority=1,
    )


# ── Active Execution: Database Exploit ─────────────────────────────────


@register_rule("database exploit", "CRITICAL")
def _fix_db_exploit(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Database exploited via Vault — rotate all DB credentials",
        root_cause=(
            "A database exploit was successfully executed through Vault's "
            "database secrets engine. The database credentials generated by "
            "Vault were used to access and manipulate the backend database."
        ),
        fix_steps=[
            "# 1. Rotate the database admin password:",
            "ALTER USER vault_admin WITH PASSWORD '<new-password>';",
            "# 2. Update Vault DB config:",
            "vault write database/config/postgres-prod \\",
            "  password=<new-password>",
            "# 3. Revoke all dynamic credentials:",
            "vault lease revoke -prefix database/creds/",
            "# 4. Review and tighten DB role creation statements:",
            "vault read database/roles/<role>",
            "# 5. Use least-privilege GRANT statements in roles",
        ],
        priority=1,
    )


@register_rule("database pivot", "HIGH")
def _fix_db_pivot(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Database pivot attack successful — segment Vault from production databases",
        root_cause=(
            "The attacker pivoted from Vault to the backend database. "
            "Vault's database credentials were used for lateral movement."
        ),
        fix_steps=[
            "# 1. Isolate the database from Vault's network if possible",
            "# 2. Use firewall rules to restrict database access:",
            "#    Only allow Vault server IP on database port",
            "# 3. Implement network segmentation (Vault in mgmt VPC, DB in data VPC)",
            "# 4. Monitor for unusual database connection patterns",
        ],
        priority=2,
    )


# ── Active Execution: Cloud Exploit ────────────────────────────────────


@register_rule("cloud exploit", "CRITICAL")
def _fix_cloud_exploit(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Cloud IAM keys compromised via Vault — deactivate and rotate",
        root_cause=(
            "Cloud IAM credentials (AWS/Azure/GCP) were exfiltrated through "
            "Vault's cloud secrets engines. These keys grant direct access "
            "to cloud resources."
        ),
        fix_steps=[
            "# 1. IMMEDIATE: Deactivate compromised cloud keys:",
            "# AWS:",
            "aws iam update-access-key --access-key-id <KEY> --status Inactive",
            "# Azure:",
            "az ad app credential reset --id <app-id>",
            "# GCP:",
            "gcloud iam service-accounts keys delete <key-id>",
            "# 2. Review cloud audit logs (CloudTrail, Azure Monitor)",
            "# 3. Rotate all cloud secret engine configs in Vault",
            "# 4. Implement short TTLs for cloud credentials (max 1h)",
        ],
        priority=1,
    )


# ── Active Execution: Reverse Shell ────────────────────────────────────


@register_rule("reverse shell", "CRITICAL")
def _fix_reverse_shell(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="General Security",
        title="Reverse shell detected — incident response required",
        root_cause=(
            "A reverse shell was launched from the Vault server. The system "
            "is actively compromised. This is an INCIDENT, not just a finding."
        ),
        fix_steps=[
            "# 1. ISOLATE THE COMPROMISED SYSTEM IMMEDIATELY",
            "# 2. Initiate incident response procedures",
            "# 3. Collect forensic evidence (audit logs, network captures)",
            "# 4. Revoke ALL Vault tokens",
            "# 5. Rekey Vault and rotate all secrets",
            "# 6. Rebuild the compromised system from scratch",
        ],
        priority=1,
    )


# ── Active Execution: Unauthenticated Attack ───────────────────────────


@register_rule("tokensiz kesif", "HIGH")
def _fix_unauthenticated_attack(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Information Disclosure",
        title="Unauthenticated reconnaissance was successful — reduce attack surface",
        root_cause=(
            "The tool successfully enumerated Vault endpoints, auth methods, "
            "and configuration details without authentication. This information "
            "aids attackers in planning targeted exploits."
        ),
        fix_steps=[
            "# 1. Block unauthenticated access to sys/health and sys/seal-status:",
            "# Use reverse proxy (nginx):",
            "location ~ ^/v1/sys/(health|seal-status|internal) { deny all; }",
            "# 2. Disable Vault UI if not needed:",
            'ui = false  # in config.hcl',
            "# 3. Implement IP allow-listing for Vault API",
        ],
        priority=2,
    )


# ── Database Credential Harvest ────────────────────────────────────────


@register_rule("database credentials harvested", "CRITICAL")
def _fix_db_creds_harvest(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Secrets Management",
        title="Database credentials harvested — rotate and use dynamic secrets properly",
        root_cause=(
            "An attacker was able to harvest database credentials through "
            "Vault's database secrets engine. This provides direct database "
            "access with the role's privileges."
        ),
        fix_steps=[
            "# 1. Revoke all active database leases:",
            "vault lease revoke -prefix database/creds/",
            "# 2. Review database roles and tighten GRANT statements",
            "# 3. Set appropriate TTLs:",
            "vault write database/roles/<role> default_ttl=15m max_ttl=1h",
            "# 4. Implement credential rotation policies",
        ],
        priority=1,
    )


# ── Privilege Escalation (Active) ──────────────────────────────────────


@register_rule("full takeover", "CRITICAL")
def _fix_full_takeover(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="FULL TAKEOVER possible — wildcard policy management must be eliminated",
        root_cause=(
            "The token can create or modify policies with wildcard capabilities. "
            "This enables complete Vault takeover by creating a root-equivalent "
            "policy and assigning it to a token."
        ),
        fix_steps=[
            "# 1. IMMEDIATE: Remove policy create/update from non-root tokens",
            "# 2. Audit all existing policies for unauthorized modifications",
            "vault policy list",
            "vault policy read <each-policy>",
            "# 3. Remove any backdoor policies:",
            "# Look for policies with root-equivalent permissions",
            "# 4. Implement policy-as-code with code review requirements",
            "# 5. Enable Sentinel/OPA policy governance (Vault Enterprise)",
        ],
        priority=1,
    )


@register_rule("root-equivalent", "CRITICAL")
def _fix_root_equivalent(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Root-equivalent policy created — immediate revocation required",
        root_cause=(
            "A policy granting root-equivalent access (wildcard paths with "
            "all capabilities) was created. This gives unrestricted Vault access."
        ),
        fix_steps=[
            "# 1. Identify and delete the malicious policy:",
            "vault policy delete <backdoor-policy>",
            "# 2. Revoke all tokens with that policy:",
            "vault token revoke <token>",
            "# 3. Audit who created the policy",
            "# 4. Implement alerts for policy creation events",
        ],
        priority=1,
    )


# ── Default / catch-all (must be last) ─────────────────────────────────


@register_rule("root capability", "CRITICAL")
def _fix_root_capability(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Remove root capabilities from non-administrative tokens",
        root_cause=(
            "A non-root token has root-level capability on Vault paths. "
            "This is functionally equivalent to having the root token."
        ),
        fix_steps=[
            "# 1. Identify which policy grants root capability:",
            "vault policy list",
            "# 2. Replace 'root' with explicit capabilities:",
            '# BEFORE: path "sys/*" { capabilities = ["root"] }',
            '# AFTER:  path "sys/mounts" { capabilities = ["read","list"] }',
            "# 3. Update the policy:",
            "vault policy write <policy> <fixed>.hcl",
        ],
        priority=1,
    )


@register_rule("non-expiring token", "HIGH")
def _fix_non_expiring_token(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Token Management",
        title="Replace non-expiring tokens with short-lived, auto-rotated tokens",
        root_cause=(
            "A token with no expiration (TTL=0) was detected. Non-expiring "
            "tokens grant permanent access unless manually revoked."
        ),
        fix_steps=[
            "# 1. Revoke the non-expiring token:",
            "vault token revoke <token>",
            "# 2. Set max_lease_ttl on the auth mount:",
            "vault auth tune -max-lease-ttl=720h token/",
            "# 3. Create tokens with explicit TTLs:",
            "vault token create -policy=<policy> -ttl=24h",
            "# 4. Use Vault Agent for automatic token refresh",
        ],
        priority=1,
    )


@register_rule("over-privileged token", "HIGH")
def _fix_over_privileged_token(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Reduce over-privileged token capabilities to least privilege",
        root_cause=(
            "The token has more capabilities than needed for its function. "
            "Over-privileged tokens increase blast radius if compromised."
        ),
        fix_steps=[
            "# 1. Audit what the application actually needs:",
            "vault read sys/internal/counters/tokens",
            "# 2. Create a scoped policy with only required paths:",
            'path "secret/data/app/*" { capabilities = ["read"] }',
            "# 3. Reissue the token with the scoped policy:",
            "vault token create -policy=scoped-app -ttl=24h",
            "# 4. Revoke the old over-privileged token",
        ],
        priority=2,
    )


@register_rule("vault_token found", "HIGH")
def _fix_vault_token_env(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Remove Vault token from environment variables",
        root_cause=(
            "VAULT_TOKEN was found in environment variables. Tokens in "
            "environment variables can be leaked via process listing, "
            "crash dumps, CI logs, or child process inheritance."
        ),
        fix_steps=[
            "# 1. Unset the variable:",
            "unset VAULT_TOKEN",
            "# 2. Use Vault Agent with auto-auth instead:",
            "vault agent -config=agent.hcl",
            "# 3. For CI/CD, use short-lived wrapped tokens:",
            "vault write -wrap-ttl=300s -f auth/approle/login",
        ],
        priority=2,
    )


@register_rule("vault token", "HIGH")
def _fix_token_exposure(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Potential Vault token found — verify and revoke if valid",
        root_cause=(
            "A potential Vault token pattern (hvs./hvb.) was detected in files. "
            "Even if it appears to be a placeholder, verify immediately."
        ),
        fix_steps=[
            "# 1. Try to look up the token to verify:",
            "vault token lookup <token>",
            "# 2. If valid, revoke immediately:",
            "vault token revoke <token>",
            "# 3. Remove from files and git history",
            "# 4. Implement pre-commit scanning for Vault token patterns",
        ],
        priority=1,
    )


@register_rule("vault-token file found", "HIGH")
def _fix_dot_vault_token(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="Remove ~/.vault-token file — use secure token storage",
        root_cause=(
            "A ~/.vault-token file stores Vault tokens in plaintext on disk. "
            "Any process or user with filesystem access can steal the token."
        ),
        fix_steps=[
            "# 1. Delete the file:",
            "rm ~/.vault-token",
            "# 2. Use a token helper:",
            "vault token helper enable",
            "# 3. Or authenticate per session:",
            "vault login -method=oidc",
        ],
        priority=2,
    )


@register_rule("long-lived token", "MEDIUM")
def _fix_long_lived_token(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Token Management",
        title="Reduce token TTL to production-safe values",
        root_cause=(
            "A token with excessively long TTL was detected. Long-lived "
            "tokens increase the window of opportunity for attackers."
        ),
        fix_steps=[
            "# 1. Set shorter TTLs on auth mounts:",
            "vault auth tune -default-lease-ttl=1h -max-lease-ttl=24h token/",
            "# 2. Create tokens with short TTL:",
            "vault token create -policy=<policy> -ttl=4h",
        ],
        priority=3,
    )


@register_rule("approle credential pair", "CRITICAL")
def _fix_approle_pair_discovered(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Credential Leaks",
        title="AppRole credentials discovered — rotate immediately",
        root_cause=(
            "Both role_id and secret_id were found together. This allows "
            "anyone with these credentials to authenticate to Vault and "
            "obtain tokens with the role's policies."
        ),
        fix_steps=[
            "# 1. Destroy the leaked secret_id immediately:",
            "vault write auth/approle/role/<role>/secret-id/destroy \\",
            "  secret_id=<leaked-secret-id>",
            "# 2. Generate new secret_id with tight constraints:",
            "vault write -f auth/approle/role/<role>/secret-id \\",
            "  secret_id_num_uses=1 secret_id_ttl=5m",
            "# 3. Rotate role_id if also exposed:",
            "vault write auth/approle/role/<role>/role-id",
        ],
        priority=1,
    )


@register_rule("reverse proxy", "LOW")
def _fix_reverse_proxy_header(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Information Disclosure",
        title="Suppress reverse proxy server header",
        root_cause=(
            "The reverse proxy reveals its identity via Server header. "
            "This helps attackers fingerprint the infrastructure stack."
        ),
        fix_steps=[
            "# nginx:",
            "server_tokens off;",
            "more_clear_headers 'Server';",
            "# HAProxy:",
            "http-response del-header Server",
        ],
        priority=5,
    )


@register_rule("missing strict-transport", "LOW")
def _fix_hsts_header(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="TLS",
        title="Add HSTS and security headers to Vault responses",
        root_cause=(
            "Security headers (HSTS, X-Content-Type-Options, X-Frame-Options, "
            "CSP) are missing from Vault responses. These headers protect "
            "against common web attacks."
        ),
        fix_steps=[
            "# Add via reverse proxy (recommended):",
            "# nginx:",
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
            "add_header X-Content-Type-Options 'nosniff' always;",
            "add_header X-Frame-Options 'DENY' always;",
            "add_header Content-Security-Policy \"default-src 'self'\" always;",
            "add_header Referrer-Policy 'no-referrer' always;",
            "# Or use Vault's custom response headers (1.12+):",
            "vault write sys/config/ui/headers/Custom-Response-Headers \\",
            '  value="Strict-Transport-Security: max-age=31536000"',
        ],
        priority=4,
    )


@register_rule("many policies", "MEDIUM")
def _fix_many_policies(f: dict) -> RemediationAdvice:
    return RemediationAdvice(
        category="Policy / ACL",
        title="Reduce number of attached policies — consolidate to least privilege",
        root_cause=(
            "A token has many policies attached. Multiple overlapping policies "
            "make it difficult to audit effective permissions and may grant "
            "unintended access."
        ),
        fix_steps=[
            "# 1. Review effective permissions:",
            "vault read sys/internal/ui/resultant-acl",
            "# 2. Consolidate into a single well-scoped policy",
            "# 3. Reissue token with consolidated policy",
            "# 4. Delete unused policies",
        ],
        priority=3,
    )


# ── Last resort catch-all ─────────────────────────────────────────────


@register_rule("", "INFO")
def _fix_generic(f: dict) -> RemediationAdvice:
    """Catch-all: produce a basic remediation hint for any unclassified finding."""
    sev = f.get("severity", "INFO")
    title = f.get("title", "")
    desc = f.get("description", "")
    evidence = f.get("evidence", "")

    priority_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    priority = priority_map.get(sev, 5)

    steps = [
        "# Review this finding in the context of your Vault deployment.",
        "# Check the official Vault documentation for best practices:",
        "#   https://developer.hashicorp.com/vault/docs",
    ]
    if evidence:
        steps.append(f"# Evidence: {evidence[:120]}")

    return RemediationAdvice(
        category="General Security",
        title=title or "Unclassified finding",
        root_cause=desc or "No detailed root cause available — manual review recommended.",
        fix_steps=steps,
        priority=priority,
    )
