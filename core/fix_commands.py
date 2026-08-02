"""Vault CLI fix-command generator — maps finding patterns to concrete commands.

Each function returns a list of Vault CLI commands that address a specific
finding category.  Used by the PDF report to show actionable fixes alongside
every finding.

Usage::

    from core.fix_commands import get_fix_commands
    cmds = get_fix_commands(finding)
    for cmd in cmds:
        logger.info(f"  vault {cmd}")
"""

from __future__ import annotations

from typing import Optional
from core.logger import logger


def get_fix_commands(finding: dict) -> list[str]:
    """Return a list of ``vault ...`` CLI commands that fix *finding*.

    Returns an empty list when no concrete command can be generated (e.g.
    informational findings or pass results).
    """
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    mod = (finding.get("module") or "").lower()
    evidence = finding.get("evidence", "")

    cmds: list[str] = []

    # ── Policy-related fixes ────────────────────────────────────────────
    if "policy" in mod or "policy" in title or "sudo" in desc or "wildcard" in title:
        if _extract_policy_name(evidence):
            pname = _extract_policy_name(evidence)
            cmds.append(f'policy write {pname} -<<EOF\npath "*" {{\n  capabilities = ["read", "list"]\n}}\nEOF')
        else:
            cmds.append('policy list   # audit all policies first')
            cmds.append('# Then tighten each policy with: vault policy write <name> <file.hcl>')

    if "sudo" in title or "sudo" in desc:
        cmds.append('# Remove sudo capability from any policy that does not need it')
        cmds.append('vault policy read <policy-name>  # audit for "sudo" keywords')

    if "root" in title and "policy" in title:
        cmds.append('# Audit all root-equivalent policies and restrict to least privilege')
        cmds.append('vault policy list')
        cmds.append('vault policy read <each-policy>')

    # ── Token-related fixes ─────────────────────────────────────────────
    if "token" in mod or "token" in title:
        if "expir" in title or "ttl" in title or "no ttl" in desc or "never expir" in desc:
            cmds.append('vault write auth/token/roles/<role> ttl=30d max_ttl=90d')
            cmds.append('vault token revoke <token-accessor>')
        elif "orphan" in desc and "root" not in title:
            cmds.append('vault token revoke <orphan-token-accessor>')
        elif "display" in title or "no display" in desc:
            cmds.append('vault write auth/token/create display-name="audit-purpose" ttl=8h')
        else:
            cmds.append('vault list auth/token/accessors  # audit all active tokens')
            cmds.append('vault token revoke <suspicious-accessor>')

    # ── TLS / HTTPS fixes ───────────────────────────────────────────────
    if "tls" in mod or "tls" in title or "ssl" in title:
        if "self" in title or "self-signed" in desc:
            cmds.append('# Replace self-signed cert with CA-signed certificate')
            cmds.append('# Update Vault config listener block with new cert paths:')
            cmds.append('#   tls_cert_file = "/path/to/cert.pem"')
            cmds.append('#   tls_key_file  = "/path/to/key.pem"')
        if "http" in title and "https" not in title:
            cmds.append('# Enable HTTPS in Vault config:')
            cmds.append('# listener "tcp" { tls_disable = false }')

    # ── CORS fixes ──────────────────────────────────────────────────────
    if "cors" in mod or "cors" in title:
        cmds.append('vault write sys/config/cors allowed_origins="https://trusted.example.com" allowed_headers="X-Custom-Header"')

    # ── Auth method fixes ───────────────────────────────────────────────
    if "auth" in mod or "authentication" in mod or "approle" in mod or "userpass" in mod:
        if "approle" in title.lower() or "bind_secret" in desc:
            cmds.append('vault write auth/approle/role/<role> bind_secret_id=true secret_id_num_uses=0')
        elif "userpass" in title.lower():
            cmds.append('vault write auth/userpass/users/<user> password="<new-strong-password>"')
        elif "kubernetes" in title.lower() or "k8s" in desc:
            cmds.append('vault write auth/kubernetes/config token_reviewer_jwt="<reviewer-jwt>" kubernetes_host="https://<k8s-api>:443"')
        elif "ldap" in title.lower():
            cmds.append('vault write auth/ldap/config url="ldaps://<dc>:636" userdn="ou=users,dc=example,dc=com"')
        else:
            cmds.append('vault auth list  # audit enabled auth methods')
            cmds.append('vault auth disable <unused-method>')

    # ── Secrets engine fixes ────────────────────────────────────────────
    if "kv" in mod or "secret" in mod or "kv" in title:
        cmds.append('vault secrets enable -version=2 kv')
        cmds.append('vault kv put secret/<path> key="value"')
        if "version" in desc and "1" in desc:
            cmds.append('vault secrets tune -version=2 kv/    # upgrade from KV v1 to v2')

    # ── Database engine fixes ───────────────────────────────────────────
    if "database" in mod or "db" in mod:
        if "creds" in title or "credential" in title or "harvest" in desc:
            cmds.append('vault write database/config/<name> plugin_name="postgresql-database-plugin" allowed_roles="<role>" connection_url="postgresql://{{username}}:{{password}}@<host>:5432/<db>?sslmode=require" root_credentials_rotate_statements=\'ALTER USER "{{username}}" WITH PASSWORD \'\\\'\'{{password}}\'\\\'\';\'')
            cmds.append('# Rotate root credentials immediately:')
            cmds.append('vault write -force database/rotate-root/<name>')
        if "privilege" in desc or "grant all" in desc or "superuser" in desc:
            cmds.append('# Replace GRANT ALL with least-privilege grants:')
            cmds.append('vault write database/roles/<role> db_name=<name> creation_statements=\'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'\\\'\'{{password}}\'\\\'\' VALID UNTIL \'\\\'\'{{expiration}}\'\\\'\'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";\' default_ttl=1h max_ttl=4h')
        elif "ttl" in desc or "max_ttl" in desc:
            cmds.append('vault write database/roles/<role> default_ttl=1h max_ttl=4h')

    # ── Audit / logging fixes ───────────────────────────────────────────
    if "audit" in mod or "audit" in title:
        if "disable" in desc or "backdoor" in title:
            cmds.append('vault audit enable file file_path=/vault/logs/audit.log')
            cmds.append('vault audit list  # verify audit devices are active')
        else:
            cmds.append('vault audit enable file file_path=/vault/logs/audit.log')
            cmds.append('vault audit enable socket address=127.0.0.1:8200 socket_type=tcp')

    # ── Version / CVE fixes ─────────────────────────────────────────────
    if "version" in mod or "cve" in mod or "version" in title:
        cmds.append('# Upgrade Vault to the latest patched version:')
        cmds.append('# 1. Stop Vault: systemctl stop vault')
        cmds.append('# 2. Backup: cp -r /vault/data /vault/data.backup')
        cmds.append('# 3. Upgrade binary + restart')

    # ── Network / deployment fixes ──────────────────────────────────────
    if "network" in mod or "network" in title or "port" in desc:
        if "8201" in desc or "cluster" in title:
            cmds.append('# Close cluster port to external access:')
            cmds.append('# iptables -A INPUT -p tcp --dport 8201 -j DROP')
        if "80" in desc or "http" in title:
            cmds.append('# Disable plain HTTP listener in Vault config')

    # ── Rate limiting fixes ─────────────────────────────────────────────
    if "rate" in desc or "limit" in desc or "brute" in desc:
        cmds.append('# Enable rate limiting in Vault:')
        cmds.append('vault write sys/quotas/rate-limit/rl-rate path="*" rate=100 interval=1s')

    # ── Generic hardening (always applicable) ────────────────────────────
    if "header" in mod or "security" in mod or "hsts" in desc or "x-frame" in desc:
        cmds.append('# Add security headers via reverse proxy (nginx):')
        cmds.append('# add_header Strict-Transport-Security "max-age=31536000";')
        cmds.append('# add_header X-Frame-Options "DENY";')
        cmds.append('# add_header X-Content-Type-Options "nosniff";')

    # ── Fallback: no fix command generated ──────────────────────────────
    if not cmds:
        cmds.append("# Review finding manually — no automated fix command available")

    return cmds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_policy_name(evidence) -> Optional[str]:
    """Try to pull a policy name from evidence (dict, JSON string, or plain str)."""
    import json as _json

    if not evidence:
        return None
    if isinstance(evidence, dict):
        return evidence.get("policy_name") or evidence.get("policy") or evidence.get("backdoor_policy")
    if isinstance(evidence, str):
        if evidence.startswith("{"):
            try:
                d = _json.loads(evidence)
                return d.get("policy_name") or d.get("policy") or d.get("backdoor_policy")
            except (_json.JSONDecodeError, TypeError):
                pass
    return None
