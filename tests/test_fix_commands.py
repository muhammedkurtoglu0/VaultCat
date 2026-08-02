"""Tests for core.fix_commands — Vault CLI fix-command generator."""

import pytest

from core.fix_commands import get_fix_commands, _extract_policy_name


class TestGetFixCommands:
    """Tests for the main get_fix_commands function."""

    # ── Policy fixes ────────────────────────────────────────────────────

    def test_policy_sudo_triggers_fix(self):
        finding = {
            "title": "Token has sudo on wildcard policy",
            "description": "The token can manage ACL policies with sudo.",
            "module": "capability_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("policy list" in c or "policy read" in c for c in cmds)

    def test_policy_with_name_in_evidence(self):
        finding = {
            "title": "Wildcard policy found",
            "module": "policy_auditor",
            "evidence": {"policy_name": "admin-policy"},
        }
        cmds = get_fix_commands(finding)
        assert any("admin-policy" in c for c in cmds)

    def test_root_policy_triggers_audit(self):
        finding = {
            "title": "Root-equivalent policy detected",
            "module": "policy_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("vault policy list" in c for c in cmds)

    # ── Token fixes ─────────────────────────────────────────────────────

    def test_token_ttl_expiry_fix(self):
        finding = {
            "title": "Token with no TTL",
            "description": "Token never expires.",
            "module": "ttl_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("ttl=" in c for c in cmds)

    def test_generic_token_audit(self):
        finding = {
            "title": "Suspicious token activity",
            "module": "capability_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("token revoke" in c.lower() or "token" in c.lower() for c in cmds)

    # ── TLS fixes ───────────────────────────────────────────────────────

    def test_self_signed_cert_fix(self):
        finding = {
            "title": "Self-signed TLS certificate",
            "description": "Vault uses a self-signed certificate.",
            "module": "tls_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("self-signed" in c.lower() or "CA-signed" in c for c in cmds)

    def test_http_without_https(self):
        finding = {
            "title": "Vault running on HTTP",
            "description": "TLS is not enabled.",
            "module": "tls_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("tls_disable" in c.lower() or "Enable HTTPS" in c for c in cmds)

    # ── CORS fixes ──────────────────────────────────────────────────────

    def test_cors_misconfiguration_fix(self):
        finding = {
            "title": "CORS allows all origins",
            "module": "cors_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("allowed_origins" in c for c in cmds)

    # ── Auth method fixes ───────────────────────────────────────────────

    def test_approle_bind_secret_fix(self):
        finding = {
            "title": "AppRole bind_secret_id disabled",
            "description": "AppRole allows login without secret_id.",
            "module": "approle_exploit",
        }
        cmds = get_fix_commands(finding)
        assert any("bind_secret_id=true" in c for c in cmds)

    def test_userpass_fix(self):
        finding = {"title": "Weak userpass password", "module": "auth_config_scanner"}
        cmds = get_fix_commands(finding)
        assert any("userpass" in c.lower() for c in cmds)

    def test_generic_auth_disable(self):
        finding = {"title": "Unused auth method enabled", "module": "auth_config_scanner"}
        cmds = get_fix_commands(finding)
        assert any("auth disable" in c or "auth list" in c for c in cmds)

    # ── Database fixes ──────────────────────────────────────────────────

    def test_database_credential_harvest_fix(self):
        finding = {
            "title": "Database credentials harvested",
            "description": "Dynamic credentials were generated.",
            "module": "database_credential_harvest",
        }
        cmds = get_fix_commands(finding)
        assert any("rotate-root" in c or "database/config" in c for c in cmds)

    def test_database_superuser_fix(self):
        finding = {
            "title": "DB role with GRANT ALL",
            "description": "The role grants ALL PRIVILEGES on the database, giving full access.",
            "module": "database_credential_harvest",
        }
        cmds = get_fix_commands(finding)
        assert any("GRANT SELECT" in c or "least-privilege" in c for c in cmds)

    def test_database_ttl_fix(self):
        finding = {
            "title": "Database role TTL too long",
            "description": "max_ttl is set to 7 days.",
            "module": "database_credential_harvest",
        }
        cmds = get_fix_commands(finding)
        assert any("default_ttl" in c or "max_ttl" in c for c in cmds)

    # ── Audit fixes ─────────────────────────────────────────────────────

    def test_audit_backdoor_fix(self):
        finding = {
            "title": "Audit Backdoor - Disable Audit Devices",
            "description": "Audit devices were disabled.",
            "module": "audit_backdoor",
        }
        cmds = get_fix_commands(finding)
        assert any("audit enable" in c for c in cmds)

    def test_audit_generic_fix(self):
        finding = {"title": "No audit devices enabled", "module": "audit_backdoor"}
        cmds = get_fix_commands(finding)
        assert any("audit enable" in c for c in cmds)

    # ── Version/CVE fixes ───────────────────────────────────────────────

    def test_cve_version_fix(self):
        finding = {
            "title": "Vault version 1.15.3 affected by CVE-2023-6337",
            "module": "version_risk_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("Upgrade Vault" in c or "systemctl" in c for c in cmds)

    # ── Network fixes ───────────────────────────────────────────────────

    def test_cluster_port_open_fix(self):
        finding = {
            "title": "Vault cluster port exposed",
            "description": "Port 8201 is open to external traffic.",
            "module": "network_probe",
        }
        cmds = get_fix_commands(finding)
        assert any("8201" in c or "DROP" in c for c in cmds)

    # ── Security headers ────────────────────────────────────────────────

    def test_security_headers_fix(self):
        finding = {
            "title": "Missing security headers",
            "description": "HSTS header not set.",
            "module": "header_scanner",
        }
        cmds = get_fix_commands(finding)
        assert any("Strict-Transport-Security" in c or "X-Frame" in c for c in cmds)

    # ── Rate limiting ───────────────────────────────────────────────────

    def test_rate_limit_fix(self):
        finding = {
            "title": "No rate limiting detected",
            "description": "brute-force attacks possible",
            "module": "network_probe",
        }
        cmds = get_fix_commands(finding)
        assert any("quotas" in c or "rate-limit" in c for c in cmds)

    # ── Fallback ────────────────────────────────────────────────────────

    def test_pass_finding_returns_fallback(self):
        finding = {
            "title": "HTTPS enabled",
            "description": "The target uses HTTPS.",
            "severity": "PASS",
            "module": "tls_scanner",
        }
        cmds = get_fix_commands(finding)
        assert len(cmds) == 1
        assert "manually" in cmds[0].lower()


class TestExtractPolicyName:
    """Tests for the _extract_policy_name helper."""

    def test_dict_evidence_policy_name(self):
        assert _extract_policy_name({"policy_name": "admin-backdoor"}) == "admin-backdoor"

    def test_dict_evidence_policy_key(self):
        assert _extract_policy_name({"policy": "my-policy"}) == "my-policy"

    def test_dict_evidence_backdoor_policy(self):
        assert _extract_policy_name({"backdoor_policy": "hidden"}) == "hidden"

    def test_json_string_evidence(self):
        assert _extract_policy_name('{"policy_name": "from-json"}') == "from-json"

    def test_none_evidence(self):
        assert _extract_policy_name(None) is None

    def test_empty_string_evidence(self):
        assert _extract_policy_name("") is None

    def test_plain_string_evidence(self):
        # Plain string — no policy name extractable
        assert _extract_policy_name("some evidence text") is None
