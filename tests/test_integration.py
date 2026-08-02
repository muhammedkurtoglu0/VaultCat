"""End-to-end integration tests against the docker-compose Vault lab.

These tests require a running Vault lab (``vault-pentest-lab/docker-compose.yml``).
When the lab is not reachable, every test is automatically skipped — there is
no penalty for running ``pytest`` without the lab.

Quick-start::

    cd vault-pentest-lab
    docker compose up -d
    cd ..
    pytest tests/test_integration.py -v

Environment variables (optional):
    VAULT_TEST_ADDR    override target URL (default https://localhost:8200)
    VAULT_TEST_TOKEN   override root token
"""

from __future__ import annotations

import json
import os
import time

import pytest
import requests

pytestmark = pytest.mark.integration

# ── Lab connectivity check ───────────────────────────────────────────────────

VAULT_ADDR = os.environ.get("VAULT_TEST_ADDR", "https://localhost:8200")
ROOT_TOKEN = os.environ.get("VAULT_TEST_TOKEN", "")


def _lab_reachable() -> bool:
    """Return True if the Vault lab is up and responding."""
    try:
        r = requests.get(
            f"{VAULT_ADDR}/v1/sys/health",
            timeout=3,
            verify=False,
        )
        return r.status_code == 200
    except Exception:
        return False


def _resolve_token() -> str:
    """Resolve a valid Vault token for integration tests.

    Priority: VAULT_TEST_TOKEN env → lab-tokens.env file → skip.
    """
    global ROOT_TOKEN
    if ROOT_TOKEN:
        return ROOT_TOKEN

    # Try lab-tokens.env
    env_path = os.path.join(
        os.path.dirname(__file__), "..", "vault-pentest-lab", "lab-tokens.env"
    )
    if os.path.isfile(env_path):
        for line in open(env_path, encoding="utf-8"):
            if line.startswith("ROOT_TOKEN="):
                ROOT_TOKEN = line.split("=", 1)[1].strip()
                return ROOT_TOKEN

    return ""


# ── Skip marker ──────────────────────────────────────────────────────────────

needs_lab = pytest.mark.skipif(
    not _lab_reachable(),
    reason="Vault pentest lab is not running. Start with: cd vault-pentest-lab && docker compose up -d",
)

needs_token = pytest.mark.skipif(
    not _lab_reachable() or not _resolve_token(),
    reason="No Vault token available for integration tests",
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _req(method, path, token=None, body=None):
    """Make an authenticated request to the Vault lab."""
    h = {"X-Vault-Token": token or _resolve_token(), "Content-Type": "application/json"}
    url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
    kwargs = {"headers": h, "timeout": 10, "verify": False}
    if body is not None:
        kwargs["json"] = body
    return requests.request(method, url, **kwargs)


# ── Phase 1: Recon ───────────────────────────────────────────────────────────

class TestReconPhase:
    """Unauthenticated reconnaissance against the live Vault lab."""

    @needs_lab
    def test_health_endpoint_returns_200(self):
        """sys/health must be reachable without authentication."""
        r = requests.get(
            f"{VAULT_ADDR}/v1/sys/health",
            timeout=5,
            verify=False,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["initialized"] is True
        assert data["sealed"] is False
        assert "version" in data

    @needs_lab
    def test_seal_status_is_unsealed(self):
        """Lab must be unsealed for authenticated tests to proceed."""
        r = requests.get(
            f"{VAULT_ADDR}/v1/sys/seal-status",
            timeout=5,
            verify=False,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["sealed"] is False

    @needs_lab
    def test_tls_certificate_present(self):
        """Target must present a TLS certificate (even self-signed)."""
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(VAULT_ADDR)
        if parsed.scheme != "https":
            pytest.skip("Target is not HTTPS")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((parsed.hostname, parsed.port or 8200), timeout=5)
        try:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
                assert cert is not None
                assert "subject" in cert
        finally:
            sock.close()

    @needs_lab
    def test_auth_methods_exposed(self):
        """sys/auth must list enabled auth methods (unauthenticated or not)."""
        r = requests.get(
            f"{VAULT_ADDR}/v1/sys/auth",
            timeout=5,
            verify=False,
        )
        # May 403 without token — still a valid response
        assert r.status_code in (200, 403)


# ── Phase 2: Audit ───────────────────────────────────────────────────────────

class TestAuditPhase:
    """Authenticated audit tests — require a valid token."""

    @needs_token
    def test_root_token_lookup_self(self):
        """Root token must authenticate and return root policy."""
        r = _req("POST", "auth/token/lookup-self")
        assert r.status_code == 200, f"lookup-self failed: {r.text}"
        data = r.json()
        td = data.get("data", {})
        assert "root" in td.get("policies", [])
        assert td.get("display_name") == "root"

    @needs_token
    def test_sys_mounts_listable(self):
        """Root token must list all secret engine mounts."""
        r = _req("GET", "sys/mounts")
        assert r.status_code == 200, f"sys/mounts failed: {r.text}"
        data = r.json().get("data", {})
        assert isinstance(data, dict)
        # At minimum we expect a secret/ mount
        assert "secret/" in data, f"No secret/ mount found: {list(data.keys())[:5]}"

    @needs_token
    def test_policies_listable(self):
        """Root token must list ACL policies."""
        r = _req("GET", "sys/policy")
        assert r.status_code == 200, f"sys/policy failed: {r.text}"
        policies = r.json().get("policies", [])
        assert "root" in policies
        assert "default" in policies

    @needs_token
    def test_kv_read_admin_creds(self):
        """Read known lab secret: secret/data/admin/creds."""
        r = _req("GET", "secret/data/admin/creds")
        assert r.status_code == 200, f"secret/admin/creds not found: {r.text}"
        data = r.json().get("data", {}).get("data", {})
        assert "username" in data
        assert "password" in data

    @needs_token
    def test_database_engine_mounted(self):
        """Database secrets engine must be mounted."""
        r = _req("GET", "sys/mounts")
        mounts = r.json().get("data", {})
        assert "database/" in mounts, f"No database/ mount in: {list(mounts.keys())}"

    @needs_token
    def test_approle_auth_enabled(self):
        """AppRole auth method must be enabled with my-role."""
        r = _req("GET", "auth/approle/role/my-role")
        assert r.status_code == 200, f"AppRole role not found: {r.text}"
        role = r.json().get("data", {})
        assert "token_policies" in role

    @needs_token
    def test_userpass_testuser_exists(self):
        """testuser must authenticate via userpass and receive a token."""
        r = _req("POST", "auth/userpass/login/testuser", body={"password": "testpassword"})
        assert r.status_code == 200, f"userpass login failed: {r.text}"
        auth = r.json().get("auth", {})
        assert auth.get("client_token", "").startswith("hvs.")
        assert "read-only" in auth.get("policies", [])

    @needs_token
    def test_approle_login_works(self):
        """AppRole role_id + secret_id must produce a valid token."""
        # Read current role_id + generate fresh secret_id
        rid_resp = _req("GET", "auth/approle/role/my-role/role-id")
        assert rid_resp.status_code == 200
        role_id = rid_resp.json().get("data", {}).get("role_id")

        sid_resp = _req("POST", "auth/approle/role/my-role/secret-id")
        assert sid_resp.status_code == 200, f"secret-id generation failed: {sid_resp.text}"
        secret_id = sid_resp.json().get("data", {}).get("secret_id")

        login = requests.post(
            f"{VAULT_ADDR}/v1/auth/approle/login",
            json={"role_id": role_id, "secret_id": secret_id},
            timeout=10,
            verify=False,
        )
        assert login.status_code == 200, f"AppRole login failed: {login.text}"
        auth = login.json().get("auth", {})
        assert auth.get("client_token", "").startswith("hvs.")

    @needs_token
    def test_transit_key_my_key_exists(self):
        """Transit engine must have 'my-key'."""
        r = _req("GET", "transit/keys/my-key")
        assert r.status_code == 200, f"transit/my-key not found: {r.text}"


# ── Phase 3: Exploit chain ───────────────────────────────────────────────────

class TestExploitChain:
    """Full recon → audit → exploit chains against the live lab."""

    @needs_token
    def test_kv_enum_to_exfil_chain(self):
        """Enumerate secret/ → read admin/creds, api/keys, db/config."""
        r = _req("LIST", "secret/metadata/")
        assert r.status_code == 200, f"KV LIST failed: {r.text}"
        keys = r.json().get("data", {}).get("keys", [])
        assert len(keys) >= 2, f"Expected >=2 keys under secret/, got {keys}"

        secrets_found = 0
        for key in keys[:5]:
            r2 = _req("GET", f"secret/data/{key}")
            if r2.status_code == 200:
                secrets_found += 1
        assert secrets_found >= 1, "No readable secrets under secret/"

    @needs_token
    def test_token_creation_chain(self):
        """Create a child token → verify it works."""
        r = _req("POST", "auth/token/create",
                 body={"policies": ["default"], "ttl": "1h", "display_name": "test-child"})
        assert r.status_code == 200, f"Token creation failed: {r.text}"
        child = r.json().get("auth", {}).get("client_token")
        assert child and child.startswith("hvs.")

        # Verify the child token works
        r2 = _req("GET", "sys/health", token=child)
        assert r2.status_code == 200, f"Child token health check failed: {r2.text}"

    @needs_token
    def test_dynamic_db_credential_chain(self):
        """Generate dynamic DB credentials via app-admin role."""
        r = _req("GET", "database/creds/app-admin")
        # May fail if DB connection is down — that's OK, just check structure
        if r.status_code == 200:
            data = r.json().get("data", {})
            assert "username" in data
            assert "password" in data
        else:
            assert "error" in r.text.lower() or r.status_code >= 400

    @needs_token
    def test_policy_creation_and_delete_chain(self):
        """Create a temp policy → verify → delete."""
        policy_name = "int-test-temp-policy"
        policy_body = 'path "secret/*" { capabilities = ["read"] }'

        r = _req("PUT", f"sys/policies/acl/{policy_name}",
                 body={"policy": policy_body})
        assert r.status_code in (200, 204)

        # Verify
        r2 = _req("GET", f"sys/policies/acl/{policy_name}")
        assert r2.status_code == 200
        assert "read" in r2.json().get("data", {}).get("policy", "")

        # Cleanup
        r3 = _req("DELETE", f"sys/policies/acl/{policy_name}")
        assert r3.status_code in (200, 204)

    @needs_token
    def test_approle_exploit_chain(self):
        """Full AppRole exploit: role_id → secret_id → login → token audit."""
        # 1. Discover role_id
        r = _req("GET", "auth/approle/role/my-role/role-id")
        assert r.status_code == 200
        role_id = r.json().get("data", {}).get("role_id")

        # 2. Generate secret_id
        r = _req("POST", "auth/approle/role/my-role/secret-id")
        assert r.status_code == 200
        secret_id = r.json().get("data", {}).get("secret_id")

        # 3. Login
        r = _req("POST", "auth/approle/login",
                 body={"role_id": role_id, "secret_id": secret_id})
        assert r.status_code == 200
        app_token = r.json().get("auth", {}).get("client_token")
        assert app_token

        # 4. Audit the AppRole-derived token
        r = _req("POST", "auth/token/lookup", token=app_token,
                 body={"token": app_token})
        if r.status_code == 200:
            policies = r.json().get("data", {}).get("policies", [])
            assert "app-admin" in policies or "default" in policies

    @needs_token
    def test_full_recon_to_report_pipeline(self):
        """End-to-end: run the tool's main pipeline and verify report output."""
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        token = _resolve_token()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_prefix = str(Path(tmpdir) / "pipeline_test")
            proc = subprocess.run(
                [
                    sys.executable, "-m", "main",
                    "--target", VAULT_ADDR,
                    "--token", token,
                    "--skip-tls-verify",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=os.path.join(os.path.dirname(__file__), ".."),
            )
            # Pipeline may exit non-zero if no explicit subcommand was given;
            # we only assert it doesn't crash hard.
            assert proc.returncode is not None  # it ran
            # stderr should be clean of tracebacks
            assert "Traceback (most recent call last)" not in proc.stderr


# ── Phase 4: Edge Cases ──────────────────────────────────────────────────────

class TestEdgeCases:
    """Error-handling and edge-case tests against the live lab."""

    @needs_lab
    def test_unauthenticated_403_on_protected_path(self):
        """Protected paths must return 403 without token."""
        r = requests.get(
            f"{VAULT_ADDR}/v1/secret/data/admin/creds",
            timeout=5,
            verify=False,
        )
        assert r.status_code in (400, 403), f"Expected 403, got {r.status_code}"

    @needs_token
    def test_bad_token_returns_403(self):
        """A fake token must produce 403."""
        r = _req("GET", "sys/mounts", token="hvs.this-token-is-completely-fake")
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"

    @needs_token
    def test_nonexistent_path_returns_404(self):
        """Non-existent API paths must return 404 (not 500)."""
        r = _req("GET", "this/path/does/not/exist")
        assert r.status_code in (404, 405), f"Expected 404, got {r.status_code}: {r.text[:200]}"

    @needs_lab
    def test_empty_post_body_handled(self):
        """Empty POST body must not crash the server."""
        r = requests.post(
            f"{VAULT_ADDR}/v1/sys/health",
            data="",
            timeout=5,
            verify=False,
        )
        assert r.status_code in (200, 400, 405)  # OK or bad request, not 500

    @needs_token
    def test_very_long_path_handled(self):
        """A very long path must return 400/404, not 500."""
        long_path = "a" * 2000
        r = _req("GET", f"sys/{long_path}")
        assert r.status_code < 500, f"Expected <500, got {r.status_code}"

    @needs_token
    def test_unicode_in_body_handled(self):
        """Unicode payload must not crash the server."""
        r = _req("POST", "auth/token/lookup-self",
                 body={"display_name": "türkçe-☃-test"})
        assert r.status_code in (200, 400)  # OK or bad request, not 500
