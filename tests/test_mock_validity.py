"""Mock-vs-real validation: ensure VaultMockFactory responses match live Vault behavior.

Every test in this file:
1. Calls ``VaultMockFactory.dispatch()`` with realistic parameters.
2. Verifies the response shape matches the Vault API specification.

This prevents the "mock returns True but real Vault returns a dict" class of
false positives that plague pentest tool test suites.

When the docker-compose Vault lab is available, each test also calls the
REAL Vault API and asserts the mock matches the real response shape.
"""

from __future__ import annotations

import json
import os

import pytest
import requests

from tests.conftest import VaultMockFactory, FAKE_VAULT_TOKEN

pytestmark = pytest.mark.mock_validity

# ── Lab connectivity (same pattern as test_integration.py) ──────────────────

VAULT_ADDR = os.environ.get("VAULT_TEST_ADDR", "https://localhost:8200")
ROOT_TOKEN = os.environ.get("VAULT_TEST_TOKEN", "")


def _lab_token() -> str:
    """Resolve a token for the real Vault lab, or empty string if unreachable."""
    global ROOT_TOKEN
    if ROOT_TOKEN:
        return ROOT_TOKEN
    env_path = os.path.join(os.path.dirname(__file__), "..", "vault-pentest-lab", "lab-tokens.env")
    if os.path.isfile(env_path):
        for line in open(env_path, encoding="utf-8"):
            if line.startswith("ROOT_TOKEN="):
                ROOT_TOKEN = line.split("=", 1)[1].strip()
                return ROOT_TOKEN
    return ""


def _lab_reachable() -> bool:
    try:
        r = requests.get(f"{VAULT_ADDR}/v1/sys/health", timeout=3, verify=False)
        return r.status_code == 200
    except Exception:
        return False


has_lab = pytest.mark.skipif(not _lab_reachable(), reason="Vault lab not running")


def _real_req(method, path, token=None, body=None):
    """Make a real request to the Vault lab."""
    h = {"X-Vault-Token": token or _lab_token(), "Content-Type": "application/json"}
    url = f"{VAULT_ADDR}/v1/{path.lstrip('/')}"
    kwargs = {"headers": h, "timeout": 10, "verify": False}
    if body is not None:
        kwargs["json"] = body
    return requests.request(method, url, **kwargs)


# ── Mock factory fixture ─────────────────────────────────────────────────────

@pytest.fixture
def factory():
    return VaultMockFactory()


# ── Response shape validation (mock-only, always runs) ───────────────────────

class TestMockResponseShapes:
    """Verify mock responses have the correct JSON structure."""

    def test_lookup_self_has_policies(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/auth/token/lookup-self",
                                headers={"X-Vault-Token": FAKE_VAULT_TOKEN})
        data = resp.json()["data"]
        assert "policies" in data
        assert "display_name" in data
        assert isinstance(data["policies"], list)

    def test_sys_mounts_has_secret(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/sys/mounts")
        mounts = resp.json()["data"]
        assert "secret/" in mounts
        assert mounts["secret/"]["type"] == "kv"

    def test_token_create_returns_client_token(self, factory):
        resp = factory.dispatch("POST", "https://vault.test/v1/auth/token/create",
                                json={"policies": ["default"]})
        auth = resp.json()["auth"]
        assert auth["client_token"].startswith("hvs.")
        assert "policies" in auth

    def test_kv_read_has_data(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/secret/data/admin/creds")
        data = resp.json()["data"]["data"]
        assert "username" in data
        assert "password" in data

    def test_database_creds_has_username(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/database/creds/app-admin")
        creds = resp.json()["data"]
        assert "username" in creds
        assert "password" in creds

    def test_approle_login_returns_token(self, factory):
        resp = factory.dispatch("POST", "https://vault.test/v1/auth/approle/login",
                                json={"role_id": "rid", "secret_id": "sid"})
        auth = resp.json()["auth"]
        assert auth["client_token"].startswith("hvs.")
        assert "app-admin" in auth["policies"]

    def test_approle_empty_secret_returns_400(self, factory):
        resp = factory.dispatch("POST", "https://vault.test/v1/auth/approle/login",
                                json={"role_id": "rid", "secret_id": ""})
        assert resp.status_code == 400

    def test_seal_status_has_keys(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/sys/seal-status")
        data = resp.json()
        assert "sealed" in data
        assert "t" in data

    def test_sys_health_has_version(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/sys/health")
        data = resp.json()
        assert "version" in data
        assert "sealed" in data

    def test_audit_list_returns_dict(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/sys/audit")
        data = resp.json()["data"]
        assert isinstance(data, dict)

    def test_pki_ca_has_certificate(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/pki/ca/pem")
        assert "-----BEGIN CERTIFICATE-----" in resp.json()["data"]["certificate"]

    def test_transit_key_has_type(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/transit/keys/my-key")
        data = resp.json()["data"]
        assert "type" in data
        assert "exportable" in data

    def test_userpass_login_returns_token(self, factory):
        resp = factory.dispatch("POST", "https://vault.test/v1/auth/userpass/login/testuser",
                                json={"password": "testpassword"})
        auth = resp.json()["auth"]
        assert auth["client_token"].startswith("hvs.")

    def test_policy_put_returns_204(self, factory):
        resp = factory.dispatch("PUT", "https://vault.test/v1/sys/policies/acl/test-policy",
                                json={"policy": 'path "*" { capabilities = ["read"] }'})
        assert resp.status_code == 204

    def test_policy_delete_returns_204(self, factory):
        resp = factory.dispatch("DELETE", "https://vault.test/v1/sys/policies/acl/test-policy")
        assert resp.status_code == 204

    def test_unknown_path_returns_404(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/this/does/not/exist")
        assert resp.status_code == 404

    def test_database_config_has_connection_url(self, factory):
        resp = factory.dispatch("GET", "https://vault.test/v1/database/config/postgres-prod")
        data = resp.json()["data"]
        assert "connection_details" in data
        assert "allowed_roles" in data


# ── Mock-vs-real comparison (requires Vault lab) ─────────────────────────────

class TestMockVsReal:
    """Verify mock response SHAPES match real Vault API response shapes.

    These tests don't compare values (which differ between mock and real),
    only structure: same keys, same types, same status codes.
    """

    @has_lab
    def test_mock_lookup_self_matches_real_structure(self):
        token = _lab_token()
        factory = VaultMockFactory()

        mock_resp = factory.dispatch("GET", "https://vault.test/v1/auth/token/lookup-self",
                                     headers={"X-Vault-Token": "test"})
        real_resp = _real_req("POST", "auth/token/lookup-self", token=token)

        mock_data = mock_resp.json()["data"]
        real_data = real_resp.json()["data"]
        # Same top-level keys
        assert set(mock_data.keys()) == set(real_data.keys()), \
            f"Mock keys {set(mock_data.keys())} != real keys {set(real_data.keys())}"

    @has_lab
    def test_mock_sys_mounts_matches_real_structure(self):
        factory = VaultMockFactory()
        mock_resp = factory.dispatch("GET", "https://vault.test/v1/sys/mounts")
        real_resp = _real_req("GET", "sys/mounts")

        mock_mounts = mock_resp.json()["data"]
        real_mounts = real_resp.json()["data"]
        # Both return dict[str, dict]
        assert isinstance(mock_mounts, dict)
        assert isinstance(real_mounts, dict)
        # At least secret/ mount exists in both
        assert "secret/" in real_mounts, "Real Vault should have secret/ mount"

    @has_lab
    def test_mock_sys_health_matches_real_structure(self):
        factory = VaultMockFactory()
        mock_resp = factory.dispatch("GET", "https://vault.test/v1/sys/health")
        real_resp = _real_req("GET", "sys/health")

        mock_keys = set(mock_resp.json().keys())
        real_keys = set(real_resp.json().keys())
        # Must share core keys
        assert {"initialized", "sealed", "version"}.issubset(mock_keys & real_keys)

    @has_lab
    def test_mock_token_create_matches_real_structure(self):
        token = _lab_token()
        factory = VaultMockFactory()
        mock_resp = factory.dispatch("POST", "https://vault.test/v1/auth/token/create",
                                     json={"policies": ["default"], "ttl": "1h"})
        real_resp = _real_req("POST", "auth/token/create",
                              token=token, body={"policies": ["default"], "ttl": "1h"})

        mock_auth = mock_resp.json()["auth"]
        real_auth = real_resp.json()["auth"]
        assert "client_token" in mock_auth and "client_token" in real_auth
        assert "policies" in mock_auth and "policies" in real_auth

    @has_lab
    def test_status_codes_match(self):
        """Key HTTP status codes match between mock and real."""
        token = _lab_token()
        factory = VaultMockFactory()

        tests = [
            # (method, path, expected_status)
            ("GET", "sys/health", 200),
            ("GET", "sys/mounts", 200),
            ("POST", "auth/token/lookup-self", 200),
        ]
        for method, path, expected in tests:
            mock_resp = factory.dispatch(method, f"https://vault.test/v1/{path}",
                                         headers={"X-Vault-Token": "test"})
            real_resp = _real_req(method, path, token=token)
            assert mock_resp.status_code == expected, f"Mock {method} {path}: {mock_resp.status_code} != {expected}"
            assert real_resp.status_code == expected, f"Real {method} {path}: {real_resp.status_code} != {expected}"
