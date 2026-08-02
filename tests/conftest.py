"""Shared fixtures for AI component tests."""

import json

import pytest

# ---------------------------------------------------------------------------
# Fake constants
# ---------------------------------------------------------------------------

FAKE_VAULT_ADDR = "http://192.0.2.1:8200"  # TEST-NET-1 (safe)
FAKE_TOKEN = "hvs.test-token-unit-test-abc123"


# ---------------------------------------------------------------------------
# Fake HTTP responses
# ---------------------------------------------------------------------------


class FakeResponse:
    """Minimal requests.Response stub."""

    def __init__(self, status_code: int, json_data: dict | None = None,
                 text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body")
        return self._json_data


def fake_openai_response(content: str | None = None,
                          tool_calls: list[dict] | None = None) -> dict:
    """Build a fake OpenAI chat completion response dict."""
    msg: dict = {"role": "assistant", "content": content or ""}
    if tool_calls:
        msg["tool_calls"] = [
            {
                "id": f"call_{i}",
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": json.dumps(tc.get("arguments", {})),
                },
            }
            for i, tc in enumerate(tool_calls)
        ]
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": msg, "finish_reason": "tool_calls" if tool_calls else "stop"}
        ],
    }


def fake_anthropic_response(content: str = "",
                             tool_use_blocks: list[dict] | None = None) -> dict:
    """Build a fake Anthropic messages response dict."""
    blocks: list[dict] = []
    if content:
        blocks.append({"type": "text", "text": content})
    if tool_use_blocks:
        for tb in tool_use_blocks:
            blocks.append({
                "type": "tool_use",
                "id": tb.get("id", "tool_0"),
                "name": tb.get("name", ""),
                "input": tb.get("input", {}),
            })
    return {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "content": blocks,
        "model": "claude-sonnet-5",
        "stop_reason": "tool_use" if tool_use_blocks else "end_turn",
    }


def fake_ollama_response(content: str = "",
                          tool_calls: list[dict] | None = None) -> dict:
    """Build a fake Ollama /api/chat response dict."""
    msg: dict = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = [
            {"function": {"name": tc["name"],
                          "arguments": tc.get("arguments", {})}}
            for tc in tool_calls
        ]
    return {"model": "llama3.1:8b", "message": msg, "done": True}


# ---------------------------------------------------------------------------
# Enumeration data fixture
# ---------------------------------------------------------------------------


def sample_enum_data() -> dict:
    return {
        "capabilities": json.dumps({
            "status": "completed",
            "findings": [
                {"severity": "HIGH", "title": "Token has sys/mounts read access",
                 "description": "Can list all secret engines"},
                {"severity": "CRITICAL", "title": "Token can create new tokens",
                 "description": "auth/token/create is permitted"},
            ],
        }),
        "priv_esc": json.dumps({
            "status": "completed",
            "findings": [
                {"severity": "HIGH",
                 "title": "Token can escalate via token creation"},
            ],
        }),
        "kv_paths": json.dumps({
            "status": "completed",
            "paths": ["secret/", "secret/database", "kv/app"],
        }),
        "findings": [
            {"severity": "HIGH", "title": "Vault running on HTTP",
             "module": "tls_scanner"},
            {"severity": "MEDIUM", "title": "Vault version 1.15.6 has 3 CVEs",
             "module": "version_risk_scanner"},
            {"severity": "HIGH",
             "title": "Token can create new tokens",
             "module": "capability_scanner"},
        ],
    }


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_token() -> str:
    return FAKE_TOKEN


@pytest.fixture
def fake_vault_addr() -> str:
    return FAKE_VAULT_ADDR


@pytest.fixture
def enum_data() -> dict:
    return sample_enum_data()


@pytest.fixture
def mock_openai(monkeypatch):
    """Patch requests.post for OpenAI-compatible endpoints."""
    original_post = __import__("requests").post

    def _mock(url: str, **kwargs):
        r = FakeResponse(200, json_data=fake_openai_response(
            content="This is a mocked response from the AI.",
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    return _mock


@pytest.fixture
def mock_openai_tool_call(monkeypatch):
    """Patch requests.post to return a tool_calls response."""
    def _mock(url: str, **kwargs):
        r = FakeResponse(200, json_data=fake_openai_response(
            content="Let me run that tool.",
            tool_calls=[{"name": "run_unauthenticated_recon",
                         "arguments": {"vault_addr": FAKE_VAULT_ADDR}}],
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    return _mock


@pytest.fixture
def mock_openai_error_429(monkeypatch):
    """Patch requests.post to return a 429 rate-limit."""
    call_count = [0]

    def _mock(url: str, **kwargs):
        call_count[0] += 1
        if call_count[0] <= 2:
            r = FakeResponse(429, text="Rate limit exceeded")
            return r
        r = FakeResponse(200, json_data=fake_openai_response(
            content="Finally succeeded after retries.",
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    monkeypatch.setattr("time.sleep", lambda s: None)  # speed up retries
    return _mock


# ---------------------------------------------------------------------------
# Reusable Vault mock factories — for active_execution module tests
# ---------------------------------------------------------------------------

FAKE_VAULT_TOKEN = "hvs.mock-vault-token-for-unit-tests"
FAKE_ROOT_TOKEN = "hvs.mock-root-token"


class VaultMockFactory:
    """Produces fake Vault HTTP responses for active_execution module testing.

    Usage in a test::

        factory = VaultMockFactory()
        monkeypatch.setattr("requests.request", factory.dispatch)
        # or: monkeypatch.setattr("core.tls_config", "vault_request", factory.dispatch)
    """

    def __init__(
        self,
        *,
        root_token: str = FAKE_ROOT_TOKEN,
        source_policies: list[str] | None = None,
        kv_secrets: dict[str, dict] | None = None,
        db_roles: list[str] | None = None,
        auth_methods: dict[str, dict] | None = None,
        mounts: dict[str, dict] | None = None,
        policies: list[str] | None = None,
        transit_keys: list[str] | None = None,
        seal_status: dict | None = None,
    ):
        self.root_token = root_token
        self.source_policies = source_policies or ["default"]
        self.kv_secrets = kv_secrets or {
            "secret/data/admin/creds": {"username": "admin", "password": "SuperSecret123!"},
            "secret/data/api/keys": {"github_token": "ghp_fake123", "stripe_key": "sk_live_fake456"},
            "secret/data/db/config": {"user": "vault_admin", "pass": "vault-admin-password", "host": "localhost", "port": 5432},
        }
        self.db_roles = db_roles or ["app-admin", "app-readonly"]
        self.auth_methods = auth_methods or {
            "approle/": {"type": "approle", "accessor": "auth_approle_00000"},
            "userpass/": {"type": "userpass", "accessor": "auth_userpass_00000"},
        }
        self.mounts = mounts or {
            "secret/": {"type": "kv", "options": {"version": "2"}},
            "database/": {"type": "database", "config": {"plugin_name": "postgresql-database-plugin"}},
            "transit/": {"type": "transit"},
            "pki/": {"type": "pki"},
            "cubbyhole/": {"type": "cubbyhole"},
        }
        self.policies = policies or ["default", "root", "read-only", "app-admin", "admin-policy", "weak-policy"]
        self.transit_keys = transit_keys or ["my-key"]
        self.seal_status = seal_status or {"sealed": False, "t": 1, "n": 1, "progress": 0}

        # Per-instance call log
        self.calls: list[dict] = []

    # ── main dispatcher ──────────────────────────────────────────────────

    def dispatch(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})

        # ── Token lookup-self ────────────────────────────────────────
        if "lookup-self" in url:
            token = (kwargs.get("headers", {}).get("X-Vault-Token", ""))
            return FakeResponse(200, json_data={
                "data": {
                    "id": token or self.root_token,
                    "policies": self.source_policies,
                    "display_name": "mock-token",
                    "creation_ttl": 3600,
                    "ttl": 1800,
                    "renewable": True,
                    "orphan": False,
                    "type": "service",
                }
            })

        # ── Policy management ────────────────────────────────────────
        if "policies/acl" in url:
            # Policy creation (PUT)
            if method == "PUT":
                return FakeResponse(204)
            # Policy deletion (DELETE)
            if method == "DELETE":
                return FakeResponse(204)
            # Policy read (GET)
            return FakeResponse(200, json_data={
                "data": {
                    "name": url.rstrip("/").split("/")[-1],
                    "policy": 'path "*" { capabilities = ["read"] }',
                }
            })

        # ── Policy list ──────────────────────────────────────────────
        if url.endswith("/v1/sys/policy") or url.endswith("/sys/policy"):
            return FakeResponse(200, json_data={"policies": self.policies})

        # ── Token creation ───────────────────────────────────────────
        if "auth/token/create" in url:
            body = kwargs.get("json") or {}
            req_policies = body.get("policies", ["default"])
            return FakeResponse(200, json_data={
                "auth": {
                    "client_token": f"hvs.mock-created-token-{'-'.join(req_policies)}",
                    "policies": req_policies,
                    "lease_duration": 3600,
                    "renewable": True,
                }
            })

        # ── Mounts ───────────────────────────────────────────────────
        if url.rstrip("/").endswith("/sys/mounts") or "/sys/mounts" in url:
            return FakeResponse(200, json_data={"data": self.mounts})

        # ── KV read ──────────────────────────────────────────────────
        for kv_path, kv_data in self.kv_secrets.items():
            if kv_path.replace("secret/data/", "") in url or kv_path in url:
                return FakeResponse(200, json_data={
                    "data": {
                        "data": kv_data,
                        "metadata": {"version": 1, "created_time": "2024-01-01T00:00:00Z"},
                    }
                })
        # KV list
        if "secret/metadata" in url and method == "LIST":
            keys = [k.replace("secret/data/", "") for k in self.kv_secrets]
            return FakeResponse(200, json_data={"data": {"keys": keys}})

        # ── Database ─────────────────────────────────────────────────
        if "database/config/postgres-prod" in url:
            return FakeResponse(200, json_data={
                "data": {
                    "connection_details": {
                        "connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/app",
                        "username": "vault_admin",
                    },
                    "allowed_roles": self.db_roles,
                }
            })
        if "database/roles" in url and method == "LIST":
            return FakeResponse(200, json_data={"data": {"keys": self.db_roles}})
        if "database/roles/app-admin" in url:
            return FakeResponse(200, json_data={
                "data": {
                    "creation_statements": [
                        'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' SUPERUSER VALID UNTIL \'{{expiration}}\';'
                    ],
                    "db_name": "postgres-prod",
                    "default_ttl": 3600,
                    "max_ttl": 172800,
                }
            })
        if "database/roles/app-readonly" in url:
            return FakeResponse(200, json_data={
                "data": {
                    "creation_statements": [
                        'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';'
                    ],
                    "db_name": "postgres-prod",
                    "default_ttl": 3600,
                    "max_ttl": 86400,
                }
            })
        if "database/creds/" in url:
            role = url.rstrip("/").split("/")[-1]
            return FakeResponse(200, json_data={
                "request_id": "mock-db-creds",
                "lease_id": f"database/creds/{role}/mock-lease-id",
                "lease_duration": 3600,
                "data": {
                    "username": f"v-{role}-mock-user-12345",
                    "password": "mock-generated-db-password",
                },
            })

        # ── Auth methods ─────────────────────────────────────────────
        if url.rstrip("/").endswith("/sys/auth"):
            return FakeResponse(200, json_data={"data": self.auth_methods})
        if "auth/userpass/login" in url:
            return FakeResponse(200, json_data={
                "auth": {
                    "client_token": "hvs.mock-userpass-token",
                    "policies": ["default", "read-only"],
                    "lease_duration": 2764800,
                    "renewable": True,
                }
            })
        if "auth/approle/login" in url:
            body = kwargs.get("json") or {}
            secret_id = body.get("secret_id", "")
            if not secret_id or secret_id == "empty-secret-id":
                return FakeResponse(400, json_data={"errors": ["invalid role or secret ID"]})
            return FakeResponse(200, json_data={
                "auth": {
                    "client_token": "hvs.mock-approle-token",
                    "policies": ["default", "app-admin"],
                    "metadata": {"role_name": "my-role"},
                }
            })
        if "approle/role/my-role/role-id" in url:
            return FakeResponse(200, json_data={"data": {"role_id": "mock-role-id-1234"}})
        if "approle/role/my-role/secret-id" in url:
            return FakeResponse(200, json_data={
                "data": {"secret_id": "mock-secret-id-5678", "secret_id_accessor": "mock-accessor-0000"}
            })
        if "approle/role/" in url:
            return FakeResponse(200, json_data={
                "data": {
                    "bind_secret_id": True,
                    "secret_id_num_uses": 10,
                    "token_policies": ["app-admin"],
                }
            })

        # ── Transit ──────────────────────────────────────────────────
        if "transit/keys/" in url and (method == "GET" or method == "LIST"):
            key = url.rstrip("/").split("/")[-1]
            if key in self.transit_keys or url.endswith("/transit/keys"):
                return FakeResponse(200, json_data={
                    "data": {
                        "name": key if key != "keys" else self.transit_keys[0],
                        "type": "aes256-gcm96",
                        "exportable": False,
                        "allow_plaintext_backup": False,
                    }
                })
        if "transit/encrypt/" in url:
            return FakeResponse(200, json_data={"data": {"ciphertext": "vault:v1:mock-encrypted-data"}})

        # ── PKI ──────────────────────────────────────────────────────
        if "pki/ca/pem" in url or "/pki/ca" in url.rstrip("/").split("/")[-2:]:
            return FakeResponse(200, json_data={
                "data": {"certificate": "-----BEGIN CERTIFICATE-----\nMOCKCA12345\n-----END CERTIFICATE-----"}
            })
        if "pki/issue/" in url or "pki/roles/" in url:
            return FakeResponse(200, json_data={
                "data": {
                    "certificate": "-----BEGIN CERTIFICATE-----\nMOCKCERT12345\n-----END CERTIFICATE-----",
                    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMOCKKEY12345\n-----END RSA PRIVATE KEY-----",
                }
            })

        # ── Seal status ──────────────────────────────────────────────
        if "seal-status" in url:
            return FakeResponse(200, json_data=self.seal_status)

        # ── Health ───────────────────────────────────────────────────
        if "sys/health" in url:
            return FakeResponse(200, json_data={
                "initialized": True,
                "sealed": self.seal_status.get("sealed", False),
                "version": "1.15.3",
                "cluster_name": "vault-cluster-mock",
                "cluster_id": "mock-cluster-id",
            })

        # ── Audit ────────────────────────────────────────────────────
        if "sys/audit" in url and method == "GET":
            return FakeResponse(200, json_data={
                "data": {
                    "file/": {"type": "file", "description": "File audit device", "options": {"file_path": "/vault/logs/audit.log"}}
                }
            })
        if "sys/audit/" in url and method == "DELETE":
            return FakeResponse(204)

        # ── JWT/OIDC ─────────────────────────────────────────────────
        if "oidc/" in url.lower() or "jwt/" in url.lower():
            return FakeResponse(200, json_data={
                "data": {"bound_issuer": "https://accounts.google.com", "oidc_discovery_url": "https://accounts.google.com"}
            })

        # ── K8s auth ─────────────────────────────────────────────────
        if "kubernetes/" in url.lower():
            return FakeResponse(200, json_data={
                "data": {
                    "kubernetes_host": "https://k8s-api:443",
                    "issuer": "https://kubernetes.default.svc.cluster.local",
                }
            })

        # ── Userpass user management ─────────────────────────────────
        if "auth/userpass/users/" in url and method == "POST":
            return FakeResponse(204)

        # ── Fallback ─────────────────────────────────────────────────
        return FakeResponse(404, text="mock: endpoint not configured in VaultMockFactory")


@pytest.fixture
def vault_mock():
    """Return a fresh VaultMockFactory instance — use with monkeypatch."""
    return VaultMockFactory()


@pytest.fixture
def vault_mock_patched(monkeypatch):
    """Return a VaultMockFactory that is already patched over requests.request."""
    factory = VaultMockFactory()
    monkeypatch.setattr("requests.request", factory.dispatch)
    monkeypatch.setattr("core.tls_config", "vault_request", factory.dispatch)
    return factory
