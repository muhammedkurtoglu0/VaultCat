from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
from active_execution.modules.secret_exfiltration import SecretExfiltrationModule
from active_execution.modules.database_credential_harvest import DatabaseCredentialHarvestModule
from active_execution.registry import ActiveExecutionRegistry, RiskLevel, risk_level_allowed


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_privilege_escalation_module_discovers_policy_and_creates_raw_success_evidence(monkeypatch):
    requests_seen = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        requests_seen.append({
            "url": url,
            "headers": headers,
            "json": json,
            "timeout": timeout,
            "verify": verify,
        })
        if json["policies"] == ["admin"]:
            return FakeResponse(
                status_code=400,
                payload={"errors": ["policy not allowed"]},
                text='{"errors":["policy not allowed"]}',
            )
        return FakeResponse(
            payload={
                "auth": {
                    "client_token": "hvs.example-elevated-token",
                    "policies": ["admin-policy", "default"],
                }
            }
        )

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)

    context = ExecutionContext(
        vault_addr="https://vault.test/",
        token="hvs.source-token",
        namespace="admin",
        verify_tls=False,
    )
    result = PrivilegeEscalationModule().execute(context)

    assert result.status == "success"
    assert requests_seen[:2] == [{
        "url": "https://vault.test/v1/auth/token/create",
        "headers": {
            "X-Vault-Token": "hvs.source-token",
            "Content-Type": "application/json",
            "X-Vault-Namespace": "admin",
        },
        "json": {"policies": ["admin"], "ttl": "30m"},
        "timeout": 10,
        "verify": False,
    }, {
        "url": "https://vault.test/v1/auth/token/create",
        "headers": {
            "X-Vault-Token": "hvs.source-token",
            "Content-Type": "application/json",
            "X-Vault-Namespace": "admin",
        },
        "json": {"policies": ["admin-policy"], "ttl": "30m"},
        "timeout": 10,
        "verify": False,
    }]
    assert result.evidence["selected_policy"] == "admin-policy"
    assert result.evidence["source_token_policies"] == ["default", "low-privilege-policy"]
    assert result.evidence["added_policies"] == ["admin-policy"]
    assert result.evidence["captured_token"] == "hvs.example-elevated-token"
    assert context.findings[0]["evidence"]["captured_token"] == "hvs.example-elevated-token"
    assert context.escalated_token == "hvs.example-elevated-token"


def test_privilege_escalation_module_honors_explicit_policy(monkeypatch):
    requests_seen = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        requests_seen.append(json)
        return FakeResponse(
            payload={
                "auth": {
                    "client_token": "hvs.admin-policy-token",
                    "policies": ["admin-policy", "default"],
                }
            }
        )

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)

    result = PrivilegeEscalationModule().execute(
        ExecutionContext(vault_addr="https://vault.test", token="hvs.source-token"),
        {"policies": ["admin-policy"], "ttl": "15m"},
    )

    assert result.status == "success"
    assert requests_seen == [{"policies": ["admin-policy"], "ttl": "15m"}]
    assert result.evidence["selected_policy"] == "admin-policy"


def test_privilege_escalation_module_rejects_same_or_lower_policy_result(monkeypatch):
    requests_seen = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})

    def fake_post(url, headers=None, json=None, timeout=None, verify=None):
        requests_seen.append(json)
        return FakeResponse(
            payload={
                "auth": {
                    "client_token": "hvs.same-policy-token",
                    "policies": ["default", "low-privilege-policy"],
                }
            }
        )

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)

    result = PrivilegeEscalationModule().execute(
        ExecutionContext(vault_addr="https://vault.test", token="hvs.source-token"),
        {"policies": ["low-privilege-policy", "admin-policy"], "ttl": "15m"},
    )

    assert result.status == "failed"
    assert requests_seen == [{"policies": ["admin-policy"], "ttl": "15m"}]
    assert result.evidence["attempted_policies"][0]["reason"] == "policy already present on source token"
    assert result.evidence["attempted_policies"][1]["reason"] == "created token did not add a new candidate policy"


def test_privilege_escalation_module_skips_when_context_is_incomplete():
    context = ExecutionContext(vault_addr="https://vault.test")
    result = PrivilegeEscalationModule().execute(context)

    assert result.status == "skipped"
    assert result.evidence == {"missing": ["token"]}


def test_secret_exfiltration_module_requires_captured_token():
    result = SecretExfiltrationModule().execute(
        ExecutionContext(vault_addr="https://vault.test", token="hvs.low-token")
    )

    assert result.status == "skipped"
    assert result.evidence == {"missing": ["captured_token"]}


def test_secret_exfiltration_module_reads_kv_v2_payloads(monkeypatch):
    requests_seen = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        requests_seen.append(("GET", url, headers))
        if url == "https://vault.test/v1/sys/mounts":
            return FakeResponse(payload={
                "data": {
                    "secret/": {"type": "kv", "options": {"version": "2"}},
                    "database/": {"type": "database"},
                }
            })
        if url == "https://vault.test/v1/secret/data/app/db":
            return FakeResponse(payload={
                "data": {
                    "data": {
                        "password": "super-secret",
                        "api_key": "key-123",
                    }
                }
            })
        return FakeResponse(status_code=404, text="not found")

    def fake_request(method, url, headers=None, timeout=None, verify=None):
        requests_seen.append((method, url, headers))
        if method == "LIST" and url == "https://vault.test/v1/secret/metadata":
            return FakeResponse(payload={"data": {"keys": ["app/"]}})
        if method == "LIST" and url == "https://vault.test/v1/secret/metadata/app":
            return FakeResponse(payload={"data": {"keys": ["db"]}})
        return FakeResponse(status_code=404, text="not found")

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.request", fake_request)

    context = ExecutionContext(vault_addr="https://vault.test", token="hvs.low-token")
    context.captured_token = "hvs.admin-token"
    result = SecretExfiltrationModule().execute(context, {"namespace": "admin"})

    assert result.status == "success"
    assert result.evidence["leaked_payloads"] == {
        "secret/app/db": {
            "password": "super-secret",
            "api_key": "key-123",
        }
    }
    assert context.findings[0]["title"] == "CRITICAL: Secret Exfiltration Successful"
    assert all(
        request_headers["X-Vault-Token"] == "hvs.admin-token"
        and request_headers["X-Vault-Namespace"] == "admin"
        for _, _, request_headers in requests_seen
    )


def test_database_credential_harvest_skips_without_token():
    context = ExecutionContext(vault_addr="https://vault.test")
    result = DatabaseCredentialHarvestModule().execute(context)

    assert result.status == "skipped"
    assert "token or captured_token" in result.evidence["missing"]


def test_database_credential_harvest_skips_without_vault_addr():
    context = ExecutionContext(vault_addr="", token="hvs.token")
    result = DatabaseCredentialHarvestModule().execute(context)

    assert result.status == "skipped"
    assert "vault_addr" in result.evidence["missing"]


def test_database_credential_harvest_returns_failed_when_no_db_mounts(monkeypatch):
    def fake_get(url, headers=None, timeout=None, verify=None):
        if "/v1/sys/mounts" in url:
            return FakeResponse(payload={
                "data": {
                    "secret/": {"type": "kv", "options": {"version": "2"}},
                }
            })
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.get", fake_get)

    context = ExecutionContext(vault_addr="https://vault.test", token="hvs.token")
    result = DatabaseCredentialHarvestModule().execute(context)

    assert result.status == "failed"
    assert result.evidence["db_mounts"] == []


def test_database_credential_harvest_generates_dynamic_creds(monkeypatch):
    requests_seen = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        requests_seen.append(("GET", url))
        if "/v1/sys/mounts" in url:
            return FakeResponse(payload={
                "data": {
                    "database/": {"type": "database"},
                }
            })
        if "/v1/database/roles/app-role" in url:
            return FakeResponse(payload={
                "data": {
                    "creation_statements": ["GRANT ALL ON *.* TO '{{name}}'@'%';"],
                    "default_ttl": "1h",
                    "max_ttl": "24h",
                }
            })
        if "/v1/database/creds/app-role" in url:
            return FakeResponse(payload={
                "lease_id": "database/creds/app-role/abc123",
                "lease_duration": 3600,
                "data": {
                    "username": "v-root-app-role-xyz",
                    "password": "A1B2-secret-pw",
                },
            })
        return FakeResponse(status_code=404)

    def fake_request(method, url, headers=None, timeout=None, verify=None):
        requests_seen.append((method, url))
        if method == "LIST" and "/v1/database/roles" in url and "static" not in url:
            return FakeResponse(payload={"data": {"keys": ["app-role"]}})
        if method == "LIST" and "/v1/database/static-roles" in url:
            return FakeResponse(status_code=404)
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.request", fake_request)

    context = ExecutionContext(vault_addr="https://vault.test", token="hvs.token")
    result = DatabaseCredentialHarvestModule().execute(context)

    assert result.status == "success"
    assert result.evidence["total_harvested"] == 1
    cred = result.evidence["credentials"][0]
    assert cred["username"] == "v-root-app-role-xyz"
    assert cred["password"] == "A1B2-secret-pw"
    assert cred["type"] == "dynamic"
    assert cred["high_privilege"] is True  # "GRANT ALL" in creation_statements
    assert cred["lease_duration_seconds"] == 3600
    assert context.findings[0]["severity"] == "CRITICAL"
    assert context.findings[0]["title"].startswith("CRITICAL: Database Credentials Harvested")


def test_database_credential_harvest_flags_non_privileged_role(monkeypatch):
    def fake_get(url, headers=None, timeout=None, verify=None):
        if "/v1/sys/mounts" in url:
            return FakeResponse(payload={"data": {"database/": {"type": "database"}}})
        if "/v1/database/roles/readonly-role" in url:
            return FakeResponse(payload={
                "data": {
                    "creation_statements": [
                        "GRANT SELECT ON mydb.* TO '{{name}}'@'%';"
                    ]
                }
            })
        if "/v1/database/creds/readonly-role" in url:
            return FakeResponse(payload={
                "lease_id": "database/creds/readonly-role/def456",
                "lease_duration": 1800,
                "data": {"username": "v-read-xyz", "password": "pw-read"},
            })
        return FakeResponse(status_code=404)

    def fake_request(method, url, headers=None, timeout=None, verify=None):
        if method == "LIST" and "/v1/database/roles" in url and "static" not in url:
            return FakeResponse(payload={"data": {"keys": ["readonly-role"]}})
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.request", fake_request)

    context = ExecutionContext(vault_addr="https://vault.test", token="hvs.token")
    result = DatabaseCredentialHarvestModule().execute(context)

    assert result.status == "success"
    cred = result.evidence["credentials"][0]
    assert cred["high_privilege"] is False
    assert context.findings[0]["severity"] == "HIGH"


def test_database_credential_harvest_uses_captured_token(monkeypatch):
    tokens_used = []

    def fake_get(url, headers=None, timeout=None, verify=None):
        tokens_used.append(headers.get("X-Vault-Token"))
        if "/v1/sys/mounts" in url:
            return FakeResponse(payload={"data": {"database/": {"type": "database"}}})
        return FakeResponse(status_code=404)

    def fake_request(method, url, headers=None, timeout=None, verify=None):
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.request", fake_request)

    context = ExecutionContext(
        vault_addr="https://vault.test",
        token="hvs.low-token",
        captured_token="hvs.elevated-token",
    )
    DatabaseCredentialHarvestModule().execute(context)

    assert all(t == "hvs.elevated-token" for t in tokens_used)


def test_database_credential_harvest_module_metadata():
    module = DatabaseCredentialHarvestModule()

    assert module.module_id == "database_credential_harvest.dynamic_creds"
    assert module.risk_level == RiskLevel.STATE_CHANGING
    assert module.default_enabled is False
    assert risk_level_allowed(module.risk_level, RiskLevel.STATE_CHANGING) is True
    assert risk_level_allowed(module.risk_level, RiskLevel.READ_ONLY) is False


def test_active_execution_registry_filters_by_risk_level():
    module = PrivilegeEscalationModule()

    assert module.default_enabled is True
    assert risk_level_allowed(module.risk_level, RiskLevel.STATE_CHANGING) is True
    assert risk_level_allowed(module.risk_level, RiskLevel.READ_ONLY) is False


def test_active_execution_registry_rejects_duplicate_module_ids():
    registry = ActiveExecutionRegistry()
    registry.register(PrivilegeEscalationModule())

    try:
        registry.register(PrivilegeEscalationModule())
    except ValueError as error:
        assert "duplicate active execution module_id" in str(error)
    else:
        raise AssertionError("duplicate module_id was accepted")


def test_active_execution_engine_skips_missing_context():
    registry = ActiveExecutionRegistry()
    registry.register(PrivilegeEscalationModule())
    registry.register(SecretExfiltrationModule())
    engine = ActiveExecutionEngine(registry)

    results = engine.execute_plan(
        [{"module_id": "privilege_escalation.token_abuse", "params": {}}],
        ExecutionContext(vault_addr="https://vault.test"),
    )

    assert len(results) == 1
    assert results[0].status == "blocked"


def test_active_execution_engine_requires_confirmation_for_state_changing_module():
    registry = ActiveExecutionRegistry()
    registry.register(PrivilegeEscalationModule())
    engine = ActiveExecutionEngine(registry)

    results = engine.execute_plan(
        [{"module_id": "privilege_escalation.token_abuse", "params": {}}],
        ExecutionContext(vault_addr="https://vault.test", token="hvs.token"),
        max_risk=RiskLevel.STATE_CHANGING,
    )

    assert results[0].status == "blocked"
    assert results[0].evidence["required_confirmation"] == "confirm_state_changing"


def test_active_execution_engine_accepts_parameters_alias_and_normalizes_exceptions():
    class ExplodingModule(PrivilegeEscalationModule):
        def __init__(self):
            super().__init__()
            self.module_id = "test.exploding"

        def execute(self, context, params=None):
            assert params == {"ttl": "20m"}
            raise RuntimeError("boom")

    registry = ActiveExecutionRegistry()
    registry.register(ExplodingModule())
    engine = ActiveExecutionEngine(registry)

    results = engine.execute_plan(
        [{"module_id": "test.exploding", "parameters": {"ttl": "20m"}}],
        ExecutionContext(vault_addr="https://vault.test", token="hvs.token"),
        max_risk=RiskLevel.STATE_CHANGING,
        confirm_state_changing=True,
    )

    assert results[0].status == "error"
    assert "boom" in results[0].message
