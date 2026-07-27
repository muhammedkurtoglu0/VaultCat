import pytest

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

    def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
        requests_seen.append({
            "method": method,
            "url": url,
            "headers": headers,
            "json": json,
            "timeout": timeout,
            "verify": verify,
        })
        if "/v1/auth/token/lookup-self" in url:
            return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})
        if "/v1/sys/mounts" in url:
            # Token verification check — return 200 for elevated tokens
            if "example-elevated-token" in str(headers.get("X-Vault-Token", "")):
                return FakeResponse(payload={"data": {}})
            return FakeResponse(status_code=403, payload={"errors": ["permission denied"]})
        if "policies/acl" in url:
            # Token cannot manage policies — no wildcard policy access
            return FakeResponse(status_code=403, payload={"errors": ["permission denied"]})
        if json and json.get("policies") == ["admin"]:
            return FakeResponse(
                status_code=400,
                payload={"errors": ["policy not allowed"]},
                text='{"errors":["policy not allowed"]}',
            )
        if "/v1/auth/token/create" in url:
            return FakeResponse(
                payload={
                    "auth": {
                        "client_token": "hvs.example-elevated-token",
                        "policies": ["admin-policy", "default"],
                    }
                }
            )
        return FakeResponse(status_code=404, text="not found")

    monkeypatch.setattr("requests.request", fake_request)

    context = ExecutionContext(
        vault_addr="https://vault.test/",
        token="hvs.source-token",
        namespace="admin",
        verify_tls=False,
    )
    result = PrivilegeEscalationModule().execute(context)

    assert result.status == "success"
    # First call: lookup-self (GET)
    assert requests_seen[0]["method"] == "GET"
    assert "lookup-self" in requests_seen[0]["url"]
    # Then token creation attempts (POST)
    create_calls = [r for r in requests_seen if "/v1/auth/token/create" in r["url"]]
    assert len(create_calls) >= 2
    assert result.evidence["selected_policy"] == "admin-policy"
    assert result.evidence["source_token_policies"] == ["default", "low-privilege-policy"]
    assert result.evidence["added_policies"] == ["admin-policy"]
    assert result.evidence["captured_token"] == "hvs.example-elevated-token"
    assert context.findings[0]["evidence"]["captured_token"] == "hvs.example-elevated-token"
    assert context.escalated_token == "hvs.example-elevated-token"


def test_privilege_escalation_module_honors_explicit_policy(monkeypatch):
    requests_seen = []

    def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
        requests_seen.append({"method": method, "url": url, "json": json})
        if "/v1/auth/token/lookup-self" in url:
            return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})
        if "/v1/sys/mounts" in url:
            return FakeResponse(payload={"data": {}})
        if "policies/acl" in url:
            # Token cannot manage policies
            return FakeResponse(status_code=403, payload={"errors": ["permission denied"]})
        if "/v1/auth/token/create" in url:
            return FakeResponse(
                payload={
                    "auth": {
                        "client_token": "hvs.admin-policy-token",
                        "policies": ["admin-policy", "default"],
                    }
                }
            )
        return FakeResponse(status_code=404, text="not found")

    monkeypatch.setattr("requests.request", fake_request)

    result = PrivilegeEscalationModule().execute(
        ExecutionContext(vault_addr="https://vault.test", token="hvs.source-token"),
        {"policies": ["admin-policy"], "ttl": "15m"},
    )

    assert result.status == "success"
    create_calls = [r for r in requests_seen if "/v1/auth/token/create" in r["url"]]
    assert len(create_calls) == 1
    assert create_calls[0]["json"] == {"policies": ["admin-policy"], "ttl": "15m"}
    assert result.evidence["selected_policy"] == "admin-policy"


def test_privilege_escalation_module_rejects_same_or_lower_policy_result(monkeypatch):
    requests_seen = []

    def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
        requests_seen.append(json)
        if "/v1/auth/token/lookup-self" in url:
            return FakeResponse(payload={"data": {"policies": ["default", "low-privilege-policy"]}})
        if "/v1/sys/mounts" in url:
            return FakeResponse(status_code=403, payload={"errors": ["permission denied"]})
        if "policies/acl" in url:
            return FakeResponse(status_code=403, payload={"errors": ["permission denied"]})
        if "/v1/auth/token/create" in url:
            return FakeResponse(
                payload={
                    "auth": {
                        "client_token": "hvs.same-policy-token",
                        "policies": ["default", "low-privilege-policy"],
                    }
                }
            )
        return FakeResponse(status_code=404, text="not found")

    monkeypatch.setattr("requests.request", fake_request)

    result = PrivilegeEscalationModule().execute(
        ExecutionContext(vault_addr="https://vault.test", token="hvs.source-token"),
        {"policies": ["low-privilege-policy", "admin-policy"], "ttl": "15m"},
    )

    assert result.status == "failed"
    assert result.evidence["attempted_policies"][0]["reason"] == "policy already present on source token"
    assert result.evidence["attempted_policies"][1]["reason"] == "created token did not add a new candidate policy"


def test_privilege_escalation_module_skips_when_context_is_incomplete():
    context = ExecutionContext(vault_addr="https://vault.test")
    result = PrivilegeEscalationModule().execute(context)

    assert result.status == "skipped"
    assert result.evidence == {"missing": ["token"]}


def test_secret_exfiltration_module_requires_captured_token():
    """Module skips when no token at all (neither captured nor context.token)."""
    result = SecretExfiltrationModule().execute(
        ExecutionContext(vault_addr="https://vault.test")  # no token
    )
    assert result.status == "skipped"
    assert "token" in str(result.evidence)


def test_secret_exfiltration_module_reads_kv_v2_payloads(monkeypatch):
    requests_seen = []

    def fake_request(method, url, headers=None, timeout=None, verify=None, **kwargs):
        requests_seen.append((method, url, headers))
        if method == "GET" and url == "https://vault.test/v1/sys/mounts":
            return FakeResponse(payload={
                "data": {
                    "secret/": {"type": "kv", "options": {"version": "2"}},
                    "database/": {"type": "database"},
                }
            })
        if method == "GET" and url == "https://vault.test/v1/secret/data/app/db":
            return FakeResponse(payload={
                "data": {
                    "data": {
                        "password": "super-secret",
                        "api_key": "key-123",
                    }
                }
            })
        if method == "LIST" and url == "https://vault.test/v1/secret/metadata":
            return FakeResponse(payload={"data": {"keys": ["app/"]}})
        if method == "LIST" and url == "https://vault.test/v1/secret/metadata/app":
            return FakeResponse(payload={"data": {"keys": ["db"]}})
        return FakeResponse(status_code=404, text="not found")

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


# ---------------------------------------------------------------------------
# Domain system tests
# ---------------------------------------------------------------------------


# All expected domains from the taxonomy
EXPECTED_DOMAINS = {
    "database", "cloud", "token", "persistence",
    "seal", "secrets", "pivot", "general",
}


def _register_sample_modules(registry: ActiveExecutionRegistry):
    """Register one module per domain for testing."""
    from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
    from active_execution.modules.secret_exfiltration import SecretExfiltrationModule
    from active_execution.modules.database_credential_harvest import DatabaseCredentialHarvestModule
    from active_execution.modules.cloud_key_exfiltration import CloudKeyExfiltrationModule
    from active_execution.modules.persistence import PersistenceModule
    from active_execution.modules.vault_seal_manipulation import SealStatusModule
    from active_execution.modules.pivot_engine import PivotEngineModule
    from active_execution.modules.cve_scanner import CVEScannerModule

    registry.register(PrivilegeEscalationModule())
    registry.register(SecretExfiltrationModule())
    registry.register(DatabaseCredentialHarvestModule())
    registry.register(CloudKeyExfiltrationModule())
    registry.register(PersistenceModule())
    registry.register(SealStatusModule())
    registry.register(PivotEngineModule())
    registry.register(CVEScannerModule())


class TestDomainField:
    """Verify every registered module has a valid non-empty domain."""

    def test_all_modules_have_valid_domain(self):
        """Every module from the sample set must declare a known domain."""
        registry = ActiveExecutionRegistry()
        _register_sample_modules(registry)

        for m in registry.list_modules():
            assert m.domain, (
                f"Module '{m.module_id}' has empty/missing domain"
            )
            assert m.domain in EXPECTED_DOMAINS, (
                f"Module '{m.module_id}' has unknown domain '{m.domain}'; "
                f"expected one of {EXPECTED_DOMAINS}"
            )

    def test_domain_is_accessible_as_attribute(self):
        """domain must be a plain str attribute on the module instance."""
        from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
        m = PrivilegeEscalationModule()
        assert isinstance(m.domain, str)
        assert m.domain == "token"


class TestListByDomain:
    """Test ActiveExecutionRegistry.list_by_domain."""

    @pytest.fixture
    def registry(self):
        r = ActiveExecutionRegistry()
        _register_sample_modules(r)
        return r

    def test_database_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("database")
        ids = {m.module_id for m in mods}
        assert "database_credential_harvest.dynamic_creds" in ids
        assert len(mods) >= 1

    def test_cloud_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("cloud")
        ids = {m.module_id for m in mods}
        assert "cloud_key_exfiltration.key_dump" in ids
        assert len(mods) >= 1

    def test_token_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("token")
        ids = {m.module_id for m in mods}
        assert "privilege_escalation.token_abuse" in ids
        assert len(mods) >= 1

    def test_persistence_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("persistence")
        ids = {m.module_id for m in mods}
        assert "persistence.backdoor" in ids
        assert len(mods) >= 1

    def test_seal_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("seal")
        ids = {m.module_id for m in mods}
        assert "vault_seal.seal_status" in ids
        assert len(mods) >= 1

    def test_secrets_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("secrets")
        ids = {m.module_id for m in mods}
        assert "secret_exfiltration.kv_dump" in ids

    def test_pivot_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("pivot")
        ids = {m.module_id for m in mods}
        assert "pivot_engine.cross_service" in ids

    def test_general_domain_returns_correct_modules(self, registry):
        mods = registry.list_by_domain("general")
        ids = {m.module_id for m in mods}
        assert "cve_scanner.scan" in ids

    def test_unknown_domain_returns_empty_list(self, registry):
        mods = registry.list_by_domain("nonexistent_domain")
        assert mods == []

    def test_empty_registry_returns_empty_list(self):
        r = ActiveExecutionRegistry()
        assert r.list_by_domain("token") == []


class TestDomainsSet:
    """Test ActiveExecutionRegistry.domains()."""

    @pytest.fixture
    def registry(self):
        r = ActiveExecutionRegistry()
        _register_sample_modules(r)
        return r

    def test_domains_contains_expected_categories(self, registry):
        domains = registry.domains()
        expected = {"token", "secrets", "database", "cloud",
                     "persistence", "seal", "pivot", "general"}
        assert domains == expected, (
            f"Expected domains {expected}, got {domains}"
        )

    def test_empty_registry_domains_is_empty(self):
        r = ActiveExecutionRegistry()
        assert r.domains() == set()

    def test_single_module_domain(self):
        r = ActiveExecutionRegistry()
        from active_execution.modules.persistence import PersistenceModule
        r.register(PersistenceModule())
        assert r.domains() == {"persistence"}


class TestDomainBackwardCompat:
    """Verify domain addition does not break existing module attributes."""

    def test_module_id_unchanged(self):
        from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
        m = PrivilegeEscalationModule()
        assert m.module_id == "privilege_escalation.token_abuse"

    def test_risk_level_unchanged(self):
        from active_execution.modules.privilege_escalation import PrivilegeEscalationModule
        m = PrivilegeEscalationModule()
        assert m.risk_level == RiskLevel.STATE_CHANGING

    def test_title_unchanged(self):
        from active_execution.modules.database_credential_harvest import DatabaseCredentialHarvestModule
        m = DatabaseCredentialHarvestModule()
        assert "Database Credentials Harvest" in m.title

    def test_default_enabled_unchanged(self):
        from active_execution.modules.vault_seal_manipulation import SealStatusModule
        m = SealStatusModule()
        assert m.default_enabled is True
