import pytest

from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.modules.token.privilege_escalation import PrivilegeEscalationModule
from active_execution.modules.secrets.secret_exfiltration import SecretExfiltrationModule
from active_execution.modules.database.database_credential_harvest import DatabaseCredentialHarvestModule
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
    from active_execution.modules.token.privilege_escalation import PrivilegeEscalationModule
    from active_execution.modules.secrets.secret_exfiltration import SecretExfiltrationModule
    from active_execution.modules.database.database_credential_harvest import DatabaseCredentialHarvestModule
    from active_execution.modules.cloud.cloud_key_exfiltration import CloudKeyExfiltrationModule
    from active_execution.modules.persistence.persistence import PersistenceModule
    from active_execution.modules.seal.vault_seal_manipulation import SealStatusModule
    from active_execution.modules.pivot.pivot_engine import PivotEngineModule
    from active_execution.modules.general.cve_scanner import CVEScannerModule

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
        from active_execution.modules.token.privilege_escalation import PrivilegeEscalationModule
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
        from active_execution.modules.persistence.persistence import PersistenceModule
        r.register(PersistenceModule())
        assert r.domains() == {"persistence"}


class TestDomainBackwardCompat:
    """Verify domain addition does not break existing module attributes."""

    def test_module_id_unchanged(self):
        from active_execution.modules.token.privilege_escalation import PrivilegeEscalationModule
        m = PrivilegeEscalationModule()
        assert m.module_id == "privilege_escalation.token_abuse"

    def test_risk_level_unchanged(self):
        from active_execution.modules.token.privilege_escalation import PrivilegeEscalationModule
        m = PrivilegeEscalationModule()
        assert m.risk_level == RiskLevel.STATE_CHANGING

    def test_title_unchanged(self):
        from active_execution.modules.database.database_credential_harvest import DatabaseCredentialHarvestModule
        m = DatabaseCredentialHarvestModule()
        assert "Database Credentials Harvest" in m.title

    def test_default_enabled_unchanged(self):
        from active_execution.modules.seal.vault_seal_manipulation import SealStatusModule
        m = SealStatusModule()
        assert m.default_enabled is True


# ────────────────────────────────────────────────────────────────────────
# Transit Engine Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestTransitEngineExploit:
    """Tests for TransitEngineExploitModule."""

    def test_skips_without_token(self):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule
        context = ExecutionContext(vault_addr="https://vault.test/")
        assert not TransitEngineExploitModule().can_run(context)

    def test_skips_without_vault_addr(self):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule
        context = ExecutionContext(vault_addr="", token="hvs.test")
        assert not TransitEngineExploitModule().can_run(context)

    def test_audit_discovers_keys(self, monkeypatch):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"transit/": {"type": "transit"}}})
            if url.endswith("/keys") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["my-key", "encryption-key"]}})
            if "/keys/my-key" in url:
                return FakeResponse(payload={
                    "data": {
                        "type": "aes256-gcm96",
                        "exportable": False,
                        "derived": False,
                        "convergent_encryption": False,
                        "min_version": 1,
                        "keys": {"1": {"creation_time": "2024-01-01T00:00:00Z"}},
                    }
                })
            if "/keys/encryption-key" in url:
                return FakeResponse(payload={
                    "data": {
                        "type": "aes256-gcm96",
                        "exportable": False,
                        "min_version": 1,
                        "keys": {"1": {}},
                    }
                })
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.transit_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = TransitEngineExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert result.evidence["keys_total"] == 2
        assert len(result.evidence["mounts_found"]) == 1

    def test_finds_exportable_keys(self, monkeypatch):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"transit/": {"type": "transit"}}})
            if url.endswith("/keys") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["export-key"]}})
            if "/keys/export-key" in url:
                return FakeResponse(payload={
                    "data": {
                        "type": "aes256-gcm96",
                        "exportable": True,
                        "min_version": 1,
                        "keys": {"1": {}},
                    }
                })
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.transit_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = TransitEngineExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert len(result.evidence["exportable_keys"]) == 1
        assert any("CRITICAL" in str(f.get("severity")) for f in context.findings if "Exportable" in str(f.get("title")))

    def test_operate_encrypt_poc(self, monkeypatch):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"transit/": {"type": "transit"}}})
            if url.endswith("/keys") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["poc-key"]}})
            if "/keys/poc-key" in url and method == "GET":
                return FakeResponse(payload={
                    "data": {"type": "aes256-gcm96", "exportable": False, "keys": {"1": {}}}
                })
            if "/encrypt/" in url:
                return FakeResponse(payload={"data": {"ciphertext": "vault:v1:abcd1234"}})
            if "/decrypt/" in url:
                return FakeResponse(payload={
                    "data": {"plaintext": "dmF1bHQtcGVudGVzdC10cmFuc2l0LXBvYw=="}
                })
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.transit_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = TransitEngineExploitModule().execute(context, {"mode": "operate"})

        assert result.status == "success"
        ops = result.evidence.get("operations_performed", [])
        assert any(op["op"] == "encrypt" and op["status"] == "success" for op in ops)
        assert any(op["op"] == "decrypt" and op["status"] == "success" for op in ops)

    def test_detects_convergent_encryption(self, monkeypatch):
        from active_execution.modules.secrets.transit_engine_exploit import TransitEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"transit/": {"type": "transit"}}})
            if url.endswith("/keys") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["convergent-key"]}})
            if "/keys/convergent-key" in url:
                return FakeResponse(payload={
                    "data": {
                        "type": "aes256-gcm96",
                        "exportable": False,
                        "convergent_encryption": True,
                        "keys": {"1": {}},
                    }
                })
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.transit_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = TransitEngineExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert any("Convergent" in str(f.get("title")) for f in context.findings)


# ────────────────────────────────────────────────────────────────────────
# Vault Agent / Sidecar Attack tests
# ────────────────────────────────────────────────────────────────────────


class TestAgentSidecarAttack:
    """Tests for AgentSidecarAttackModule."""

    def test_discovers_hcl_configs(self, monkeypatch, tmp_path):
        from active_execution.modules.general.agent_sidecar_attack import AgentSidecarAttackModule

        # Create a mock agent config file
        agent_dir = tmp_path / "vault-agent"
        agent_dir.mkdir()
        config_file = agent_dir / "agent.hcl"
        config_file.write_text("""
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/etc/vault/role_id"
      secret_id_file_path = "/etc/vault/secret_id"
    }
  }
  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}
""")

        context = ExecutionContext(vault_addr="https://vault.test/")
        result = AgentSidecarAttackModule().execute(
            context, {"path": str(agent_dir)}
        )

        assert result.status == "success"
        assert len(result.evidence["config_files_found"]) >= 1
        assert any("approle" in str(m).lower() for m in result.evidence.get("auto_auth_methods", []))

    def test_detects_exit_after_auth(self, tmp_path):
        from active_execution.modules.general.agent_sidecar_attack import AgentSidecarAttackModule

        agent_dir = tmp_path / "vault-agent2"
        agent_dir.mkdir()
        config_file = agent_dir / "agent.hcl"
        config_file.write_text("""
exit_after_auth = true
auto_auth {
  method "kubernetes" {
    config = {
      role = "my-role"
    }
  }
}
""")

        context = ExecutionContext(vault_addr="https://vault.test/")
        result = AgentSidecarAttackModule().execute(
            context, {"path": str(agent_dir)}
        )

        assert result.status == "success"
        assert any(
            "exit_after_auth" in str(m).lower()
            for m in result.evidence.get("misconfigurations", [])
        )

    def test_detects_env_token(self, monkeypatch):
        from active_execution.modules.general.agent_sidecar_attack import AgentSidecarAttackModule

        monkeypatch.setenv("VAULT_TOKEN", "hvs.s3cr3tT0k3nFr0mEnv")
        monkeypatch.setenv("VAULT_ADDR", "https://vault.internal:8200")

        context = ExecutionContext(vault_addr="https://vault.test/")
        result = AgentSidecarAttackModule().execute(context, {"path": "/tmp/nonexistent"})

        assert result.status == "success"
        assert len(result.evidence.get("env_tokens", [])) >= 1
        assert any("HIGH" in str(f.get("severity")) for f in context.findings if "Environment" in str(f.get("title")))

    def test_reads_sink_token(self, tmp_path):
        from active_execution.modules.general.agent_sidecar_attack import AgentSidecarAttackModule

        agent_dir = tmp_path / "vault-agent3"
        agent_dir.mkdir()
        sink_file = tmp_path / "sink-token.txt"
        sink_file.write_text("hvs.CAFESECRETSINKTOKEN1234")

        config_file = agent_dir / "agent.hcl"
        config_file.write_text(f"""
auto_auth {{
  method "approle" {{
    config = {{}}
  }}
  sink "file" {{
    config = {{
      path = "{sink_file}"
    }}
  }}
}}
""")

        context = ExecutionContext(vault_addr="https://vault.test/")
        result = AgentSidecarAttackModule().execute(
            context, {"path": str(agent_dir)}
        )

        assert result.status == "success"
        assert len(result.evidence.get("sink_tokens", [])) >= 1
        assert any("CRITICAL" in str(f.get("severity")) for f in context.findings if "Sink Token" in str(f.get("title")))


# ────────────────────────────────────────────────────────────────────────
# PKI Engine Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestPKIEngineExploit:
    """Tests for PKIEngineExploitModule."""

    def test_skips_without_token(self):
        from active_execution.modules.secrets.pki_engine_exploit import PKIEngineExploitModule
        context = ExecutionContext(vault_addr="https://vault.test/")
        assert not PKIEngineExploitModule().can_run(context)

    def test_audit_downloads_ca(self, monkeypatch):
        from active_execution.modules.secrets.pki_engine_exploit import PKIEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"pki/": {"type": "pki"}}})
            if url.endswith("/ca") and "/ca/pem" not in url:
                return FakeResponse(payload={"data": {"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"}})
            if url.endswith("/ca/pem"):
                return FakeResponse(text="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----")
            if "/roles" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": []}})
            if "/config/urls" in url:
                return FakeResponse(payload={"data": {"issuing_certificates": "http://vault:8200/v1/pki/ca"}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.pki_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = PKIEngineExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert len(result.evidence.get("ca_certificates", [])) >= 1

    def test_deep_role_audit_allow_any_name(self, monkeypatch):
        from active_execution.modules.secrets.pki_engine_exploit import PKIEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"pki/": {"type": "pki"}}})
            if url.endswith("/roles") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["dangerous-role"]}})
            if "dangerous-role" in url:
                return FakeResponse(payload={
                    "data": {
                        "allow_any_name": True,
                        "allow_ip_sans": False,
                        "allow_localhost": False,
                        "enforce_hostnames": True,
                        "max_ttl": 86400,
                        "key_usage": ["DigitalSignature"],
                    }
                })
            if "/ca/pem" in url:
                return FakeResponse(status_code=200, text="-----BEGIN CERTIFICATE-----\nMIIB...")
            if "/ca" == url.split("/v1/pki")[-1] if "/v1/pki" in url else False:
                return FakeResponse(payload={"data": {"certificate": "..."}})
            if "/config/urls" in url:
                return FakeResponse(payload={"data": {}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.pki_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = PKIEngineExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert result.evidence["roles_audited"] >= 1
        flags = result.evidence.get("critical_flags", [])
        assert any("allow_any_name" in str(f) for f in flags)

    def test_cert_issuance_poc(self, monkeypatch):
        from active_execution.modules.secrets.pki_engine_exploit import PKIEngineExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"pki/": {"type": "pki"}}})
            if url.endswith("/roles") and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["test-role"]}})
            if "test-role" in url and method == "GET":
                return FakeResponse(payload={
                    "data": {"allow_any_name": False, "enforce_hostnames": True, "max_ttl": 86400}
                })
            if "/issue/test-role" in url:
                return FakeResponse(payload={
                    "data": {
                        "certificate": "-----BEGIN CERTIFICATE-----\ntest",
                        "private_key": "-----BEGIN RSA PRIVATE KEY-----\ntest",
                        "serial_number": "12:34:56",
                    }
                })
            if "/ca/pem" in url:
                return FakeResponse(status_code=200, text="-----BEGIN CERTIFICATE-----\nMIIB...")
            if "/config/urls" in url:
                return FakeResponse(payload={"data": {}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.pki_engine_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = PKIEngineExploitModule().execute(
            context, {"mode": "operate", "issue_test_cert": True}
        )

        assert result.status == "success"
        assert result.evidence.get("cert_issued") is True


# ────────────────────────────────────────────────────────────────────────
# Kubernetes Auth Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestKubernetesAuthExploit:
    """Tests for KubernetesAuthExploitModule."""

    def test_discovers_k8s_mounts(self, monkeypatch):
        from active_execution.modules.token.kubernetes_auth_exploit import KubernetesAuthExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={
                    "data": {
                        "kubernetes/": {"type": "kubernetes"},
                        "k8s-us-east/": {"type": "kubernetes"},
                    }
                })
            if "/config" in url:
                return FakeResponse(payload={
                    "data": {
                        "issuer": "https://kubernetes.default.svc.cluster.local",
                        "disable_iss_validation": False,
                        "disable_local_ca_jwt": False,
                    }
                })
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": []}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.kubernetes_auth_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = KubernetesAuthExploitModule().execute(context)

        assert result.status == "success"
        assert len(result.evidence["mounts_found"]) == 2

    def test_decode_jwt(self, monkeypatch):
        from active_execution.modules.token.kubernetes_auth_exploit import _decode_jwt_claims

        # Construct a mock JWT: header.payload.signature
        import base64, json
        payload = {
            "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": "system:serviceaccount:default:my-sa",
            "kubernetes.io/serviceaccount/namespace": "default",
            "kubernetes.io/serviceaccount/name": "my-sa",
        }
        payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        jwt = f"header.{payload_b64}.signature"

        claims = _decode_jwt_claims(jwt)
        assert claims is not None
        assert claims["kubernetes.io/serviceaccount/name"] == "my-sa"
        assert claims["kubernetes.io/serviceaccount/namespace"] == "default"

    def test_detects_issuer_validation_disabled(self, monkeypatch):
        from active_execution.modules.token.kubernetes_auth_exploit import KubernetesAuthExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"kubernetes/": {"type": "kubernetes"}}})
            if "/config" in url:
                return FakeResponse(payload={
                    "data": {
                        "issuer": "https://evil.k8s.io",
                        "disable_iss_validation": True,
                        "disable_local_ca_jwt": True,
                    }
                })
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": []}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.kubernetes_auth_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = KubernetesAuthExploitModule().execute(context)

        assert result.status == "success"
        suspicious = result.evidence.get("suspicious_configs", [])
        assert len(suspicious) >= 2
        flag_names = [s["flag"] for s in suspicious]
        assert "disable_iss_validation" in flag_names
        assert "disable_local_ca_jwt" in flag_names

    def test_role_wildcard_detection(self, monkeypatch):
        from active_execution.modules.token.kubernetes_auth_exploit import KubernetesAuthExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"kubernetes/": {"type": "kubernetes"}}})
            if "/config" in url:
                return FakeResponse(payload={"data": {"issuer": "https://kubernetes.default.svc"}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["wildcard-role"]}})
            if "wildcard-role" in url and method == "GET":
                return FakeResponse(payload={
                    "data": {
                        "bound_service_account_names": ["*"],
                        "bound_service_account_namespaces": ["*"],
                        "policies": ["default"],
                    }
                })
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.kubernetes_auth_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = KubernetesAuthExploitModule().execute(context)

        assert result.status == "success"
        assert any("Wildcard" in str(f.get("title")) for f in context.findings)


# ────────────────────────────────────────────────────────────────────────
# Auth config scanner extension tests
# ────────────────────────────────────────────────────────────────────────


class TestK8sAuthConfigScannerExtension:
    """Tests for the K8s auth config deep audit in auth_config_scanner."""

    def test_flags_disabled_issuer_validation(self, monkeypatch):
        from scanners import auth_config_scanner

        def fake_request(method, vault_addr, path, token, namespace):
            class FakeResp:
                status_code = 200
                def json(self):
                    return {}
            resp = FakeResp()

            if "role" in path:
                resp.json = lambda: {"data": {"keys": ["test-role"]}}
                return resp
            if "test-role" in path:
                resp.json = lambda: {"data": {
                    "bound_service_account_names": ["default"],
                    "bound_service_account_namespaces": ["default"],
                }}
                return resp
            if "config" in path:
                resp.json = lambda: {"data": {
                    "kubernetes_host": "https://k8s:6443",
                    "issuer": "https://kubernetes.default.svc",
                    "disable_iss_validation": True,
                    "disable_local_ca_jwt": False,
                }}
                return resp
            return resp

        monkeypatch.setattr(auth_config_scanner, "_vault_request", fake_request)

        checks = auth_config_scanner._audit_kubernetes_auth_config(
            "https://vault.test", "hvs.t", None, {"path": "kubernetes/"}
        )
        assert any("CRITICAL" in str(c.get("severity")) or "DISABLED" in str(c.get("title")) for c in checks)

    def test_flags_disabled_ca_jwt(self, monkeypatch):
        from scanners import auth_config_scanner

        def fake_request(method, vault_addr, path, token, namespace):
            class FakeResp:
                status_code = 200
                def json(self):
                    return {}
            resp = FakeResp()

            if "config" in path:
                resp.json = lambda: {"data": {
                    "kubernetes_host": "https://k8s:6443",
                    "issuer": "https://kubernetes.default.svc",
                    "disable_iss_validation": False,
                    "disable_local_ca_jwt": True,
                }}
                return resp
            return resp

        monkeypatch.setattr(auth_config_scanner, "_vault_request", fake_request)

        checks = auth_config_scanner._audit_kubernetes_auth_config(
            "https://vault.test", "hvs.t", None, {"path": "kubernetes/"}
        )
        assert any("HIGH" in str(c.get("severity")) for c in checks)
        assert any("disable" in str(c.get("title")).lower() and "jwt" in str(c.get("title")).lower() for c in checks)


# ────────────────────────────────────────────────────────────────────────
# Tier 2: JWT/OIDC Auth Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestJWTOIDCExploit:
    """Tests for JWTOIDCExploitModule."""

    def test_discovers_jwt_oidc_mounts(self, monkeypatch):
        from active_execution.modules.token.jwt_oidc_exploit import JWTOIDCExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {
                    "oidc/": {"type": "oidc"},
                    "jwt/": {"type": "jwt"},
                }})
            if "/config" in url:
                return FakeResponse(payload={"data": {"bound_issuer": "https://idp.example.com"}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": []}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.jwt_oidc_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = JWTOIDCExploitModule().execute(context)

        assert result.status == "success"
        assert len(result.evidence["mounts_found"]) == 2

    def test_detects_wildcard_bound_issuer(self, monkeypatch):
        from active_execution.modules.token.jwt_oidc_exploit import JWTOIDCExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"oidc/": {"type": "oidc"}}})
            if "/config" in url:
                return FakeResponse(payload={"data": {"bound_issuer": "*"}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": []}})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.jwt_oidc_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = JWTOIDCExploitModule().execute(context)

        assert result.status == "success"
        assert any("Wildcard" in str(f.get("title")) for f in context.findings)

    def test_audit_role_no_bound_audiences(self, monkeypatch):
        from active_execution.modules.token.jwt_oidc_exploit import JWTOIDCExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"jwt/": {"type": "jwt"}}})
            if "/config" in url:
                return FakeResponse(payload={"data": {}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["test-role"]}})
            if "test-role" in url:
                return FakeResponse(payload={"data": {
                    "bound_claims": {"group": "admin"},
                    "bound_audiences": [],
                    "token_policies": ["default"],
                }})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.jwt_oidc_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = JWTOIDCExploitModule().execute(context)

        assert result.status == "success"
        assert any("audiences" in str(f.get("title")).lower() or "No Bound" in str(f.get("title")) for f in context.findings)


# ────────────────────────────────────────────────────────────────────────
# Tier 2: Raft Storage Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestRaftStorageExploit:
    """Tests for RaftStorageExploitModule."""

    def test_api_reads_raft_config(self, monkeypatch):
        from active_execution.modules.secrets.raft_storage_exploit import RaftStorageExploitModule

        def fake_request(method, url, headers=None, stream=None, timeout=None, verify=None, **kwargs):
            if "raft/configuration" in url:
                return FakeResponse(payload={"data": {"config": {
                    "servers": [{"address": "node1:8201", "leader": True}],
                    "leader": "node1",
                }}})
            if "raft/autopilot" in url:
                return FakeResponse(status_code=404)
            if "raft/snapshot" in url:
                resp = FakeResponse(status_code=200)
                resp.iter_content = lambda chunk_size: [b"snapshot-data"]
                return resp
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.secrets.raft_storage_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = RaftStorageExploitModule().execute(context, {"mode": "api"})

        assert result.status == "success"
        assert result.evidence["api"]["cluster_nodes"] >= 1

    def test_filesystem_parses_raft_db(self, monkeypatch, tmp_path):
        from active_execution.modules.secrets.raft_storage_exploit import RaftStorageExploitModule
        import sqlite3

        # Create a mock raft.db
        data_dir = tmp_path / "vault-data"
        data_dir.mkdir()
        db_path = data_dir / "raft.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE logs (type INTEGER, data BLOB)")
        conn.execute("INSERT INTO logs VALUES (0, ?)", (b"test log entry with secret/path",))
        conn.commit()
        conn.close()

        # Also create peers.json
        import json
        (data_dir / "peers.json").write_text(json.dumps([{"id": "node1", "address": "localhost:8201"}]))

        context = ExecutionContext(vault_addr="https://vault.test/")
        result = RaftStorageExploitModule().execute(
            context, {"mode": "filesystem", "data_path": str(data_dir)}
        )

        assert result.status == "success"
        assert "raft_db" in str(result.evidence.get("filesystem", {}))
        assert "peers" in str(result.evidence.get("filesystem", {}))


# ────────────────────────────────────────────────────────────────────────
# Tier 2: AppRole Exploit tests
# ────────────────────────────────────────────────────────────────────────


class TestAppRoleExploit:
    """Tests for AppRoleExploitModule."""

    def test_detects_bind_secret_id_disabled(self, monkeypatch):
        from active_execution.modules.token.approle_exploit import AppRoleExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"approle/": {"type": "approle"}}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["unsafe-role"]}})
            if "unsafe-role" in url:
                return FakeResponse(payload={"data": {
                    "bind_secret_id": False,
                    "secret_id_num_uses": 0,
                    "secret_id_ttl": 0,
                    "token_bound_cidrs": [],
                    "token_num_uses": 0,
                }})
            return FakeResponse(status_code=404)

        monkeypatch.setattr("active_execution.modules.token.approle_exploit.vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = AppRoleExploitModule().execute(context, {"mode": "audit"})

        assert result.status == "success"
        assert any("bind_secret_id" in str(f.get("title")).lower() for f in context.findings)

    def test_cidr_bypass_attempt(self, monkeypatch):
        from active_execution.modules.token.approle_exploit import AppRoleExploitModule

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            if "/v1/sys/mounts" in url:
                return FakeResponse(payload={"data": {"approle/": {"type": "approle"}}})
            if "/role" in url and method == "LIST":
                return FakeResponse(payload={"data": {"keys": ["test-role"]}})
            if "test-role" in url and method == "GET":
                return FakeResponse(payload={"data": {"bind_secret_id": True}})
            return FakeResponse(status_code=404)

        # Mock requests.post for login attempts
        def fake_post(url, json=None, headers=None, timeout=None, verify=None, **kwargs):
            return FakeResponse(status_code=401)

        monkeypatch.setattr("active_execution.modules.token.approle_exploit.vault_request", fake_request)
        monkeypatch.setattr("active_execution.modules.token.approle_exploit.requests.post", fake_post)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = AppRoleExploitModule().execute(
            context, {"mode": "exploit", "role_id": "test-role-id"}
        )

        assert result.status == "success"
        assert len(result.evidence.get("bypass_tests", [])) > 0


# ────────────────────────────────────────────────────────────────────────
# Tier 2: Audit Backdoor extension tests
# ────────────────────────────────────────────────────────────────────────


class TestAuditBackdoorExtended:
    """Tests for extended audit backdoor capabilities."""

    def test_disables_audit_devices(self, monkeypatch):
        from active_execution.modules.persistence.audit_backdoor import AuditBackdoorModule
        import core.tls_config

        def fake_request(method, url, headers=None, json=None, timeout=None, verify=None, **kwargs):
            # Only allow GET on sys/audit listing; everything else = 204 (success delete)
            if "/v1/sys/audit" in url:
                if method == "GET":
                    return FakeResponse(payload={"data": {
                        "file-audit/": {"type": "file", "options": {"file_path": "/tmp/audit.log"}},
                    }})
                return FakeResponse(status_code=204)
            # Block all other calls (syslog injection, audit-hash) so they don't interfere
            return FakeResponse(status_code=403)

        monkeypatch.setattr(core.tls_config, "vault_request", fake_request)

        context = ExecutionContext(vault_addr="https://vault.test/", token="hvs.test", verify_tls=False)
        result = AuditBackdoorModule().execute(context)

        assert result.status == "success"
        assert "Audit Logs Disabled" in str(context.findings)

    def test_can_run_requires_token(self):
        from active_execution.modules.persistence.audit_backdoor import AuditBackdoorModule
        context = ExecutionContext(vault_addr="https://vault.test/")
        assert not AuditBackdoorModule().can_run(context)
