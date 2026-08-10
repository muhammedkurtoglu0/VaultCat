import asyncio

from ai_core import mcp_server


class FakeModuleResult:
    def __init__(self, status, message, evidence=None):
        self.status = status
        self.message = message
        self.evidence = evidence or {}


def test_mcp_privilege_escalation_requires_target_and_token_schema():
    tools = asyncio.run(mcp_server.mcp_server.list_tools())
    tool = next(item for item in tools if item.name == "run_privilege_escalation")
    schema = mcp_server.tool_schema(tool)

    assert "vault_addr" in schema["properties"]
    assert "token" in schema["properties"]
    assert "vault_addr" in schema["required"]
    assert "token" in schema["required"]


def test_mcp_secret_exfiltration_requires_target_but_token_is_optional_schema():
    tools = asyncio.run(mcp_server.mcp_server.list_tools())
    tool = next(item for item in tools if item.name == "run_secret_exfiltration")
    schema = mcp_server.tool_schema(tool)

    assert "vault_addr" in schema["properties"]
    assert "token" in schema["properties"]
    assert "vault_addr" in schema["required"]
    assert "token" not in schema["required"]


def test_mcp_policy_auditor_tool_is_exposed_with_target_and_token_schema():
    tools = asyncio.run(mcp_server.mcp_server.list_tools())
    tool = next(item for item in tools if item.name == "run_policy_auditor")
    schema = mcp_server.tool_schema(tool)

    assert "vault_addr" in schema["required"]
    assert "token" in schema["required"]


def test_mcp_recon_returns_only_findings_from_current_call(monkeypatch):
    class FakeReconContext:
        def __init__(self, target):
            self.target = target

        def fetch_health_once(self):
            return None

    def noop_scan(*args, **kwargs):
        return None

    def fake_health_scan(vault_addr, context=None):
        mcp_server.report_findings.append({
            "severity": "HIGH",
            "title": f"current health finding for {vault_addr}",
            "module": "health_scanner",
            "target": vault_addr,
        })

    mcp_server.report_findings.clear()
    mcp_server.report_findings.append({
        "severity": "HIGH",
        "title": "stale finding from previous target",
        "module": "health_scanner",
        "target": "https://old-target.test",
    })

    monkeypatch.setattr(mcp_server, "ReconContext", FakeReconContext)
    for name in (
        "scan_tls",
        "scan_version_risk",
        "scan_fingerprint",
        "scan_ui",
        "scan_auth_surface",
        "scan_deployment",
        "scan_cors",
        "scan_headers",
        "scan_endpoints",
    ):
        monkeypatch.setattr(mcp_server, name, noop_scan)
    monkeypatch.setattr(mcp_server, "scan_health", fake_health_scan)

    result = asyncio.run(mcp_server.run_unauthenticated_recon("https://new-target.test"))

    assert "current health finding for https://new-target.test" in result
    assert "stale finding from previous target" not in result
    assert '"findings_count": 1' in result

    mcp_server.report_findings.clear()


def test_mcp_run_policy_auditor_invokes_scanner_and_returns_findings(monkeypatch):
    def fake_scan(vault_addr, token, namespace=None):
        assert vault_addr == "http://vault.test:8200"
        assert token == "hvs.token"
        mcp_server.report_findings.append({
            "severity": "HIGH",
            "title": "High-risk capability on critical Vault ACL path",
            "description": "test",
            "module": "policy_scanner",
        })
        return {"policies": ["admin"], "audited": ["admin"], "denied": []}

    monkeypatch.setattr(mcp_server, "scan_policy_audit", fake_scan)
    mcp_server.report_findings.clear()

    result = asyncio.run(mcp_server.run_policy_auditor(
        vault_addr="http://vault.test:8200",
        token="hvs.token",
    ))

    assert '"status": "completed"' in result
    assert '"policies_analyzed": 1' in result
    assert "High-risk capability on critical Vault ACL path" in result

    mcp_server.report_findings.clear()


def test_mcp_generic_active_module_tools_are_exposed():
    tools = asyncio.run(mcp_server.mcp_server.list_tools())
    tool_names = {tool.name for tool in tools}

    assert "list_active_modules" in tool_names
    assert "run_active_module" in tool_names

    runner = next(item for item in tools if item.name == "run_active_module")
    schema = mcp_server.tool_schema(runner)
    assert "module_id" in schema["required"]
    assert "vault_addr" in schema["required"]
    assert "params" in schema["properties"]


def test_mcp_privilege_escalation_uses_arguments_and_stores_captured_token(monkeypatch):
    mcp_server.pentest_context["captured_token"] = None

    def fake_execute(self, context, params):
        assert context.vault_addr == "http://vault.test:8200"
        assert context.token == "hvs.low-token"
        assert context.namespace == "admin"
        assert params["ttl"] == "15m"
        assert params["namespace"] == "admin"
        return FakeModuleResult(
            "success",
            "ok",
            {"captured_token": "hvs.admin-token", "selected_policy": "admin"},
        )

    monkeypatch.setattr(
        "active_execution.modules.token.privilege_escalation.PrivilegeEscalationModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_privilege_escalation(
        vault_addr="http://vault.test:8200/",
        token="hvs.low-token",
        ttl="15m",
        namespace="admin",
    ))

    # Token is now redacted in JSON response: "hvs.admin-token" (15 chars) → "<redacted>"
    assert "<redacted>" in result
    assert "admin" in result  # selected_policy still visible
    assert "success" in result
    assert mcp_server.pentest_context["captured_token"] == "hvs.admin-token"


def test_mcp_secret_exfiltration_uses_captured_token_when_token_argument_missing(monkeypatch):
    mcp_server.pentest_context["captured_token"] = "hvs.admin-token"

    def fake_execute(self, context, params):
        assert context.vault_addr == "http://vault.test:8200"
        assert context.token == "hvs.admin-token"
        assert context.captured_token == "hvs.admin-token"
        assert params["max_depth"] == 2
        return FakeModuleResult(
            "success",
            "ok",
            {"leaked_payloads": {"secret/app": {"password": "super-secret"}}},
        )

    monkeypatch.setattr(
        "active_execution.modules.secrets.secret_exfiltration.SecretExfiltrationModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_secret_exfiltration(
        vault_addr="http://vault.test:8200/",
        max_depth=2,
    ))

    assert "Sizdirma basarili" in result
    assert "super-secret" in result


def test_mcp_secret_exfiltration_can_use_explicit_token(monkeypatch):
    mcp_server.pentest_context["captured_token"] = None

    def fake_execute(self, context, params):
        assert context.token == "hvs.explicit-token"
        assert context.captured_token == "hvs.explicit-token"
        return FakeModuleResult("failed", "no secrets", {"total_leaked_secrets": 0})

    monkeypatch.setattr(
        "active_execution.modules.secrets.secret_exfiltration.SecretExfiltrationModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_secret_exfiltration(
        vault_addr="http://vault.test:8200/",
        token="hvs.explicit-token",
    ))

    assert "Sizdirma basarisiz" in result


def test_mcp_list_active_modules_returns_registry_metadata():
    result = asyncio.run(mcp_server.list_active_modules())

    assert "privilege_escalation.token_abuse" in result
    assert "secret_exfiltration.kv_dump" in result
    assert "database_credential_harvest.dynamic_creds" in result
    assert "risk_level" in result


def test_mcp_database_credential_harvest_tool_is_exposed():
    tools = asyncio.run(mcp_server.mcp_server.list_tools())
    tool_names = {tool.name for tool in tools}

    assert "run_database_credential_harvest" in tool_names

    tool = next(item for item in tools if item.name == "run_database_credential_harvest")
    schema = mcp_server.tool_schema(tool)
    assert "vault_addr" in schema["properties"]
    assert "vault_addr" in schema["required"]
    assert "token" in schema["properties"]
    assert "token" not in schema["required"]  # opsiyonel: captured_token kullanılabilir
    assert "mount_path" in schema["properties"]


def test_mcp_database_credential_harvest_returns_error_without_token(monkeypatch):
    mcp_server.pentest_context["captured_token"] = None

    result = asyncio.run(mcp_server.run_database_credential_harvest(
        vault_addr="http://vault.test:8200",
    ))

    assert '"status": "error"' in result
    assert "token" in result.lower()


def test_mcp_database_credential_harvest_invokes_module_and_returns_credentials(monkeypatch):
    mcp_server.pentest_context["captured_token"] = None

    def fake_execute(self, context, params):
        assert context.vault_addr == "http://vault.test:8200"
        assert context.token == "hvs.db-token"
        assert params.get("mount_path") == "database/"
        return FakeModuleResult(
            "success",
            "Harvested 1 credential set(s); 1 flagged as high-privilege.",
            {
                "db_mounts": ["database/"],
                "total_harvested": 1,
                "high_privilege_count": 1,
                "credentials": [
                    {
                        "mount": "database",
                        "role": "dba-role",
                        "type": "dynamic",
                        "username": "v-dba-xyz",
                        "password": "secret-pw",
                        "lease_duration_seconds": 3600,
                        "high_privilege": True,
                    }
                ],
                "errors": [],
            },
        )

    monkeypatch.setattr(
        "active_execution.modules.database.database_credential_harvest.DatabaseCredentialHarvestModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_database_credential_harvest(
        vault_addr="http://vault.test:8200/",
        token="hvs.db-token",
        mount_path="database/",
    ))

    assert '"status": "success"' in result
    assert '"total_harvested": 1' in result
    assert '"high_privilege_count": 1' in result
    assert "v-dba-xyz" in result
    assert "secret-pw" in result


def test_mcp_run_active_module_blocks_above_max_risk():
    result = asyncio.run(mcp_server.run_active_module(
        module_id="privilege_escalation.token_abuse",
        vault_addr="http://vault.test:8200",
        token="hvs.low-token",
        max_risk="read_only",
    ))

    assert '"status": "blocked"' in result
    assert "state_changing" in result


def test_mcp_run_active_module_executes_registered_module_and_stores_token(monkeypatch):
    mcp_server.pentest_context["captured_token"] = None

    def fake_execute(self, context, params):
        assert context.vault_addr == "http://vault.test:8200"
        assert context.token == "hvs.low-token"
        assert params["ttl"] == "20m"
        return FakeModuleResult(
            "success",
            "ok",
            {"captured_token": "hvs.generic-admin-token"},
        )

    monkeypatch.setattr(
        "active_execution.modules.token.privilege_escalation.PrivilegeEscalationModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_active_module(
        module_id="privilege_escalation.token_abuse",
        vault_addr="http://vault.test:8200/",
        token="hvs.low-token",
        params={"ttl": "20m"},
        max_risk="state_changing",
    ))

    # Token is now redacted in JSON response: "hvs.generic-admin-token" → "hvs.gene...oken"
    assert "hvs.gene...oken" in result
    assert "success" in result
    assert mcp_server.pentest_context["captured_token"] == "hvs.generic-admin-token"


def test_mcp_run_active_module_uses_captured_token_when_token_missing(monkeypatch):
    mcp_server.pentest_context["captured_token"] = "hvs.captured"

    def fake_execute(self, context, params):
        assert context.token == "hvs.captured"
        assert context.captured_token == "hvs.captured"
        return FakeModuleResult("failed", "no secrets", {"total_leaked_secrets": 0})

    monkeypatch.setattr(
        "active_execution.modules.secrets.secret_exfiltration.SecretExfiltrationModule.execute",
        fake_execute,
    )

    result = asyncio.run(mcp_server.run_active_module(
        module_id="secret_exfiltration.kv_dump",
        vault_addr="http://vault.test:8200/",
        max_risk="read_only",
    ))

    assert '"status": "failed"' in result
    assert "no secrets" in result
