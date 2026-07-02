import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from core import report
from reconnaissance import vault_recon
from scanners import auth_config_scanner, capability_scanner, privilege_escalation_scanner, ttl_scanner


class FakeAiohttpResponse:
    def __init__(self, status=200, payload=None, text="", headers=None, json_error=None):
        self.status = status
        self._payload = payload or {}
        self._text = text
        self.headers = headers or {"content-type": "application/json"}
        self._json_error = json_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload

    async def text(self):
        return self._text


class FakeAiohttpSession:
    def __init__(self, responses):
        self.responses = responses
        self.requested_urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def get(self, url):
        self.requested_urls.append(url)
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    def post(self, url, json=None):
        self.requested_urls.append(url)
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


class FakeClientTimeout:
    def __init__(self, total):
        self.total = total


class FakeClientError(Exception):
    pass


class FakeRequestsResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def install_fake_aiohttp(monkeypatch, responses):
    sessions = []

    def client_session_factory(timeout=None):
        session = FakeAiohttpSession(responses)
        sessions.append(session)
        return session

    fake_aiohttp = SimpleNamespace(
        ClientTimeout=FakeClientTimeout,
        ClientSession=client_session_factory,
        ClientError=FakeClientError,
    )
    monkeypatch.setitem(sys.modules, "aiohttp", fake_aiohttp)
    return sessions


def test_async_vault_recon_successful_health_seal_and_leader_json(monkeypatch):
    target = "http://vault.test"
    responses = {
        f"{target}/v1/sys/health": FakeAiohttpResponse(
            payload={
                "initialized": True,
                "sealed": False,
                "cluster_name": "vault-cluster",
                "cluster_id": "cluster-id",
                "version": "1.17.6",
            }
        ),
        f"{target}/v1/sys/seal-status": FakeAiohttpResponse(
            payload={
                "initialized": True,
                "sealed": False,
            }
        ),
        f"{target}/v1/sys/leader": FakeAiohttpResponse(
            payload={
                "ha_enabled": True,
                "is_self": True,
                "leader_address": "https://vault-1.example:8200",
                "leader_cluster_address": "https://vault-1.example:8201",
            }
        ),
    }
    sessions = install_fake_aiohttp(monkeypatch, responses)

    result = asyncio.run(vault_recon.vault_recon(target))

    assert result["sealed"] is False
    assert result["initialized"] is True
    assert result["cluster_name"] == "vault-cluster"
    assert result["cluster_id"] == "cluster-id"
    assert result["version"] == "1.17.6"
    assert result["leader"]["ha_enabled"] is True
    assert set(sessions[0].requested_urls) == set(responses.keys())


def test_async_vault_recon_handles_failed_and_invalid_json(monkeypatch):
    target = "http://vault.test"
    responses = {
        f"{target}/v1/sys/health": FakeAiohttpResponse(
            status=500,
            payload={"errors": ["internal error"]},
        ),
        f"{target}/v1/sys/seal-status": FakeAiohttpResponse(
            status=200,
            text="{not-json",
            json_error=ValueError("invalid json"),
        ),
        f"{target}/v1/sys/leader": FakeClientError("connection refused"),
    }
    install_fake_aiohttp(monkeypatch, responses)

    result = asyncio.run(vault_recon.vault_recon(target))

    assert result["sealed"] is None
    assert result["version"] is None
    assert result["endpoints"]["health"]["status_code"] == 500
    assert result["endpoints"]["health"]["ok"] is False
    assert result["endpoints"]["seal_status"]["error"] == "invalid json response"
    assert result["endpoints"]["leader"]["error"] == "connection refused"


def test_capabilities_self_success_response_is_reported_without_live_vault(monkeypatch):
    report.findings.clear()
    fake_client = Mock()
    fake_client.sys.get_capabilities.return_value = {
        "data": {
            "sys/*": ["read", "sudo"],
            "secret/data/app": ["read"],
        }
    }
    fake_hvac = Mock(Client=Mock(return_value=fake_client))
    monkeypatch.setitem(sys.modules, "hvac", fake_hvac)

    results = capability_scanner.audit_token_capabilities(
        "http://vault.test",
        "hvs.fake-token",
        paths=["sys/*", "secret/data/app"],
    )

    assert results == [
        {"path": "sys/*", "capabilities": ["read", "sudo"]},
        {"path": "secret/data/app", "capabilities": ["read"]},
    ]
    assert any(
        finding["title"] == "Token has sudo capability on Vault path"
        for finding in report.findings
    )
    assert any(
        finding["title"] == "Over-privileged token capability on critical Vault path"
        for finding in report.findings
    )
    report.findings.clear()


def test_capabilities_self_failure_response_is_reported_without_live_vault(monkeypatch):
    report.findings.clear()
    fake_client = Mock()
    fake_client.sys.get_capabilities.side_effect = RuntimeError("permission denied")
    fake_hvac = Mock(Client=Mock(return_value=fake_client))
    monkeypatch.setitem(sys.modules, "hvac", fake_hvac)

    results = capability_scanner.audit_token_capabilities(
        "http://vault.test",
        "hvs.fake-token",
        paths=["sys/*"],
    )

    assert results == []
    assert any(
        finding["title"] == "Token capability audit failed"
        and "permission denied" in finding["evidence"]
        for finding in report.findings
    )
    report.findings.clear()


def test_privilege_escalation_audit_flags_policy_and_token_create_risk(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        f"{target}/v1/auth/token/lookup-self": FakeAiohttpResponse(
            payload={"data": {"policies": ["app-admin"], "identity_policies": []}}
        ),
        f"{target}/v1/sys/capabilities-self": FakeAiohttpResponse(
            payload={
                "data": {
                    "auth/token/create": ["read", "sudo"],
                    "auth/token/create/*": ["deny"],
                    "auth/token/create-orphan": ["deny"],
                    "sys/policies/acl/app-admin": ["read", "update"],
                }
            }
        ),
    }
    install_fake_aiohttp(monkeypatch, responses)

    result = asyncio.run(
        privilege_escalation_scanner.analyze_token_privilege_escalation(
            target,
            "hvs.fake-token",
        )
    )

    assert result["policies"] == ["app-admin"]
    assert any(
        finding["title"] == "Kritik Yetki Yükseltme Riski"
        and "auth/token/create" in finding["evidence"]
        for finding in report.findings
    )
    assert any(
        finding["title"] == "Kritik Yetki Yükseltme Riski"
        and "sys/policies/acl/app-admin" in finding["evidence"]
        for finding in report.findings
    )
    report.findings.clear()


def test_privilege_escalation_audit_passes_when_no_risky_capabilities(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        f"{target}/v1/sys/capabilities-self": FakeAiohttpResponse(
            payload={
                "data": {
                    "auth/token/create": ["deny"],
                    "auth/token/create/*": ["deny"],
                    "auth/token/create-orphan": ["deny"],
                    "sys/policies/acl/readonly": ["read"],
                }
            }
        ),
    }
    install_fake_aiohttp(monkeypatch, responses)

    result = asyncio.run(
        privilege_escalation_scanner.analyze_token_privilege_escalation(
            target,
            "hvs.fake-token",
            policy_names=["readonly"],
        )
    )

    assert len(result["results"]) == 4
    assert any(
        finding["title"] == "No token privilege escalation capability observed"
        for finding in report.findings
    )
    report.findings.clear()


def test_auth_config_audit_flags_kubernetes_aws_and_ldap_risks(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        ("GET", f"{target}/v1/sys/auth"): FakeRequestsResponse(
            payload={
                "data": {
                    "kubernetes/": {"type": "kubernetes"},
                    "aws/": {"type": "aws"},
                    "ldap/": {"type": "ldap"},
                }
            }
        ),
        ("LIST", f"{target}/v1/auth/kubernetes/role"): FakeRequestsResponse(
            payload={"data": {"keys": ["wide-k8s"]}}
        ),
        ("GET", f"{target}/v1/auth/kubernetes/role/wide-k8s"): FakeRequestsResponse(
            payload={
                "data": {
                    "bound_service_account_names": ["*"],
                    "bound_service_account_namespaces": ["*"],
                }
            }
        ),
        ("LIST", f"{target}/v1/auth/aws/role"): FakeRequestsResponse(
            payload={"data": {"keys": ["wide-aws"]}}
        ),
        ("GET", f"{target}/v1/auth/aws/role/wide-aws"): FakeRequestsResponse(
            payload={
                "data": {
                    "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/*"],
                    "bound_account_id": ["123456789012"],
                }
            }
        ),
        ("GET", f"{target}/v1/auth/ldap/config"): FakeRequestsResponse(
            payload={"data": {"url": "ldaps://ldap.example"}}
        ),
        ("GET", f"{target}/v1/sys/auth/ldap/tune"): FakeRequestsResponse(
            payload={"data": {"user_lockout": {"disable_lockout": True}}}
        ),
    }

    def fake_request(method, url, **kwargs):
        return responses[(method, url)]

    monkeypatch.setattr("scanners.auth_config_scanner.requests.request", fake_request)

    result = auth_config_scanner.scan_auth_config_security(target, "hvs.fake-token")

    assert result["risk_score"] == 100
    titles = [finding["title"] for finding in report.findings]
    assert "Kubernetes auth role allows all service accounts" in titles
    assert "AWS auth role uses wildcard IAM principal binding" in titles
    assert "LDAP user lockout appears disabled" in titles
    report.findings.clear()


def test_auth_config_audit_reports_pass_for_scoped_external_auth(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        ("GET", f"{target}/v1/sys/auth"): FakeRequestsResponse(
            payload={
                "data": {
                    "kubernetes/": {"type": "kubernetes"},
                    "aws/": {"type": "aws"},
                    "ldap/": {"type": "ldap"},
                }
            }
        ),
        ("LIST", f"{target}/v1/auth/kubernetes/role"): FakeRequestsResponse(
            payload={"data": {"keys": ["app"]}}
        ),
        ("GET", f"{target}/v1/auth/kubernetes/role/app"): FakeRequestsResponse(
            payload={
                "data": {
                    "bound_service_account_names": ["app-sa"],
                    "bound_service_account_namespaces": ["prod"],
                }
            }
        ),
        ("LIST", f"{target}/v1/auth/aws/role"): FakeRequestsResponse(
            payload={"data": {"keys": ["app"]}}
        ),
        ("GET", f"{target}/v1/auth/aws/role/app"): FakeRequestsResponse(
            payload={
                "data": {
                    "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/app"],
                    "bound_account_id": ["123456789012"],
                }
            }
        ),
        ("GET", f"{target}/v1/auth/ldap/config"): FakeRequestsResponse(
            payload={"data": {"url": "ldaps://ldap.example"}}
        ),
        ("GET", f"{target}/v1/sys/auth/ldap/tune"): FakeRequestsResponse(
            payload={"data": {"user_lockout": {"disable_lockout": False, "lockout_threshold": 5}}}
        ),
    }

    def fake_request(method, url, **kwargs):
        return responses[(method, url)]

    monkeypatch.setattr("scanners.auth_config_scanner.requests.request", fake_request)

    result = auth_config_scanner.scan_auth_config_security(target, "hvs.fake-token")

    assert result["risk_score"] == 0
    assert all(finding["severity"] == "PASS" for finding in report.findings)
    report.findings.clear()


def test_ttl_governance_flags_unlimited_mount_and_long_pki_role(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        ("GET", f"{target}/v1/sys/mounts"): FakeRequestsResponse(
            payload={
                "data": {
                    "secret/": {"type": "kv", "config": {"max_lease_ttl": 0}},
                    "database/": {"type": "database", "config": {"max_lease_ttl": "90d"}},
                    "pki/": {"type": "pki", "config": {"max_lease_ttl": "365d"}},
                }
            }
        ),
        ("LIST", f"{target}/v1/pki/roles"): FakeRequestsResponse(
            payload={"data": {"keys": ["web"]}}
        ),
        ("GET", f"{target}/v1/pki/roles/web"): FakeRequestsResponse(
            payload={"data": {"ttl": "24h", "max_ttl": "365d"}}
        ),
    }

    def fake_request(method, url, **kwargs):
        return responses[(method, url)]

    monkeypatch.setattr("scanners.ttl_scanner.requests.request", fake_request)

    result = ttl_scanner.scan_ttl_governance(
        target,
        "hvs.fake-token",
        max_mount_ttl_seconds=30 * 24 * 60 * 60,
        max_pki_cert_ttl_seconds=90 * 24 * 60 * 60,
    )

    assert result["risk_score"] == 70
    titles = [finding["title"] for finding in report.findings]
    assert "Secrets engine max lease TTL appears unlimited" in titles
    assert "Secrets engine max lease TTL exceeds policy threshold" in titles
    assert "PKI certificate role TTL exceeds policy threshold" in titles
    report.findings.clear()


def test_ttl_governance_passes_when_mounts_and_pki_roles_are_within_policy(monkeypatch):
    report.findings.clear()
    target = "http://vault.test"
    responses = {
        ("GET", f"{target}/v1/sys/mounts"): FakeRequestsResponse(
            payload={
                "data": {
                    "secret/": {"type": "kv", "config": {"max_lease_ttl": "24h"}},
                    "pki/": {"type": "pki", "config": {"max_lease_ttl": "30d"}},
                }
            }
        ),
        ("LIST", f"{target}/v1/pki/roles"): FakeRequestsResponse(
            payload={"data": {"keys": ["web"]}}
        ),
        ("GET", f"{target}/v1/pki/roles/web"): FakeRequestsResponse(
            payload={"data": {"ttl": "24h", "max_ttl": "30d"}}
        ),
    }

    def fake_request(method, url, **kwargs):
        return responses[(method, url)]

    monkeypatch.setattr("scanners.ttl_scanner.requests.request", fake_request)

    result = ttl_scanner.scan_ttl_governance(target, "hvs.fake-token")

    assert result["risk_score"] == 0
    assert any(
        finding["title"] == "No secrets engine TTL findings observed"
        for finding in report.findings
    )
    report.findings.clear()


def test_ttl_duration_parser_supports_common_vault_duration_formats():
    assert ttl_scanner.parse_duration_seconds(0) == 0
    assert ttl_scanner.parse_duration_seconds("3600") == 3600
    assert ttl_scanner.parse_duration_seconds("1h") == 3600
    assert ttl_scanner.parse_duration_seconds("1h30m") == 5400
    assert ttl_scanner.parse_duration_seconds("2d") == 172800
