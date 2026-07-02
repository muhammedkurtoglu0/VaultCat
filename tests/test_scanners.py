from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from requests import Response

from core import report
from credential_hijacking.file_secret_scanner import (
    _is_material_value,
    _parse_git_grep_line,
    _scan_text,
    mask_value,
    scan_files,
)
from credential_hijacking.hijack_analyzer import analyze_hijack_findings
from credential_hijacking.patterns import PATTERNS
from reconnaissance import auth_surface_scanner, cors_scanner, recon_context, version_cve_matcher, version_risk_scanner
from reconnaissance.health_scanner import scan_health
from reconnaissance.recon_context import ReconContext
from scanners import capability_scanner, kv_enumerator, policy_scanner


@pytest.fixture(autouse=True)
def clear_findings():
    report.findings.clear()
    yield
    report.findings.clear()


def make_response(status_code=200, json_data=None, text="", headers=None, json_error=False):
    response = Response()
    response.status_code = status_code
    response._content = text.encode("utf-8")
    response.headers.update(headers or {})

    if json_error:
        response.json = Mock(side_effect=ValueError("not json"))
    else:
        response.json = Mock(return_value=json_data or {})

    return response


def finding_titles():
    return [finding["title"] for finding in report.findings]


TOKEN_PATTERNS = {
    "vault_token_value",
    "vault_token_assignment",
    "vault_response_wrapped_token",
}


def test_patterns_detect_vault_material_and_database_risk():
    text = """
    VAULT_TOKEN=hvs.abcdefghijklmnopqrstuvwxyz
    WRAPPED_TOKEN=hvs.CAESabcdefghijklmnopqrstuvwxyz123456
    VAULT_ROLE_ID=fake-role-id-123
    VAULT_SECRET_ID=fake-secret-id-456
    VAULT_ADDR=http://localhost:8200
    auth/approle/login
    database/roles/payments
    creation_statements="CREATE ROLE \"{{name}}\"; DROP DATABASE payment;"
    default_ttl=2h
    """

    assert PATTERNS["vault_token_assignment"].search(text).group(1) == "hvs.abcdefghijklmnopqrstuvwxyz"
    assert PATTERNS["vault_response_wrapped_token"].search(text).group(0) == "hvs.CAESabcdefghijklmnopqrstuvwxyz123456"
    assert PATTERNS["vault_role_id"].search(text).group(1) == "fake-role-id-123"
    assert PATTERNS["vault_secret_id"].search(text).group(1) == "fake-secret-id-456"
    assert PATTERNS["vault_addr_assignment"].search(text).group(1) == "http://localhost:8200"
    assert PATTERNS["approle_login"].search(text)
    assert PATTERNS["vault_database_role_path"].search(text)
    assert PATTERNS["vault_database_destructive_statement"].search(text)
    assert PATTERNS["vault_database_default_ttl"].search(text).group(1) == "2h"


def test_recon_context_fetches_health_once(monkeypatch):
    calls = []
    response = make_response(200, json_data={"initialized": True})

    def fake_safe_request(method, target, path, allow_redirects=True):
        calls.append((method, target, path, allow_redirects))
        return response

    monkeypatch.setattr(recon_context, "safe_request", fake_safe_request)

    context = ReconContext("http://vault.test")

    assert context.fetch_health_once() is response
    assert context.fetch_health_once() is response
    assert context.request_once("GET", "/v1/sys/health") is response
    assert calls == [("GET", "http://vault.test", "/v1/sys/health", True)]


def test_placeholder_values_are_context_not_material():
    assert _is_material_value("vault_secret_id", "fake-secret-id-456")
    assert not _is_material_value("vault_secret_id", "${VAULT_SECRET_ID}")
    assert not _is_material_value("vault_token_assignment", "{{ vault_token }}")
    assert mask_value("hvs.abcdefghijklmnopqrstuvwxyz") == "hvs.abc...wxyz"


def test_scan_text_deduplicates_and_masks_sensitive_values(tmp_path):
    source = tmp_path / ".env"
    source.write_text(
        "\n".join([
            "VAULT_TOKEN=hvs.abcdefghijklmnopqrstuvwxyz",
            "VAULT_TOKEN=hvs.abcdefghijklmnopqrstuvwxyz",
            "VAULT_ROLE_ID=fake-role-id-123",
            "VAULT_SECRET_ID=fake-secret-id-456",
        ]),
        encoding="utf-8",
    )

    matches = _scan_text(source, source.read_text(encoding="utf-8"))

    token_matches = [match for match in matches if match["pattern"] in TOKEN_PATTERNS]
    assert len(token_matches) >= 2
    assert any(match["pattern"] == "vault_token_value" for match in token_matches)
    assert token_matches[0]["masked_value"] == "hvs.abc...wxyz"
    assert any(match["pattern"] == "vault_role_id" for match in matches)
    assert any(match["pattern"] == "vault_secret_id" for match in matches)
    assert all("hvs.abcdefghijklmnopqrstuvwxyz" not in finding.get("evidence", "") for finding in report.findings)


def test_wrapped_token_detection_is_specific_and_masked(tmp_path):
    source = tmp_path / "build.log"
    wrapped_token = "hvs.CAESabcdefghijklmnopqrstuvwxyz123456"
    source.write_text(
        "\n".join([
            "VAULT_ADDR=http://localhost:8200",
            f"VAULT_TOKEN={wrapped_token}",
        ]),
        encoding="utf-8",
    )

    matches = _scan_text(source, source.read_text(encoding="utf-8"))

    wrapped_matches = [
        match for match in matches
        if match["pattern"] == "vault_response_wrapped_token"
    ]
    generic_matches = [
        match for match in matches
        if match["pattern"] in ("vault_token_value", "vault_token_assignment")
        and match["value"] == wrapped_token
    ]

    assert len(wrapped_matches) == 1
    assert generic_matches == []
    assert wrapped_matches[0]["confidence"] == "HIGH"
    assert wrapped_matches[0]["masked_value"] == "hvs.CAE...3456"
    assert "Potential Vault response-wrapped token exposure" in finding_titles()
    assert all(wrapped_token not in finding.get("evidence", "") for finding in report.findings)


def test_database_password_patterns_focus_on_infrastructure_variables(tmp_path):
    source = tmp_path / "application.yml"
    source.write_text(
        "\n".join([
            "DB_PASSWORD=db-secret-1",
            "DATABASE_PASS=db-secret-2",
            "db_password=db-secret-3",
            "pg_password=db-secret-4",
            "mysql_password=db-secret-5",
            "user_password=domain-user-password",
            "client_password=oauth-client-password",
        ]),
        encoding="utf-8",
    )

    matches = _scan_text(source, source.read_text(encoding="utf-8"))
    db_password_values = [
        match["value"] for match in matches
        if match["pattern"] == "database_static_password"
    ]

    assert db_password_values == [
        "db-secret-1",
        "db-secret-2",
        "db-secret-3",
        "db-secret-4",
        "db-secret-5",
    ]
    assert "domain-user-password" not in db_password_values
    assert "oauth-client-password" not in db_password_values


def test_code_validation_schema_lines_do_not_emit_secret_findings(tmp_path):
    source = tmp_path / "validation.js"
    source.write_text(
        "\n".join([
            "const schema = Joi.object({ DB_PASSWORD: Joi.string().required() });",
            "const parser = z.object({ VAULT_TOKEN: z.string().optional() });",
            "Validator.isLength(req.body.client_password, { min: 8 });",
        ]),
        encoding="utf-8",
    )

    matches = _scan_text(source, source.read_text(encoding="utf-8"))

    assert matches == []
    assert report.findings == []


def test_non_code_config_passwords_are_not_skipped_by_schema_words(tmp_path):
    source = tmp_path / "application.yml"
    source.write_text(
        "schema: public\nDB_PASSWORD=db-secret-1\n",
        encoding="utf-8",
    )

    matches = _scan_text(source, source.read_text(encoding="utf-8"))

    assert any(
        match["pattern"] == "database_static_password"
        and match["value"] == "db-secret-1"
        for match in matches
    )


def test_scan_files_skips_binary_large_and_unsupported_files(tmp_path):
    (tmp_path / ".env").write_text("VAULT_SECRET_ID=fake-secret-id-456\n", encoding="utf-8")
    (tmp_path / "binary.log").write_bytes(b"VAULT_TOKEN=hvs.aaaaaaaaaaaaaaaa\x00\x00")
    (tmp_path / "large.txt").write_text(
        "VAULT_TOKEN=hvs.large-token-example\n" + ("A" * 200),
        encoding="utf-8",
    )
    (tmp_path / "notes.bin").write_text("VAULT_TOKEN=hvs.unsupported-example\n", encoding="utf-8")

    matches = scan_files(
        tmp_path,
        include_git_history=False,
        max_file_size_bytes=80,
    )

    assert [match["pattern"] for match in matches] == ["vault_secret_id"]
    assert "Potential AppRole Secret ID exposure" in finding_titles()


def test_scan_files_reads_supported_zip_members(tmp_path):
    archive_path = tmp_path / "artifact.zip"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("config.yaml", "vault_token: hvs.archive-token-example\n")
        archive.writestr("image.png", "VAULT_TOKEN=hvs.should-not-scan\n")

    matches = scan_files(tmp_path, include_git_history=False)

    assert any(match["pattern"] in TOKEN_PATTERNS for match in matches)
    assert all("image.png" not in match["file"] for match in matches)


def test_parse_git_grep_line_handles_colons_in_content():
    parsed = _parse_git_grep_line(
        "abcdef123456:config/app.env:42:VAULT_ADDR=http://localhost:8200"
    )

    assert parsed == (
        "abcdef123456",
        "config/app.env",
        42,
        "VAULT_ADDR=http://localhost:8200",
    )


def test_hijack_analyzer_correlates_approle_pair_and_token_chain():
    matches = [
        {
            "file": "app.env",
            "pattern": "vault_role_id",
            "value": "role-123",
            "masked_value": "rol...123",
            "material": True,
        },
        {
            "file": "app.env",
            "pattern": "vault_secret_id",
            "value": "secret-456",
            "masked_value": "sec...456",
            "material": True,
        },
        {
            "file": "config.yaml",
            "pattern": "vault_addr_assignment",
            "value": "http://vault.local:8200",
            "masked_value": "http://...8200",
            "material": False,
        },
        {
            "file": "config.yaml",
            "pattern": "vault_token_value",
            "value": "hvs.abcdefghijklmnopqrstuvwxyz",
            "masked_value": "hvs.abc...wxyz",
            "material": True,
        },
    ]

    analyze_hijack_findings(matches)

    assert "AppRole credential pair discovered" in finding_titles()
    assert "Vault address and token discovered together" in finding_titles()
    assert "Cross-file AppRole Vault access chain discovered" in finding_titles()


def test_hijack_analyzer_correlates_wrapped_token_with_vault_addr():
    matches = [
        {
            "file": "pipeline.log",
            "pattern": "vault_addr_assignment",
            "value": "http://vault.local:8200",
            "masked_value": "http://...8200",
            "material": False,
        },
        {
            "file": "pipeline.log",
            "pattern": "vault_response_wrapped_token",
            "value": "hvs.CAESabcdefghijklmnopqrstuvwxyz123456",
            "masked_value": "hvs.CAE...3456",
            "material": True,
        },
    ]

    analyze_hijack_findings(matches)

    assert "Vault address and token discovered together" in finding_titles()


def test_auth_surface_parses_mounts_but_ignores_html_method_names(monkeypatch):
    def fake_safe_request(method, target, endpoint, **kwargs):
        if endpoint == "/v1/sys/internal/ui/mounts":
            return make_response(200, json_data={"data": {"auth": {}}})
        return make_response(
            200,
            text="<html>userpass approle ldap oidc jwt kubernetes token github</html>",
        )

    monkeypatch.setattr(auth_surface_scanner, "safe_request", fake_safe_request)

    findings = auth_surface_scanner.scan_auth_surface("http://vault.test")

    assert [finding["title"] for finding in findings] == ["No auth methods exposed"]


def test_auth_surface_reports_only_json_auth_mounts(monkeypatch):
    def fake_safe_request(method, target, endpoint, **kwargs):
        if endpoint == "/v1/sys/internal/ui/mounts":
            return make_response(
                200,
                json_data={
                    "data": {
                        "auth": {
                            "userpass/": {"type": "userpass"},
                            "custom-ldap/": {"type": "ldap"},
                            "unknown/": {"type": "not-real"},
                        }
                    }
                },
            )
        return make_response(200, text="<html>approle</html>")

    monkeypatch.setattr(auth_surface_scanner, "safe_request", fake_safe_request)

    findings = auth_surface_scanner.scan_auth_surface("http://vault.test")
    titles = [finding["title"] for finding in findings]

    assert titles == ["Detected auth mount: ldap", "Detected auth mount: userpass"]
    assert all(finding["severity"] == "LOW" for finding in findings)
    assert all("auth_path" in finding["evidence"] for finding in findings)


def test_version_risk_reports_parseable_and_below_baseline(monkeypatch):
    monkeypatch.setattr(
        version_risk_scanner,
        "safe_request",
        Mock(return_value=make_response(200, json_data={"version": "1.14.9", "enterprise": False})),
    )

    findings = version_risk_scanner.scan_version_risk("http://vault.test")

    assert [finding["title"] for finding in findings] == [
        "Vault version identified",
        "Vault version below recommended baseline",
    ]
    assert findings[1]["severity"] == "MEDIUM"


def test_version_risk_handles_invalid_version(monkeypatch):
    monkeypatch.setattr(
        version_risk_scanner,
        "safe_request",
        Mock(return_value=make_response(200, json_data={"version": "not-a-version"})),
    )

    findings = version_risk_scanner.scan_version_risk("http://vault.test")

    assert [finding["title"] for finding in findings] == ["Vault version format could not be parsed"]
    assert findings[0]["severity"] == "LOW"


def test_version_cve_matcher_flags_cve_2024_2048_range():
    matches = version_cve_matcher.match_vault_version_cves(
        "1.14.9",
        target="http://vault.test",
    )

    assert [match["cve_id"] for match in matches] == ["CVE-2024-2048"]
    assert "Vault version matches known advisory: CVE-2024-2048" in finding_titles()
    assert report.findings[0]["severity"] == "CRITICAL"


def test_version_cve_matcher_flags_cve_2023_6337_range():
    matches = version_cve_matcher.match_vault_version_cves(
        "1.15.3",
        target="http://vault.test",
    )

    assert {match["cve_id"] for match in matches} == {
        "CVE-2024-2048",
        "CVE-2023-6337",
    }
    assert "Vault version matches known advisory: CVE-2023-6337" in finding_titles()
    severities_by_title = {
        finding["title"]: finding["severity"]
        for finding in report.findings
    }
    assert severities_by_title["Vault version matches known advisory: CVE-2024-2048"] == "CRITICAL"
    assert severities_by_title["Vault version matches known advisory: CVE-2023-6337"] == "HIGH"


def test_version_cve_matcher_does_not_report_fixed_version():
    matches = version_cve_matcher.match_vault_version_cves(
        "1.15.5",
        target="http://vault.test",
    )

    assert matches == []
    assert report.findings == []


def test_cors_scanner_flags_wildcard_credentials(monkeypatch):
    responses = [
        make_response(
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        ),
        make_response(204),
    ]
    monkeypatch.setattr(cors_scanner, "safe_request", Mock(side_effect=responses))

    findings = cors_scanner.scan_cors("http://vault.test")

    assert "Wildcard CORS origin observed" in [finding["title"] for finding in findings]
    assert "Potentially unsafe CORS configuration" in [finding["title"] for finding in findings]
    assert "CORS preflight supported" in [finding["title"] for finding in findings]


def test_health_scanner_reports_disclosures(monkeypatch):
    response = make_response(
        200,
        json_data={
            "initialized": True,
            "sealed": False,
            "standby": False,
            "version": "1.17.6",
            "cluster_name": "vault-cluster-test",
            "cluster_id": "cluster-id-123",
        },
    )
    monkeypatch.setattr("reconnaissance.health_scanner.requests.get", Mock(return_value=response))

    findings = scan_health("http://vault.test")

    assert "Vault health endpoint exposed" in [finding["title"] for finding in findings]
    assert "Vault version disclosed" in [finding["title"] for finding in findings]
    assert "Vault cluster name disclosed" in [finding["title"] for finding in findings]
    assert "Vault cluster ID disclosed" in [finding["title"] for finding in findings]


def test_capability_scanner_reports_over_privileged_wildcard_path(monkeypatch):
    fake_client = Mock()
    fake_client.sys.get_capabilities.return_value = {
        "sys/*": ["read", "sudo"],
        "secret/data/app": ["read"],
    }
    fake_hvac = Mock(Client=Mock(return_value=fake_client))

    monkeypatch.setitem(__import__("sys").modules, "hvac", fake_hvac)

    results = capability_scanner.audit_token_capabilities(
        "http://vault.test",
        "hvs.fake-token",
        paths=["sys/*", "secret/data/app"],
    )

    assert results[0]["capabilities"] == ["read", "sudo"]
    assert "Over-privileged token capability on critical Vault path" in finding_titles()
    assert "Token has sudo capability on Vault path" in finding_titles()
    assert any("audited_path_contains_wildcard: true" in finding["evidence"] for finding in report.findings)


def test_kv_enumerator_parses_paths_and_builds_nested_tree():
    assert kv_enumerator._split_mount_path("secret/app/prod") == ("secret", "app/prod")
    assert kv_enumerator._split_mount_path("kv/") == ("kv", "")

    tree = {
        "mount": "secret",
        "directories": ["secret/", "secret/app", "secret/app/prod"],
        "secrets": [
            {
                "path": "secret/app/prod/db",
                "readable": True,
                "key_count": 2,
                "keys": ["username", "password"],
            }
        ],
    }

    nested = kv_enumerator._build_nested_tree(tree)

    assert nested["app"]["prod"]["db"]["_type"] == "secret"
    assert nested["app"]["prod"]["db"]["key_count"] == 2
    assert nested["app"]["prod"]["db"]["keys"] == ["username", "password"]


def test_kv_enumerator_records_findings_without_secret_values():
    tree = {
        "mount": "secret",
        "kv_version": 2,
        "directories": ["secret/", "secret/app"],
        "secrets": [
            {
                "path": "secret/app/db",
                "readable": True,
                "key_count": 2,
                "keys": ["username", "password"],
            }
        ],
        "errors": [],
    }

    kv_enumerator._add_tree_findings(tree, "http://vault.test")

    assert "Accessible KV path tree enumerated" in finding_titles()
    assert "Token can read KV secret metadata or keys" in finding_titles()
    assert all("super-secret-value" not in str(finding) for finding in report.findings)


def test_hcl_policy_analyzer_reports_wildcard_and_critical_capabilities(monkeypatch):
    fake_hcl2 = Mock()
    fake_hcl2.load.return_value = {
        "path": [
            {"*": {"capabilities": ["read", "list"]}},
            {"secret/*": {"capabilities": ["read"]}},
            {"sys/policies/acl/*": {"capabilities": ["read", "sudo"]}},
            {"auth/userpass/users/*": {"capabilities": ["update", "delete"]}},
            {"identity/entity/*": {"capabilities": ["write"]}},
        ]
    }
    monkeypatch.setitem(__import__("sys").modules, "hcl2", fake_hcl2)

    analysis = policy_scanner.analyze_hcl_policy(
        'path "*" { capabilities = ["read"] }',
        policy_name="adminish",
    )

    assert analysis["parsed"] is True
    assert len(analysis["rules"]) == 5
    titles = finding_titles()
    assert titles.count("Broad wildcard path in Vault ACL policy") >= 2
    assert titles.count("High-risk capability on critical Vault ACL path") == 3
    assert any("path: sys/policies/acl/*" in finding["evidence"] for finding in report.findings)
    assert any("capabilities: read, sudo" in finding["evidence"] for finding in report.findings)


def test_hcl_policy_rule_extraction_handles_python_hcl2_body_shapes():
    parsed_policy = {
        "path": [
            {"secret/*": [{"capabilities": ["read"]}]},
            {"sys/mounts/*": {"capabilities": ["sudo"]}},
        ]
    }

    rules = policy_scanner.extract_policy_rules(parsed_policy)

    assert rules == [
        {"path": "secret/*", "capabilities": ["read"], "raw": {"capabilities": ["read"]}},
        {"path": "sys/mounts/*", "capabilities": ["sudo"], "raw": {"capabilities": ["sudo"]}},
    ]


def test_hcl_policy_parse_failure_reports_low_finding(monkeypatch):
    fake_hcl2 = Mock()
    fake_hcl2.load.side_effect = ValueError("bad hcl")
    monkeypatch.setitem(__import__("sys").modules, "hcl2", fake_hcl2)

    analysis = policy_scanner.analyze_hcl_policy("not valid hcl", policy_name="broken-policy")

    assert analysis["parsed"] is False
    assert "HCL policy parse failed" in finding_titles()
    assert report.findings[0]["severity"] == "LOW"
