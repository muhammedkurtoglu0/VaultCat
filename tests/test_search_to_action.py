"""Tests for ai_core.search_to_action — web search → active_execution bridge."""

import pytest

from ai_core.search_to_action import (
    CVE_SEARCH_TEMPLATES,
    EXPLOIT_TEMPLATES,
    SearchToActionBridge,
    get_search_query,
    _parse_curl_commands,
    _parse_json_payloads,
    _parse_vault_cli_commands,
    _parse_step_lists,
    _guess_path_from_context,
)


class TestGetSearchQuery:
    """Tests for optimized search query templates."""

    def test_known_cve_returns_template(self):
        query = get_search_query("CVE-2023-6337")
        assert "memory exhaustion" in query
        assert "DoS" in query

    def test_cve_2025_6203(self):
        query = get_search_query("CVE-2025-6203")
        assert "crafted JSON" in query

    def test_unknown_cve_generates_template(self):
        query = get_search_query("CVE-2029-9999")
        assert "CVE-2029-9999" in query
        assert "exploit" in query.lower()

    def test_technique_approle_bypass(self):
        query = get_search_query("approle_secret_id_bypass")
        assert "bind_secret_id" in query

    def test_technique_token_escalation(self):
        query = get_search_query("token_privilege_escalation")
        assert "privilege escalation" in query.lower()

    def test_fallback_generic_query(self):
        query = get_search_query("random technique name")
        assert "Vault" in query
        assert "exploit" in query.lower()

    def test_case_insensitive_cve(self):
        query = get_search_query("cve-2024-2048")
        assert "CVE-2024-2048" in query


class TestCurlParser:
    """Tests for curl command extraction from text."""

    def test_simple_curl_get(self):
        results = _parse_curl_commands('curl https://vault:8200/v1/sys/health')
        assert len(results) == 1
        assert results[0]["method"] == "GET"
        assert results[0]["path"] == "/v1/sys/health"

    def test_curl_post_with_json(self):
        results = _parse_curl_commands(
            'curl -X POST https://vault:8200/v1/auth/approle/login -d \'{"role_id":"rid","secret_id":"sid"}\''
        )
        assert len(results) >= 1
        assert any(r["path"] == "/v1/auth/approle/login" for r in results)

    def test_no_curl_in_text(self):
        results = _parse_curl_commands("No HTTP tools used here, just plain text without commands.")
        assert results == []

    def test_multiple_curl_commands(self):
        text = """
        First: curl http://vault:8200/v1/sys/health
        Second: curl -X POST https://vault:8200/v1/auth/token/create
        """
        results = _parse_curl_commands(text)
        assert len(results) >= 2


class TestVaultCLIParser:
    """Tests for vault CLI command extraction."""

    def test_vault_read(self):
        results = _parse_vault_cli_commands("Run: vault read secret/admin/creds")
        assert len(results) == 1
        assert results[0]["method"] == "GET"
        assert "secret/admin/creds" in results[0]["path"]

    def test_vault_write(self):
        results = _parse_vault_cli_commands("vault write database/roles/app-admin db_name=pg default_ttl=1h max_ttl=4h")
        assert len(results) == 1
        assert results[0]["method"] == "POST"
        assert results[0]["path"] == "database/roles/app-admin"
        # Regex captures path + 1 keyword — rest are in the raw command text
        assert "db_name" in results[0]["args"]

    def test_vault_list(self):
        results = _parse_vault_cli_commands("vault list secret/metadata/")
        assert len(results) == 1
        assert results[0]["method"] == "LIST"

    def test_no_cli_in_text(self):
        results = _parse_vault_cli_commands("No vault CLI here")
        assert results == []


class TestJSONPayloadParser:
    """Tests for JSON payload extraction."""

    def test_approle_payload(self):
        results = _parse_json_payloads('Use: {"role_id": "abc", "secret_id": "def"} to login')
        assert len(results) >= 1

    def test_token_create_payload(self):
        text = 'POST to auth/token/create with {"policies": ["default", "admin"], "ttl": "1h"}'
        results = _parse_json_payloads(text)
        assert len(results) >= 1

    def test_no_json_in_text(self):
        results = _parse_json_payloads("Plain text without JSON")
        assert results == []


class TestStepListParser:
    """Tests for numbered step list extraction."""

    def test_step_list_with_methods(self):
        text = """
        Step 1: GET /v1/sys/health to check status
        Step 2: POST to /v1/auth/token/create with admin policy
        Step 3: Read /v1/secret/data/admin/creds
        """
        results = _parse_step_lists(text)
        assert len(results) >= 2

    def test_no_steps(self):
        results = _parse_step_lists("No numbered steps here.")
        assert results == []


class TestPathGuesser:
    """Tests for Vault API path extraction from context."""

    def test_full_api_path(self):
        path = _guess_path_from_context("GET https://vault:8200/v1/sys/mounts returns all mounts")
        assert path == "sys/mounts"

    def test_path_without_v1_prefix(self):
        path = _guess_path_from_context("Call auth/approle/login with role_id")
        assert path == "auth/approle/login"

    def test_no_path(self):
        path = _guess_path_from_context("No Vault path here")
        assert path is None


class TestSearchToActionBridge:
    """Tests for the full bridge pipeline."""

    def test_empty_results_returns_empty(self):
        bridge = SearchToActionBridge(vault_addr="https://vault:8200")
        params = bridge.to_module_params([])
        assert params == []

    def test_curl_result_maps_to_module(self):
        bridge = SearchToActionBridge(vault_addr="https://vault:8200", token="hvs.test")
        results = [{
            "title": "Vault AppRole exploit",
            "url": "https://example.com/exploit",
            "snippet": 'curl -X POST https://vault:8200/v1/auth/approle/login -d \'{"role_id":"r","secret_id":"s"}\'',
            "full_text": None,
        }]
        params = bridge.to_module_params(results)
        assert len(params) >= 1
        assert params[0]["module"] == "run_approle_exploit"
        assert params[0]["params"]["vault_addr"] == "https://vault:8200"
        assert params[0]["params"]["token"] == "hvs.test"

    def test_cli_result_maps_to_module(self):
        bridge = SearchToActionBridge(vault_addr="https://vault:8200")
        results = [{
            "title": "Vault CLI fix",
            "url": "https://example.com/fix",
            "snippet": "vault write database/rotate-root/postgres-prod",
            "full_text": None,
        }]
        params = bridge.to_module_params(results)
        assert len(params) >= 1
        assert params[0]["module"] == "run_database_pivot"

    def test_deduplication(self):
        bridge = SearchToActionBridge(vault_addr="https://vault:8200")
        results = [
            {"title": "A", "url": "https://a.com", "snippet": "curl https://vault:8200/v1/sys/health", "full_text": None},
            {"title": "B", "url": "https://b.com", "snippet": "curl https://vault:8200/v1/sys/health", "full_text": None},
        ]
        params = bridge.to_module_params(results)
        # Same (module, method, path) → deduplicated
        assert len(params) == 1

    def test_path_classifier_secret_enum(self):
        module = SearchToActionBridge._classify_path_to_module("secret/data/admin/creds", "GET")
        assert module == "run_kv_enumeration"

    def test_path_classifier_token_create(self):
        module = SearchToActionBridge._classify_path_to_module("auth/token/create", "POST")
        assert module == "run_privilege_escalation"

    def test_path_classifier_database_creds(self):
        module = SearchToActionBridge._classify_path_to_module("database/creds/app-admin", "GET")
        assert module == "run_database_credential_harvest"

    def test_path_classifier_pki_issue(self):
        module = SearchToActionBridge._classify_path_to_module("pki/issue/localhost", "POST")
        assert module == "run_pki_exploit"

    def test_path_classifier_fallback(self):
        module = SearchToActionBridge._classify_path_to_module("cubbyhole/unknown", "GET")
        assert module == "run_raw_vault_request"


class TestCVETemplates:
    """Verify all CVE templates have reasonable queries."""

    def test_all_cves_have_vault_in_query(self):
        for cve_id, query in CVE_SEARCH_TEMPLATES.items():
            assert cve_id.startswith("CVE-"), f"Key {cve_id} is not a CVE ID"
            assert "Vault" in query, f"CVE {cve_id} query missing 'Vault': {query}"

    def test_all_exploit_templates_have_vault(self):
        for technique, query in EXPLOIT_TEMPLATES.items():
            assert "Vault" in query or "vault" in query.lower(), f"Technique {technique} missing Vault: {query}"
