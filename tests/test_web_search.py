"""Tests for web search engine, cache, and auto-trigger logic."""
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ai_core.web_search import (
    _cache_get,
    _cache_key,
    _cache_set,
    _CACHE_DIR,
    _CACHE_TTL_SECONDS,
    search_web_sync,
)


# ---------------------------------------------------------------------------
# Cache tests
# ---------------------------------------------------------------------------


class TestWebSearchCache:
    """Test the 24-hour MD5-based query cache."""

    def test_cache_key_is_stable(self):
        k1 = _cache_key("Vault CVE-2024-2048", 5)
        k2 = _cache_key("Vault CVE-2024-2048", 5)
        assert k1 == k2

    def test_cache_key_differs_on_query(self):
        k1 = _cache_key("Vault CVE-2024-2048", 5)
        k2 = _cache_key("Vault CVE-2024-2049", 5)
        assert k1 != k2

    def test_cache_key_differs_on_max_results(self):
        k1 = _cache_key("test", 3)
        k2 = _cache_key("test", 5)
        assert k1 != k2

    def test_cache_miss_returns_none(self):
        result = _cache_get("never-searched-query-xyz", 5)
        assert result is None

    def test_cache_set_and_get(self):
        query = f"test-query-{time.time()}"
        results = [{"title": "Test", "url": "http://x.com", "snippet": "abc"}]
        _cache_set(query, 5, results)
        cached = _cache_get(query, 5)
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["title"] == "Test"

    def test_cache_expiry(self, monkeypatch):
        # Set a very short TTL
        old_ttl = _CACHE_TTL_SECONDS
        monkeypatch.setattr("ai_core.web_search._CACHE_TTL_SECONDS", 0)
        try:
            query = f"expire-test-{time.time()}"
            _cache_set(query, 5, [{"title": "X", "url": "x", "snippet": "x"}])
            time.sleep(0.1)
            result = _cache_get(query, 5)
            assert result is None  # expired
        finally:
            pass


# ---------------------------------------------------------------------------
# Search function tests (mocked DuckDuckGo)
# ---------------------------------------------------------------------------


class TestWebSearch:
    """Test the search_web_sync function with mocked backends."""

    def test_empty_query_returns_empty(self):
        assert search_web_sync("") == []
        assert search_web_sync("   ") == []

    def test_search_returns_results(self):
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "CVE-2024-2048", "url": "http://nvd.nist.gov/1",
                 "snippet": "Critical Vault vuln"},
                {"title": "Exploit DB", "url": "http://exploit-db.com/2",
                 "snippet": "PoC for Vault CVE"},
            ]
            results = search_web_sync("HashiCorp Vault CVE-2024-2048")
            assert len(results) == 2
            assert results[0]["title"] == "CVE-2024-2048"

    def test_search_fallback_empty_returns_empty(self):
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = []
            # No Tavily key set — should return empty without crash
            results = search_web_sync("something obscure 987654xyz")
            assert results == []


# ---------------------------------------------------------------------------
# Agent auto-trigger tests
# ---------------------------------------------------------------------------


class TestAgentAutoTrigger:
    """Test PentestAgent._should_search_web logic."""

    @pytest.fixture
    def agent(self):
        from ai_core.agent import PentestAgent
        return PentestAgent()

    def test_triggers_on_cve(self, agent):
        assert agent._should_search_web(
            "Found vulnerability CVE-2024-2048 in Vault 1.15.3"
        ) is True

    def test_no_trigger_on_plain_text(self, agent):
        assert agent._should_search_web("Scan completed successfully") is False

    def test_no_trigger_on_empty(self, agent):
        assert agent._should_search_web("") is False
        assert agent._should_search_web(None) is False  # type: ignore

    def test_triggers_on_403(self, agent):
        assert agent._should_search_web(
            "HTTP 403 Forbidden on sys/policies/acl"
        ) is True

    def test_triggers_on_permission_denied(self, agent):
        assert agent._should_search_web(
            "permission denied on secret/data/admin"
        ) is True

    def test_triggers_on_version(self, agent):
        assert agent._should_search_web(
            "Vault version: 1.15.3, build_date: 2023-11-22"
        ) is True

    def test_no_duplicate_cve_trigger(self, agent):
        cve_result = "CVE-2024-2048 affects Vault 1.15.x"
        assert agent._should_search_web(cve_result) is True  # first time
        # Simulate search done — mark the CVE as searched
        agent._searched_cves.add("CVE-2024-2048")
        assert agent._should_search_web(cve_result) is False  # already searched

    def test_disable_web_suppresses_trigger(self, agent):
        agent._disable_web = True
        assert agent._should_search_web("CVE-2024-2048 found!") is False

    def test_search_cache_key_stable(self, agent):
        k1 = agent._search_cache_key("run_recon", "CVE-2024-2048 found")
        k2 = agent._search_cache_key("run_recon", "CVE-2024-2048 found")
        assert k1 == k2

    def test_build_search_query_cve(self, agent):
        q = agent._build_web_search_query(
            "run_capability_audit",
            "Vault version 1.15.3 has CVE-2024-2048"
        )
        assert "CVE-2024-2048" in q
        assert "exploit" in q.lower()

    def test_build_search_query_error(self, agent):
        q = agent._build_web_search_query(
            "run_kv_enumeration",
            "permission denied on secret/data/admin"
        )
        assert "permission denied" in q.lower()


# ---------------------------------------------------------------------------
# Runtime — web search module loads correctly
# ---------------------------------------------------------------------------


class TestWebSearchModule:
    """Smoke test: module imports and cache directory is created."""

    def test_module_imports(self):
        import ai_core.web_search
        assert hasattr(ai_core.web_search, "search_web")
        assert hasattr(ai_core.web_search, "search_web_sync")

    def test_cache_dir_created(self, tmp_path, monkeypatch):
        monkeypatch.setattr("ai_core.web_search._CACHE_DIR", tmp_path / "cache/web_search")
        _cache_set("smoke-test", 3, [{"title": "x", "url": "x", "snippet": "x"}])
        assert (tmp_path / "cache/web_search").exists()
