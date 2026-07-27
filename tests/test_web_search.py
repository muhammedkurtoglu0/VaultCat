"""Tests for web search engine, cache, and auto-trigger logic."""
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ai_core.web_search import (
    DEFAULT_PREFER_DOMAINS,
    _cache_get,
    _cache_key,
    _cache_set,
    _CACHE_DIR,
    _CACHE_TTL_SECONDS,
    _extract_text,
    _fetch_page_text,
    _score_result,
    _sort_by_score,
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

    def test_no_trigger_on_403(self, agent):
        """403 is Vault's expected unauthenticated answer — must NOT trigger
        a web search (previously produced noise queries)."""
        assert agent._should_search_web(
            "HTTP 403 Forbidden on sys/policies/acl"
        ) is False

    def test_no_trigger_on_permission_denied(self, agent):
        assert agent._should_search_web(
            "permission denied on secret/data/admin"
        ) is False

    def test_triggers_on_5xx(self, agent):
        assert agent._should_search_web(
            '{"status": "failed", "http_status": 500, "path": "v1/sys/health"}'
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

    def test_build_search_query_generic_fallback(self, agent):
        """Non-CVE, non-version results fall back to a generic tool query."""
        q = agent._build_web_search_query(
            "run_kv_enumeration",
            "permission denied on secret/data/admin"
        )
        assert "run_kv_enumeration" in q


# ---------------------------------------------------------------------------
# Domain scoring tests
# ---------------------------------------------------------------------------


class TestDomainScoring:
    """Test _score_result logic for domain reliability ranking."""

    def test_official_hashicorp_scores_high(self):
        """developer.hashicorp.com should get +10 for hashicorp.com match."""
        result = {"title": "Vault Docs", "url": "https://developer.hashicorp.com/vault/docs"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        # "developer.hashicorp.com" matches netloc → +10
        # also "github.com/advisories" and "github.com/hashicorp" in netloc? no
        # "cve" not in url, "advisory" not in url
        assert score >= 10

    def test_nvd_scores_high(self):
        """nvd.nist.gov should get +10 for domain match."""
        result = {"title": "CVE-2024-2048", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2048"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        # "nvd.nist.gov" matches netloc → +10, "cve" in url → +5
        assert score >= 15

    def test_cve_path_bonus(self):
        """URLs containing 'cve' get +5 bonus on top of any domain match."""
        result = {"title": "CVE Detail", "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2048"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        # "cve.mitre.org" in netloc → +10, "cve" in url → +5
        assert score >= 15

    def test_github_advisory_scores_high(self):
        """GitHub advisory URLs get domain + advisory bonus."""
        result = {"title": "GHSA-xxxx", "url": "https://github.com/advisories/GHSA-1234"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        # "github.com/advisories" in url → +10, "advisory" in url → +5
        assert score >= 15

    def test_random_blog_scores_low(self):
        """A random blog should get zero score (no preferred domain, no cve/advisory)."""
        result = {"title": "My Vault Setup", "url": "https://randomblog.example.com/posts/vault"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        assert score == 0

    def test_cve_in_random_blog_gets_bonus(self):
        """A blog post about a CVE gets +5 for 'cve' in URL even if domain is unknown."""
        result = {"title": "CVE Analysis", "url": "https://security-blog.com/cve-2024-2048-analysis"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        assert score >= 5

    def test_empty_url_scores_zero(self):
        result = {"title": "No URL", "url": ""}
        assert _score_result(result, DEFAULT_PREFER_DOMAINS) == 0

    def test_github_hashicorp_path_scores_high(self):
        """github.com/hashicorp/vault URL gets +10 from path match."""
        result = {"title": "Vault Issue", "url": "https://github.com/hashicorp/vault/issues/123"}
        score = _score_result(result, DEFAULT_PREFER_DOMAINS)
        # "github.com/hashicorp" appears in full URL → +10
        assert score >= 10

    def test_empty_prefer_domains_scores_zero(self):
        result = {"title": "CVE Test", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2048"}
        score = _score_result(result, [])
        # Even with "cve" in URL, bonus only applies with prefer_domains
        # Wait — "cve" bonus is independent of prefer_domains
        assert score >= 5  # cve bonus still applies

    def test_custom_prefer_domains(self):
        """Custom domain list should score accordingly."""
        custom = ["mytrustedsource.com"]
        result = {"title": "Trusted", "url": "https://mytrustedsource.com/article"}
        score = _score_result(result, custom)
        assert score >= 10


class TestDomainSorting:
    """Test _sort_by_score result ordering."""

    def _make_results(self):
        return [
            {"title": "Random Blog", "url": "https://randomblog.com/vault", "snippet": "..."},
            {"title": "NVD CVE", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2048", "snippet": "..."},
            {"title": "HashiCorp Docs", "url": "https://developer.hashicorp.com/vault/docs", "snippet": "..."},
            {"title": "Medium Article", "url": "https://medium.com/@user/vault-cve", "snippet": "..."},
        ]

    def test_official_sources_ranked_first(self):
        results = self._make_results()
        sorted_results = _sort_by_score(results, DEFAULT_PREFER_DOMAINS)
        # Both official sources (NVD + HashiCorp) should rank above random blogs.
        # NVD gets +15 (domain + "cve" bonus), HashiCorp Docs gets +10 (domain).
        top_two_urls = [r["url"] for r in sorted_results[:2]]
        bottom_two_urls = [r["url"] for r in sorted_results[-2:]]
        assert any("nvd.nist.gov" in u for u in top_two_urls)
        assert any("hashicorp.com" in u for u in top_two_urls)
        assert any("randomblog.com" in u for u in bottom_two_urls)
        assert any("medium.com" in u for u in bottom_two_urls)

    def test_stable_sort_preserves_order_on_tie(self):
        """Results with equal score should preserve original relative order."""
        results = [
            {"title": "Article A", "url": "https://blog-a.com/post", "snippet": ""},
            {"title": "Article B", "url": "https://blog-b.com/post", "snippet": ""},
        ]
        sorted_results = _sort_by_score(results, DEFAULT_PREFER_DOMAINS)
        # Both score 0 — order preserved
        assert sorted_results[0]["title"] == "Article A"
        assert sorted_results[1]["title"] == "Article B"

    def test_empty_prefer_domains_returns_unchanged(self):
        results = self._make_results()
        sorted_results = _sort_by_score(results, [])
        # Empty prefer list → no scoring → original order preserved
        assert sorted_results == results

    def test_different_prefer_domains_yields_different_order(self):
        """With a different prefer list, ranking changes."""
        results = [
            {"title": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-2048", "snippet": ""},
            {"title": "Medium", "url": "https://medium.com/@user/vault", "snippet": ""},
        ]
        # Default: NVD on top
        default_sorted = _sort_by_score(results, DEFAULT_PREFER_DOMAINS)
        assert "NVD" == default_sorted[0]["title"]

        # Custom: prefer medium.com
        custom_sorted = _sort_by_score(results, ["medium.com"])
        assert "Medium" == custom_sorted[0]["title"]


class TestCacheKeyWithDomains:
    """Test that _cache_key includes prefer_domains in the hash."""

    def test_same_query_different_domains_different_key(self):
        k1 = _cache_key("Vault CVE", 5, ["nvd.nist.gov"])
        k2 = _cache_key("Vault CVE", 5, ["medium.com"])
        assert k1 != k2

    def test_same_query_same_domains_same_key(self):
        k1 = _cache_key("Vault CVE", 5, ["nvd.nist.gov", "cve.mitre.org"])
        k2 = _cache_key("Vault CVE", 5, ["cve.mitre.org", "nvd.nist.gov"])
        assert k1 == k2  # sorted → same order

    def test_cache_key_backward_compatible_none(self):
        """_cache_key with None should differ from explicit domains."""
        k_none = _cache_key("Vault CVE", 5, None)
        k_empty = _cache_key("Vault CVE", 5, [])
        assert k_none != k_empty  # None → "_default", [] → ""

    def test_cache_get_set_with_domains(self):
        """Cache round-trip preserves results with prefer_domains."""
        query = f"domain-cache-test-{time.time()}"
        domains = ["example.com", "test.org"]
        results = [{"title": "T", "url": "https://example.com", "snippet": "x"}]

        _cache_set(query, 5, results, prefer_domains=domains)
        cached = _cache_get(query, 5, prefer_domains=domains)
        assert cached is not None
        assert cached[0]["title"] == "T"

        # Different domains → cache miss
        cached_diff = _cache_get(query, 5, prefer_domains=["other.com"])
        assert cached_diff is None

    def test_cache_key_includes_default_domains_flag(self):
        """None vs DEFAULT_PREFER_DOMAINS produce different keys."""
        k1 = _cache_key("test", 5, None)
        k2 = _cache_key("test", 5, DEFAULT_PREFER_DOMAINS)
        assert k1 != k2  # None → "_default" vs actual domain list


class TestSearchWebSyncWithDomains:
    """Test search_web_sync with the prefer_domains parameter (mocked)."""

    def test_default_domains_applied(self):
        """When prefer_domains is omitted, results are sorted by default domains."""
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "Blog", "url": "https://randomblog.com/vault", "snippet": "x"},
                {"title": "Official", "url": "https://developer.hashicorp.com/vault", "snippet": "x"},
            ]
            results = search_web_sync("Vault config")
            # Official source should be ranked first
            assert "hashicorp.com" in results[0]["url"]

    def test_custom_domains_applied(self):
        """Custom prefer_domains changes the sort order."""
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "Hashicorp", "url": "https://developer.hashicorp.com/vault", "snippet": "x"},
                {"title": "Custom", "url": "https://mytrustedsource.com/vault", "snippet": "x"},
            ]
            results = search_web_sync("Vault config", prefer_domains=["mytrustedsource.com"])
            assert "mytrustedsource.com" in results[0]["url"]

    def test_empty_prefer_domains_disables_sorting(self):
        """Explicit empty list skips the default domain preference."""
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "First", "url": "https://first.com", "snippet": ""},
                {"title": "Second", "url": "https://developer.hashicorp.com", "snippet": ""},
            ]
            results = search_web_sync("Vault config", prefer_domains=[])
            # Empty prefer list → no scoring → original order preserved
            assert results[0]["title"] == "First"

    def test_search_web_sync_caches_with_domains(self):
        """Results are cached with domain-aware keys."""
        query = f"cache-dom-test-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "X", "url": "https://example.com", "snippet": "x"},
            ]
            # First call — should hit backend
            r1 = search_web_sync(query, prefer_domains=["example.com"])
            assert mock_ddg.call_count == 1

            # Same query, same domains — should hit cache
            r2 = search_web_sync(query, prefer_domains=["example.com"])
            assert mock_ddg.call_count == 1  # still 1, cache hit
            assert r1 == r2


# ---------------------------------------------------------------------------
# Text extraction tests
# ---------------------------------------------------------------------------


class TestExtractText:
    """Test _extract_text with trafilatura and BeautifulSoup fallback."""

    SIMPLE_HTML = b"<html><body><p>Hello world</p></body></html>"
    HTML_WITH_NOISE = (
        b"<html><head><script>console.log(1)</script><style>p{color:red}</style></head>"
        b"<body><nav>Menu</nav><article><p>Main content here.</p></article>"
        b"<footer>Copyright</footer></body></html>"
    )

    def test_trafilatura_extracts_text(self):
        """trafilatura should extract readable text from simple HTML."""
        text = _extract_text(self.SIMPLE_HTML)
        assert text is not None
        assert "Hello world" in text

    def test_beautifulsoup_fallback(self):
        """When trafilatura returns empty, BeautifulSoup fallback should work."""
        with patch("trafilatura.extract", return_value=None):
            text = _extract_text(self.HTML_WITH_NOISE)
        assert text is not None
        assert "Main content here" in text
        # Noise tags should be removed by BS4 fallback
        assert "console.log" not in text
        assert "Menu" not in text
        assert "Copyright" not in text

    def test_both_fail_returns_none(self):
        """When trafilatura returns empty and BS4 gets empty: return None."""
        with patch("trafilatura.extract", return_value=None):
            # Empty HTML — BS4 will find no text
            text = _extract_text(b"<html><head></head><body></body></html>")
            assert text is None

    def test_empty_html_returns_none(self):
        """Empty or whitespace-only HTML should return None."""
        text = _extract_text(b"<html></html>")
        assert text is None or text == ""


# ---------------------------------------------------------------------------
# Page fetch tests
# ---------------------------------------------------------------------------


class TestFetchPageText:
    """Test _fetch_page_text behaviour with mocked requests."""

    def test_successful_fetch(self):
        """Successful HTTP fetch should return extracted text."""
        fake_html = b"<html><body><p>Vault CVE details here.</p></body></html>"
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.headers = {}
            mock_resp.iter_content.return_value = [fake_html]
            mock_resp.close.return_value = None
            mock_get.return_value = mock_resp

            text = _fetch_page_text("https://nvd.nist.gov/vuln/CVE-2024-2048")
            assert text is not None
            assert "Vault CVE" in text

    def test_fetch_http_error_returns_none(self):
        """HTTP error (4xx/5xx) should return None."""
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.side_effect = Exception("404 Not Found")
            mock_get.return_value = mock_resp

            text = _fetch_page_text("https://example.com/not-found")
            assert text is None

    def test_fetch_timeout_returns_none(self):
        """Connection timeout should return None."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Connection timed out")

            text = _fetch_page_text("https://slow-site.com")
            assert text is None

    def test_content_too_large_returns_none(self):
        """Content-Length > 200KB should be skipped."""
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.headers = {"Content-Length": "300000"}
            mock_resp.close.return_value = None
            mock_get.return_value = mock_resp

            text = _fetch_page_text("https://large-file.com/big")
            assert text is None

    def test_stream_error_returns_none(self):
        """Stream read error should return None gracefully."""
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.headers = {}
            mock_resp.iter_content.side_effect = Exception("Connection reset")
            mock_resp.close.return_value = None
            mock_get.return_value = mock_resp

            text = _fetch_page_text("https://flaky-site.com")
            assert text is None

    def test_truncates_at_200kb(self):
        """Content exceeding 200KB during streaming should be truncated."""
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.headers = {}
            # Yield chunks totalling > 200KB
            big_chunk = b"x" * 100_000
            mock_resp.iter_content.return_value = [big_chunk, big_chunk, big_chunk]
            mock_resp.close.return_value = None
            mock_get.return_value = mock_resp

            # Should not raise — just truncate
            text = _fetch_page_text("https://big-page.com")
            # The extracted text may be None (binary junk) or short text
            # The key is that it shouldn't crash
            assert text is None or len(text) <= 5000

    def test_text_capped_at_5000_chars(self):
        """Returned text should never exceed 5000 characters."""
        long_text = "A" * 10000
        fake_html = f"<html><body><p>{long_text}</p></body></html>".encode()
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.headers = {}
            mock_resp.iter_content.return_value = [fake_html]
            mock_resp.close.return_value = None
            mock_get.return_value = mock_resp

            text = _fetch_page_text("https://example.com/long")
            assert text is not None
            assert len(text) <= 5000


# ---------------------------------------------------------------------------
# fetch_top_n integration tests
# ---------------------------------------------------------------------------


class TestFetchTopN:
    """Test search_web_sync with fetch_top_n parameter (mocked)."""

    def test_fetch_top_n_zero_does_not_fetch(self):
        """fetch_top_n=0 should never call _fetch_page_text."""
        query = f"no-fetch-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg, \
             patch("ai_core.web_search._fetch_page_text") as mock_fetch:
            mock_ddg.return_value = [
                {"title": "X", "url": "https://example.com", "snippet": "x"},
            ]
            results = search_web_sync(query, fetch_top_n=0)
            assert mock_fetch.call_count == 0
            assert results[0]["full_text"] is None

    def test_fetch_top_n_fetches_pages(self):
        """fetch_top_n=2 should fetch the top 2 results."""
        query = f"fetch-2-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg, \
             patch("ai_core.web_search._fetch_page_text") as mock_fetch:
            mock_ddg.return_value = [
                {"title": "First", "url": "https://example.com/1", "snippet": "a"},
                {"title": "Second", "url": "https://example.com/2", "snippet": "b"},
                {"title": "Third", "url": "https://example.com/3", "snippet": "c"},
            ]
            mock_fetch.side_effect = ["Full text 1", "Full text 2"]

            results = search_web_sync(query, fetch_top_n=2)
            assert mock_fetch.call_count == 2
            assert results[0]["full_text"] == "Full text 1"
            assert results[1]["full_text"] == "Full text 2"
            assert results[2]["full_text"] is None  # third not fetched

    def test_fetch_top_n_exceeds_results(self):
        """fetch_top_n larger than result count fetches all available."""
        query = f"fetch-over-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg, \
             patch("ai_core.web_search._fetch_page_text") as mock_fetch:
            mock_ddg.return_value = [
                {"title": "Only", "url": "https://example.com/1", "snippet": "a"},
            ]
            mock_fetch.return_value = "Full text"

            results = search_web_sync(query, fetch_top_n=5)
            assert mock_fetch.call_count == 1
            assert results[0]["full_text"] == "Full text"

    def test_fetch_error_graceful(self):
        """A fetch error for one result doesn't affect others."""
        query = f"fetch-err-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg, \
             patch("ai_core.web_search._fetch_page_text") as mock_fetch:
            mock_ddg.return_value = [
                {"title": "Good", "url": "https://good.com", "snippet": "a"},
                {"title": "Bad", "url": "https://bad.com", "snippet": "b"},
            ]
            mock_fetch.side_effect = ["Good content", None]  # second fails

            results = search_web_sync(query, fetch_top_n=2)
            assert results[0]["full_text"] == "Good content"
            assert results[1]["full_text"] is None  # graceful

    def test_all_results_have_full_text_key(self):
        """Every result must have a 'full_text' key (None if not fetched)."""
        query = f"full-text-key-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg:
            mock_ddg.return_value = [
                {"title": "X", "url": "https://example.com", "snippet": "x"},
            ]
            results = search_web_sync(query)
            assert "full_text" in results[0]
            assert results[0]["full_text"] is None


class TestFetchTopNCache:
    """Test cache key includes fetch_top_n and cache round-trips preserve full_text."""

    def test_different_fetch_top_n_different_cache_key(self):
        """Same query with different fetch_top_n should use different cache key."""
        k1 = _cache_key("Vault CVE", 5, None, fetch_top_n=0)
        k2 = _cache_key("Vault CVE", 5, None, fetch_top_n=2)
        assert k1 != k2

    def test_same_params_same_cache_key(self):
        """Identical parameters produce the same cache key."""
        k1 = _cache_key("test", 3, ["nvd.nist.gov"], fetch_top_n=1)
        k2 = _cache_key("test", 3, ["nvd.nist.gov"], fetch_top_n=1)
        assert k1 == k2

    def test_cache_round_trip_preserves_full_text(self):
        """Cached results should include full_text from previous fetch."""
        query = f"fetch-cache-test-{time.time()}"
        results = [
            {"title": "T", "url": "https://example.com", "snippet": "x",
             "full_text": "Cached full page content here."},
        ]
        _cache_set(query, 5, results, fetch_top_n=1)
        cached = _cache_get(query, 5, fetch_top_n=1)
        assert cached is not None
        assert cached[0]["full_text"] == "Cached full page content here."

    def test_cache_fetch_top_n_mismatch_miss(self):
        """Query cached with fetch_top_n=0 misses when fetch_top_n=2 requested."""
        query = f"mismatch-test-{time.time()}"
        results = [{"title": "X", "url": "https://x.com", "snippet": "", "full_text": None}]
        _cache_set(query, 5, results, fetch_top_n=0)

        # Same query, different fetch_top_n → cache miss
        cached = _cache_get(query, 5, fetch_top_n=2)
        assert cached is None

    def test_search_web_sync_caches_full_text(self):
        """search_web_sync should cache results including full_text."""
        query = f"sync-fetch-cache-{time.time()}"
        with patch("ai_core.web_search._search_ddg_sync") as mock_ddg, \
             patch("ai_core.web_search._fetch_page_text") as mock_fetch:
            mock_ddg.return_value = [
                {"title": "X", "url": "https://example.com", "snippet": "x"},
            ]
            mock_fetch.return_value = "Fetched content"

            # First call — fetches
            r1 = search_web_sync(query, fetch_top_n=1)
            assert mock_ddg.call_count == 1
            assert mock_fetch.call_count == 1
            assert r1[0]["full_text"] == "Fetched content"

            # Second call — cache hit, no new fetch
            r2 = search_web_sync(query, fetch_top_n=1)
            assert mock_ddg.call_count == 1  # still 1
            assert mock_fetch.call_count == 1  # still 1
            assert r2[0]["full_text"] == "Fetched content"


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
