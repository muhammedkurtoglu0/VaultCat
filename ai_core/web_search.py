"""Web search — DuckDuckGo (free) with optional Tavily API.

Provides ``search_web()`` and ``search_web_sync()`` for querying the
internet during autonomous pentesting.  Results are cached for 24 hours
(keyed by MD5 of the query) to avoid redundant API calls and stay
within rate limits.

Usage::

    from ai_core.web_search import search_web

    results = await search_web("Vault CVE-2024-2048 exploit", max_results=5)
    for r in results:
        print(r["title"], r["url"])
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Cache directory
_CACHE_DIR = Path("cache/web_search")
_CACHE_TTL_SECONDS = 86400  # 24 hours

# Default preferred domains — official Vault / CVE sources get higher priority.
# These are used when ``prefer_domains`` is not explicitly passed to
# :func:`search_web` / :func:`search_web_sync`.
DEFAULT_PREFER_DOMAINS: list[str] = [
    "developer.hashicorp.com",
    "discuss.hashicorp.com",
    "nvd.nist.gov",
    "github.com/hashicorp",
    "cve.mitre.org",
    "github.com/advisories",
]


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------


def _get_tavily_key() -> str | None:
    """Read Tavily API key from environment or .env file."""
    key = os.environ.get("TAVILY_API_KEY", "").strip()
    if key:
        return key

    # Try .env file
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("TAVILY_API_KEY="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                if val:
                    return val
    return None


# ---------------------------------------------------------------------------
# Domain reliability scoring
# ---------------------------------------------------------------------------


def _score_result(result: dict, prefer_domains: list[str]) -> int:
    """Assign a relevance score to a single search result based on its URL.

    Scoring rules (additive):
    * +10  — a preferred domain appears in the URL netloc or anywhere in the URL
    * +5   — ``cve`` or ``advisory`` appears in the URL (case-insensitive)

    A result can earn multiple +10 bonuses if several preferred domains match
    (e.g. ``github.com/hashicorp`` matching both in-path and in-domain).
    """
    url = result.get("url", "")
    if not url:
        return 0

    score = 0
    url_lower = url.lower()

    # Parse netloc once for domain checks
    try:
        parsed = urlparse(url)
        netloc = (parsed.netloc or "").lower()
    except Exception:
        netloc = ""

    for pd in prefer_domains:
        pd_lower = pd.lower()
        if pd_lower in netloc or pd_lower in url_lower:
            score += 10

    # Bonus for CVE / advisory URLs (check both "advisory" and the common
    # plural "advisories" used by e.g. github.com/advisories).
    if "cve" in url_lower:
        score += 5
    if "advisory" in url_lower or "advisories" in url_lower:
        score += 5

    return score


def _sort_by_score(results: list[dict], prefer_domains: list[str]) -> list[dict]:
    """Stable-sort results descending by domain relevance score.

    When scores are equal the original order is preserved (Python's ``sort``
    with ``reverse=True`` is stable).
    """
    if not prefer_domains:
        return results

    scored = [(_score_result(r, prefer_domains), r) for r in results]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [r for _, r in scored]


# ---------------------------------------------------------------------------
# Full-page fetch (opt-in)
# ---------------------------------------------------------------------------


def _extract_text(html_bytes: bytes) -> str | None:
    """Extract readable text from HTML content.

    Tries **trafilatura** first (best accuracy for article/main-content
    extraction).  Falls back to **BeautifulSoup** with tag stripping
    (``script``, ``style``, ``nav``, ``footer``, ``header``, ``aside``,
    ``noscript`` are removed before text extraction).
    """
    # 1. trafilatura (preferred — main-content extraction)
    try:
        import trafilatura

        text = trafilatura.extract(html_bytes, output_format="txt")
        if text and text.strip():
            return text.strip()
    except Exception:
        pass

    # 2. BeautifulSoup fallback (basic tag stripping)
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_bytes, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        if text:
            return text
    except Exception:
        pass

    return None


def _fetch_page_text(url: str) -> str | None:
    """Fetch and extract readable text from a single URL.

    Returns up to 5000 characters of extracted text, or *None* on any error
    (timeout, HTTP error, connection failure, content too large, parse
    failure).  All errors are swallowed and logged — this is intentionally
    best-effort so a single bad URL never blocks the whole search pipeline.
    """
    import requests

    try:
        resp = requests.get(url, timeout=8, stream=True)
        resp.raise_for_status()
    except Exception as exc:
        print(f"[web_search] Fetch error for {url}: {exc}")
        return None

    # Honour Content-Length if declared
    content_length_str = resp.headers.get("Content-Length")
    if content_length_str:
        try:
            cl = int(content_length_str)
            if cl > 200_000:
                print(f"[web_search] Skipping {url}: Content-Length={cl} > 200KB")
                resp.close()
                return None
        except ValueError:
            pass

    # Stream with a hard cap
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)
                total += len(chunk)
                if total > 200_000:
                    print(f"[web_search] Truncating {url} at 200KB")
                    break
    except Exception as exc:
        print(f"[web_search] Stream error for {url}: {exc}")
        resp.close()
        return None
    finally:
        resp.close()

    content = b"".join(chunks)
    if not content:
        return None

    # Extract text from HTML
    text = _extract_text(content)
    if not text:
        return None

    # Cap at 5000 characters
    return text[:5000]


# ---------------------------------------------------------------------------
# Cache layer
# ---------------------------------------------------------------------------


def _cache_key(
    query: str,
    max_results: int,
    prefer_domains: list[str] | None = None,
    fetch_top_n: int = 0,
) -> str:
    """Build a deterministic cache key that includes domain preferences.

    Two identical queries with different *prefer_domains* produce different
    cache entries — each preference set may yield a different sort order.
    The *fetch_top_n* parameter is also included so cached results remember
    whether full-text was fetched.
    """
    if prefer_domains is None:
        pd_key = "_default"
    else:
        pd_key = ",".join(sorted(prefer_domains))
    raw = f"{query.strip().lower()}|{max_results}|{pd_key}|{fetch_top_n}"
    return hashlib.md5(raw.encode()).hexdigest()


def _cache_get(query: str, max_results: int, prefer_domains: list[str] | None = None, fetch_top_n: int = 0) -> list[dict] | None:
    key = _cache_key(query, max_results, prefer_domains, fetch_top_n)
    cache_file = _CACHE_DIR / f"{key}.json"
    if not cache_file.exists():
        return None

    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at < _CACHE_TTL_SECONDS:
            return data.get("results", [])
    except (json.JSONDecodeError, OSError):
        pass

    # Expired — clean up
    try:
        cache_file.unlink()
    except OSError:
        pass
    return None


def _cache_set(query: str, max_results: int, results: list[dict], prefer_domains: list[str] | None = None, fetch_top_n: int = 0) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(query, max_results, prefer_domains, fetch_top_n)
    cache_file = _CACHE_DIR / f"{key}.json"
    try:
        cache_file.write_text(
            json.dumps({
                "_cached_at": time.time(),
                "query": query,
                "results": results,
            }, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# DuckDuckGo backend (free, no API key)
# ---------------------------------------------------------------------------


def _search_ddg_sync(query: str, max_results: int = 5) -> list[dict]:
    """Synchronous DuckDuckGo text search."""
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        print("[web_search] duckduckgo-search not installed. Run: pip install duckduckgo-search")
        return []

    try:
        with DDGS() as ddgs:
            raw = list(ddgs.text(query, max_results=max_results))
    except Exception as exc:
        print(f"[web_search] DuckDuckGo error: {exc}")
        return []

    results: list[dict] = []
    for r in raw:
        results.append({
            "title": r.get("title", ""),
            "url": r.get("href", r.get("link", "")),
            "snippet": r.get("body", r.get("description", "")),
        })
    return results


# ---------------------------------------------------------------------------
# Tavily backend (1000 free queries/month, needs API key)
# ---------------------------------------------------------------------------


def _search_tavily_sync(query: str, max_results: int = 5) -> list[dict]:
    """Synchronous Tavily search (requires TAVILY_API_KEY)."""
    try:
        from tavily import TavilyClient
    except ImportError:
        print("[web_search] tavily-python not installed. Run: pip install tavily-python")
        return []

    api_key = _get_tavily_key()
    if not api_key:
        print("[web_search] TAVILY_API_KEY not set. Using DuckDuckGo instead.")
        return _search_ddg_sync(query, max_results)

    try:
        client = TavilyClient(api_key=api_key)
        response = client.search(query=query, max_results=max_results)
        raw = response.get("results", [])
    except Exception as exc:
        print(f"[web_search] Tavily error: {exc} — falling back to DuckDuckGo.")
        return _search_ddg_sync(query, max_results)

    results: list[dict] = []
    for r in raw:
        results.append({
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "snippet": r.get("content", r.get("snippet", "")),
        })
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def search_web(
    query: str,
    max_results: int = 5,
    prefer_domains: list[str] | None = None,
    fetch_top_n: int = 0,
) -> list[dict]:
    """Search the web with 24-hour cache.  Returns list of result dicts.

    Each result: ``{"title": str, "url": str, "snippet": str, "full_text": str | None}``

    Parameters
    ----------
    query:
        Search query string.
    max_results:
        Maximum number of results to return (default 5).
    prefer_domains:
        Optional list of preferred domain / URL patterns.  Results matching
        these patterns are scored higher and sorted to the top.  When
        *None* (the default), :data:`DEFAULT_PREFER_DOMAINS` is used, which
        prioritises official Vault and CVE sources.
    fetch_top_n:
        If > 0, fetch the full page content for the top *N* scored results
        (in parallel via ``asyncio.gather``).  Extracted text (up to 5000
        chars) is stored in the ``"full_text"`` key.  Default 0 (no fetch).
    """
    if prefer_domains is None:
        prefer_domains = DEFAULT_PREFER_DOMAINS

    if not query or not query.strip():
        return []

    # Check cache first
    cached = _cache_get(query, max_results, prefer_domains, fetch_top_n)
    if cached is not None:
        return cached

    # Run the search in a thread (DuckDuckGo is sync)
    import asyncio
    results = await asyncio.to_thread(_search_ddg_sync, query, max_results)

    # If DuckDuckGo returned nothing and Tavily key is set, try Tavily
    if not results and _get_tavily_key():
        results = await asyncio.to_thread(_search_tavily_sync, query, max_results)

    # Sort by domain preference
    results = _sort_by_score(results, prefer_domains)

    # Ensure every result has a full_text slot (None by default)
    for r in results:
        r.setdefault("full_text", None)

    # Fetch full page text for top-N results (parallel)
    if fetch_top_n > 0 and results:
        urls_to_fetch = [r["url"] for r in results[:fetch_top_n] if r.get("url")]
        if urls_to_fetch:
            texts = await asyncio.gather(
                *[asyncio.to_thread(_fetch_page_text, u) for u in urls_to_fetch],
            )
            for i, text in enumerate(texts):
                results[i]["full_text"] = text

    # Cache the result (even if empty — don't retry every time)
    _cache_set(query, max_results, results, prefer_domains, fetch_top_n)

    return results


def search_web_sync(
    query: str,
    max_results: int = 5,
    prefer_domains: list[str] | None = None,
    fetch_top_n: int = 0,
) -> list[dict]:
    """Synchronous wrapper — useful for non-async contexts (planners, CLI).

    Parameters
    ----------
    query:
        Search query string.
    max_results:
        Maximum number of results to return (default 5).
    prefer_domains:
        Optional list of preferred domain / URL patterns.  When *None*,
        :data:`DEFAULT_PREFER_DOMAINS` is used.
    fetch_top_n:
        If > 0, fetch full page content for the top *N* scored results
        (sequential).  Extracted text (up to 5000 chars) is stored in the
        ``"full_text"`` key.  Default 0 (no fetch).
    """
    if prefer_domains is None:
        prefer_domains = DEFAULT_PREFER_DOMAINS

    if not query or not query.strip():
        return []

    cached = _cache_get(query, max_results, prefer_domains, fetch_top_n)
    if cached is not None:
        return cached

    results = _search_ddg_sync(query, max_results)
    if not results and _get_tavily_key():
        results = _search_tavily_sync(query, max_results)

    results = _sort_by_score(results, prefer_domains)

    # Ensure every result has a full_text slot (None by default)
    for r in results:
        r.setdefault("full_text", None)

    # Fetch full page text for top-N results (sequential)
    if fetch_top_n > 0 and results:
        for i in range(min(fetch_top_n, len(results))):
            url = results[i].get("url")
            if url:
                results[i]["full_text"] = _fetch_page_text(url)

    _cache_set(query, max_results, results, prefer_domains, fetch_top_n)
    return results
