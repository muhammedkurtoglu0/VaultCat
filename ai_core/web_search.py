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

# Cache directory
_CACHE_DIR = Path("cache/web_search")
_CACHE_TTL_SECONDS = 86400  # 24 hours


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
# Cache layer
# ---------------------------------------------------------------------------


def _cache_key(query: str, max_results: int) -> str:
    raw = f"{query.strip().lower()}|{max_results}"
    return hashlib.md5(raw.encode()).hexdigest()


def _cache_get(query: str, max_results: int) -> list[dict] | None:
    key = _cache_key(query, max_results)
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


def _cache_set(query: str, max_results: int, results: list[dict]) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(query, max_results)
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


async def search_web(query: str, max_results: int = 5) -> list[dict]:
    """Search the web with 24-hour cache.  Returns list of result dicts.

    Each result: ``{"title": str, "url": str, "snippet": str}``
    """
    if not query or not query.strip():
        return []

    # Check cache first
    cached = _cache_get(query, max_results)
    if cached is not None:
        return cached

    # Run the search in a thread (DuckDuckGo is sync)
    import asyncio
    results = await asyncio.to_thread(_search_ddg_sync, query, max_results)

    # If DuckDuckGo returned nothing and Tavily key is set, try Tavily
    if not results and _get_tavily_key():
        results = await asyncio.to_thread(_search_tavily_sync, query, max_results)

    # Cache the result (even if empty — don't retry every time)
    _cache_set(query, max_results, results)

    return results


def search_web_sync(query: str, max_results: int = 5) -> list[dict]:
    """Synchronous wrapper — useful for non-async contexts (planners, CLI)."""
    if not query or not query.strip():
        return []

    cached = _cache_get(query, max_results)
    if cached is not None:
        return cached

    results = _search_ddg_sync(query, max_results)
    if not results and _get_tavily_key():
        results = _search_tavily_sync(query, max_results)

    _cache_set(query, max_results, results)
    return results
