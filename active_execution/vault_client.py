"""Shared Vault client factory — single hvac/requests client reused across modules.

Every active_execution module previously called ``vault_request()`` or
``requests.request()`` independently, each with its own timeout, TLS,
and retry settings.  This factory provides a single, pre-configured
client that all modules can import.

Usage::

    from active_execution.vault_client import get_vault_client

    client = get_vault_client("https://vault:8200", "hvs.token")
    resp = client.get("sys/mounts")
"""

from __future__ import annotations

from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Module-level singleton cache: (vault_addr, token_hash) → requests.Session
_client_cache: dict[tuple[str, int], requests.Session] = {}


def get_vault_client(
    vault_addr: str,
    token: str = "",
    *,
    timeout: int = 10,
    verify_tls: bool = True,
    max_retries: int = 2,
    backoff_factor: float = 0.5,
) -> requests.Session:
    """Return a pre-configured ``requests.Session`` for *vault_addr*.

    Sessions are cached per ``(vault_addr, hash(token))`` so that multiple
    modules calling this with the same credentials reuse a single TCP
    connection pool and TLS handshake.

    Parameters
    ----------
    vault_addr:
        Target Vault URL (e.g. ``https://vault:8200``).
    token:
        Vault token.  Sessions with different tokens are NOT shared
        (token is part of the cache key).
    timeout:
        Default request timeout in seconds.
    verify_tls:
        Set to ``False`` for self-signed lab certs.
    max_retries:
        Number of retries on connection/read errors.
    backoff_factor:
        Exponential backoff multiplier between retries.
    """
    import hashlib

    addr = vault_addr.rstrip("/")
    token_hash = hashlib.md5(token.encode()).hexdigest() if token else 0  # type: ignore[arg-type]

    cache_key = (addr, token_hash)  # type: ignore[assignment]
    if cache_key in _client_cache:
        return _client_cache[cache_key]

    session = requests.Session()
    session.verify = verify_tls

    # ── Retry strategy ──────────────────────────────────────────────────
    retry = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "LIST", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # ── Default headers ─────────────────────────────────────────────────
    session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "vaultcat/0.1",
    })
    if token:
        session.headers["X-Vault-Token"] = token

    session.timeout = timeout

    _client_cache[cache_key] = session
    return session


def clear_client_cache() -> None:
    """Close all cached sessions (useful between test runs)."""
    for session in _client_cache.values():
        session.close()
    _client_cache.clear()
