"""Vault API client with dynamic credential store integration.

When a :class:`DynamicCredentialStore` is provided (or the global
singleton is populated), the client automatically uses the
highest-privilege token available.
"""

from __future__ import annotations

import requests
from typing import Optional

from core.tls_config import get_verify
from core.logger import logger


class VaultClient:
    """Thin requests wrapper that adds the ``X-Vault-Token`` header.

    If *store* is provided, every request uses the best token the store
    knows about — enabling transparent privilege escalation during a
    pentest.
    """

    def __init__(
        self,
        vault_addr: str,
        token: str | None = None,
        store=None,
    ):
        self.vault_addr = vault_addr.rstrip("/")
        self.token = token
        self._store = store

    @property
    def effective_token(self) -> str | None:
        """Return the best available token (store > explicit > None)."""
        if self._store:
            best = self._store.get_best_token_value()
            if best:
                return best
        return self.token

    def request(self, method: str, path: str):
        url = f"{self.vault_addr}/v1/{path.lstrip('/')}"
        token = self.effective_token
        headers = {"X-Vault-Token": token} if token else {}
        try:
            return requests.request(
                method, url, headers=headers, timeout=5, verify=get_verify(),
            )
        except requests.exceptions.RequestException as error:
            logger.error(f"Request error: {error}")
            return None
