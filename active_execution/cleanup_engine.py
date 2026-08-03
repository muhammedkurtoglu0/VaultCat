"""Cleanup Engine — LIFO rollback of Vault state changes.

Tracks every state-changing operation executed during a pentest and
provides automatic rollback at session end.

Usage::

    from active_execution.cleanup_engine import CleanupEngine, RollbackAction, RollbackStrategy

    engine = CleanupEngine.get()

    # Record an action
    engine.record(RollbackAction(
        module_id="persistence.backdoor",
        description="Disable approle-backdoor auth method",
        strategy=RollbackStrategy.DELETE_AUTH,
        vault_path="sys/auth/approle-backdoor",
    ))

    # Execute rollback at session end
    engine.execute_rollback(vault_addr, token)

    # Or just see what would be cleaned
    for desc in engine.dry_run():
        print(desc)
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logger import logger


# ---------------------------------------------------------------------------
# Rollback strategy enum
# ---------------------------------------------------------------------------


class RollbackStrategy(str, Enum):
    """Vault API operation to reverse a state change."""
    DELETE_AUTH = "delete_auth"         # DELETE /v1/sys/auth/{path}
    DELETE_ROLE = "delete_role"         # DELETE /v1/auth/{mount}/role/{name}
    REVOKE_TOKEN = "revoke_token"       # POST /v1/auth/token/revoke
    DELETE_POLICY = "delete_policy"     # DELETE /v1/sys/policies/acl/{name}
    RESTORE_POLICY = "restore_policy"   # PUT /v1/sys/policies/acl/{name} (original rules)
    ENABLE_AUDIT = "enable_audit"       # Re-enable a disabled audit device
    DISABLE_AUTH = "disable_auth"       # Alias for DELETE_AUTH


# ---------------------------------------------------------------------------
# Rollback action
# ---------------------------------------------------------------------------


@dataclass
class RollbackAction:
    """A single undo step recorded during a pentest.

    Each action maps to one Vault API call that reverses a state change.
    Actions are executed in LIFO order (last created = first cleaned).
    """

    module_id: str                     # e.g. "persistence.backdoor"
    description: str                   # human-readable summary
    strategy: RollbackStrategy         # which Vault API call to make

    # Vault API parameters (relative path, no /v1/ prefix)
    vault_path: str = ""               # e.g. "sys/auth/approle-backdoor"
    vault_body: dict[str, Any] | None = None  # request body (for PUT/POST)

    # Metadata
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.monotonic)
    depends_on: list[str] = field(default_factory=list)  # action_ids
    metadata: dict[str, Any] = field(default_factory=dict)

    def build_url(self, vault_addr: str) -> str:
        """Build the full Vault API URL for this rollback action."""
        base = vault_addr.rstrip("/")
        return f"{base}/v1/{self.vault_path.lstrip('/')}"


# ---------------------------------------------------------------------------
# Cleanup engine
# ---------------------------------------------------------------------------


class CleanupEngine:
    """Tracks state-changing operations and executes LIFO rollback.

    Thread-safe singleton — all modules share one instance.
    """

    def __init__(self):
        self._actions: list[RollbackAction] = []
        self._lock = threading.Lock()

    # ── public API ──────────────────────────────────────────────────────

    def record(self, action: RollbackAction):
        """Record a rollback action for later cleanup.

        Thread-safe — can be called from any module.
        """
        with self._lock:
            self._actions.append(action)
            logger.info(
                f"[cleanup] Recorded rollback action [{action.action_id}]: "
                f"{action.description} ({action.strategy.value})"
            )

    def dry_run(self) -> list[str]:
        """Return a list of human-readable descriptions of what would be cleaned.

        Does NOT execute any Vault API calls.
        """
        with self._lock:
            if not self._actions:
                return ["(no state changes recorded — nothing to clean)"]
            lines = [
                f"Would execute {len(self._actions)} rollback actions (LIFO order):"
            ]
            for i, action in enumerate(reversed(self._actions), 1):
                lines.append(
                    f"  {i}. [{action.module_id}] {action.description} "
                    f"-> {action.strategy.value} {action.vault_path}"
                )
            return lines

    def execute_rollback(
        self,
        vault_addr: str,
        token: str,
        timeout: int = 10,
        verify_tls: bool = True,
    ) -> dict[str, Any]:
        """Execute all recorded rollback actions in LIFO order.

        Actions are executed in **reverse order** of creation — the last
        thing created is cleaned up first.  Failures are logged but do
        not stop the remaining actions.

        Parameters
        ----------
        vault_addr: Target Vault URL.
        token: Vault token with sufficient privileges for cleanup.
        timeout: HTTP timeout per action.
        verify_tls: Whether to verify TLS certificates.

        Returns
        -------
        Dict with ``total``, ``succeeded``, ``failed``, and ``details`` keys.
        """
        import requests as _requests
        from core.tls_config import get_verify

        verify = verify_tls and get_verify()

        with self._lock:
            actions = list(self._actions)
            self._actions.clear()

        if not actions:
            logger.info("[cleanup] No actions to roll back.")
            return {"total": 0, "succeeded": 0, "failed": 0, "details": []}

        # LIFO: reverse the list
        actions.reverse()

        headers = {"X-Vault-Token": token}
        results: list[dict] = []
        succeeded = 0
        failed = 0

        logger.info(f"[cleanup] Starting rollback of {len(actions)} action(s)…")

        for i, action in enumerate(actions, 1):
            url = action.build_url(vault_addr)
            method, body = self._strategy_to_request(action)

            try:
                logger.info(
                    f"[cleanup] [{i}/{len(actions)}] {action.description} "
                    f"→ {method} {url}"
                )
                kwargs: dict = dict(
                    method=method, url=url, headers=headers,
                    timeout=timeout, verify=verify,
                )
                if body is not None:
                    kwargs["json"] = body

                resp = _requests.request(**kwargs)

                ok = resp.status_code in (200, 204)
                detail = {
                    "action_id": action.action_id,
                    "description": action.description,
                    "strategy": action.strategy.value,
                    "status_code": resp.status_code,
                    "success": ok,
                }
                if ok:
                    succeeded += 1
                    logger.success(f"[cleanup]   ✓ {action.description}")
                else:
                    failed += 1
                    detail["response"] = resp.text[:200]
                    logger.warning(
                        f"[cleanup]   ✗ {action.description} "
                        f"(HTTP {resp.status_code})"
                    )
                results.append(detail)

            except Exception as exc:
                failed += 1
                logger.error(f"[cleanup]   ✗ {action.description}: {exc}")
                results.append({
                    "action_id": action.action_id,
                    "description": action.description,
                    "strategy": action.strategy.value,
                    "success": False,
                    "error": str(exc),
                })

        summary = {
            "total": len(actions),
            "succeeded": succeeded,
            "failed": failed,
            "details": results,
        }
        logger.info(
            f"[cleanup] Rollback complete: {succeeded}/{len(actions)} "
            f"succeeded, {failed} failed."
        )
        return summary

    def clear(self):
        """Discard all recorded actions without executing them."""
        with self._lock:
            count = len(self._actions)
            self._actions.clear()
            logger.info(f"[cleanup] Cleared {count} rollback action(s).")

    @property
    def status(self) -> dict:
        """Diagnostic snapshot."""
        with self._lock:
            by_module: dict[str, int] = {}
            for a in self._actions:
                by_module[a.module_id] = by_module.get(a.module_id, 0) + 1
            return {
                "total_actions": len(self._actions),
                "by_module": by_module,
                "actions": [
                    {
                        "action_id": a.action_id,
                        "module_id": a.module_id,
                        "description": a.description,
                        "strategy": a.strategy.value,
                    }
                    for a in self._actions
                ],
            }

    # ── internal ────────────────────────────────────────────────────────

    @staticmethod
    def _strategy_to_request(action: RollbackAction) -> tuple[str, dict | None]:
        """Convert a strategy to (HTTP_method, body_or_None)."""
        strategy = action.strategy

        if strategy in (RollbackStrategy.DELETE_AUTH, RollbackStrategy.DISABLE_AUTH):
            return ("DELETE", None)

        if strategy == RollbackStrategy.DELETE_ROLE:
            return ("DELETE", None)

        if strategy == RollbackStrategy.DELETE_POLICY:
            return ("DELETE", None)

        if strategy == RollbackStrategy.REVOKE_TOKEN:
            # For token revocation, vault_path should be the token accessor
            # or we POST with the token in the body
            return ("POST", action.vault_body or {"token": action.vault_path})

        if strategy == RollbackStrategy.RESTORE_POLICY:
            return ("PUT", action.vault_body)

        if strategy == RollbackStrategy.ENABLE_AUDIT:
            return ("POST", action.vault_body)

        # Fallback
        return ("DELETE", None)

    # ── singleton ───────────────────────────────────────────────────────

    _instance: CleanupEngine | None = None
    _instance_lock = threading.Lock()

    @classmethod
    def get(cls) -> CleanupEngine:
        """Get or create the global singleton instance."""
        if cls._instance is not None:
            return cls._instance
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance
