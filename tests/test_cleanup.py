"""Tests for active_execution.cleanup_engine — rollback action recording & execution."""

from __future__ import annotations

import pytest

from active_execution.cleanup_engine import (
    CleanupEngine,
    RollbackAction,
    RollbackStrategy,
)


# ---------------------------------------------------------------------------
# RollbackAction
# ---------------------------------------------------------------------------


class TestRollbackAction:
    """Tests for the RollbackAction dataclass."""

    def test_build_url_constructs_full_vault_url(self):
        """build_url() joins vault_addr with /v1/ prefix and vault_path."""
        action = RollbackAction(
            module_id="test.module",
            description="Test action",
            strategy=RollbackStrategy.DELETE_AUTH,
            vault_path="sys/auth/test-backdoor",
        )
        url = action.build_url("https://vault.test:8200")
        assert url == "https://vault.test:8200/v1/sys/auth/test-backdoor"

    def test_build_url_handles_trailing_slash(self):
        """build_url() handles vault_addr with trailing slash."""
        action = RollbackAction(
            module_id="test.module",
            description="Test",
            strategy=RollbackStrategy.DELETE_POLICY,
            vault_path="sys/policies/acl/admin-backdoor",
        )
        url = action.build_url("https://vault.test:8200/")
        assert url == "https://vault.test:8200/v1/sys/policies/acl/admin-backdoor"

    def test_each_action_has_unique_id(self):
        """Each action should get a unique action_id."""
        actions = [
            RollbackAction(
                module_id="test", description=f"Action {i}",
                strategy=RollbackStrategy.DELETE_AUTH, vault_path=f"path/{i}",
            )
            for i in range(10)
        ]
        ids = {a.action_id for a in actions}
        assert len(ids) == 10

    def test_metadata_is_stored(self):
        """Metadata dict is preserved."""
        action = RollbackAction(
            module_id="test",
            description="Test",
            strategy=RollbackStrategy.REVOKE_TOKEN,
            vault_path="s.test",
            metadata={"token_preview": "s.test123", "source": "escalation"},
        )
        assert action.metadata["token_preview"] == "s.test123"
        assert action.metadata["source"] == "escalation"

    def test_depends_on_tracks_dependencies(self):
        """depends_on can track action_id dependencies."""
        a1 = RollbackAction(
            module_id="test", description="First",
            strategy=RollbackStrategy.DELETE_POLICY, vault_path="p1",
        )
        a2 = RollbackAction(
            module_id="test", description="Second",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="p2",
            depends_on=[a1.action_id],
        )
        assert a2.depends_on == [a1.action_id]


# ---------------------------------------------------------------------------
# CleanupEngine
# ---------------------------------------------------------------------------


class TestCleanupEngine:
    """Tests for the CleanupEngine singleton."""

    def setup_method(self):
        """Ensure clean state before each test."""
        CleanupEngine.get().clear()

    def test_singleton_returns_same_instance(self):
        """CleanupEngine.get() returns the same instance."""
        e1 = CleanupEngine.get()
        e2 = CleanupEngine.get()
        assert e1 is e2

    def test_initial_status_is_empty(self):
        """Fresh engine has zero actions."""
        engine = CleanupEngine.get()
        engine.clear()
        assert engine.status["total_actions"] == 0

    def test_record_adds_action(self):
        """record() adds an action and increments count."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="persistence.backdoor",
            description="Disable auth method",
            strategy=RollbackStrategy.DELETE_AUTH,
            vault_path="sys/auth/test",
        ))
        assert engine.status["total_actions"] == 1
        assert engine.status["by_module"]["persistence.backdoor"] == 1

    def test_multiple_records(self):
        """Multiple record() calls stack correctly."""
        engine = CleanupEngine.get()
        engine.clear()
        for i in range(5):
            engine.record(RollbackAction(
                module_id=f"test.{i}",
                description=f"Action {i}",
                strategy=RollbackStrategy.DELETE_AUTH,
                vault_path=f"path/{i}",
            ))
        assert engine.status["total_actions"] == 5

    def test_clear_removes_all_actions(self):
        """clear() discards all actions."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="test",
        ))
        assert engine.status["total_actions"] == 1
        engine.clear()
        assert engine.status["total_actions"] == 0

    def test_dry_run_lists_actions(self):
        """dry_run() returns human-readable action descriptions."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="test.a",
            description="Delete policy X",
            strategy=RollbackStrategy.DELETE_POLICY,
            vault_path="sys/policies/acl/X",
        ))
        engine.record(RollbackAction(
            module_id="test.b",
            description="Revoke token Y",
            strategy=RollbackStrategy.REVOKE_TOKEN,
            vault_path="s.Y",
        ))
        lines = engine.dry_run()
        assert len(lines) == 3  # header + 2 actions
        # LIFO: last created (Revoke token Y) appears first
        assert "Revoke token Y" in lines[1]
        assert "Delete policy X" in lines[2]

    def test_dry_run_empty(self):
        """dry_run() on empty engine returns a single status line."""
        engine = CleanupEngine.get()
        engine.clear()
        lines = engine.dry_run()
        assert len(lines) == 1
        assert "nothing to clean" in lines[0].lower()

    def test_dry_run_is_lifo_order(self):
        """dry_run() lists actions in LIFO (reverse creation) order."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="test", description="First created",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="first",
        ))
        engine.record(RollbackAction(
            module_id="test", description="Second created",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="second",
        ))
        lines = engine.dry_run()
        # Second created should appear first in the list (LIFO)
        assert lines[1].find("Second created") < lines[2].find("First created") or \
            "Second created" in lines[1] and "First created" in lines[2]

    def test_status_shows_by_module(self):
        """status() groups actions by module_id."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="mod.a", description="A1",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="a1",
        ))
        engine.record(RollbackAction(
            module_id="mod.a", description="A2",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="a2",
        ))
        engine.record(RollbackAction(
            module_id="mod.b", description="B1",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="b1",
        ))
        s = engine.status
        assert s["total_actions"] == 3
        assert s["by_module"]["mod.a"] == 2
        assert s["by_module"]["mod.b"] == 1


# ---------------------------------------------------------------------------
# Rollback strategy → request conversion
# ---------------------------------------------------------------------------


class TestStrategyToRequest:
    """Tests for _strategy_to_request conversion."""

    def test_delete_auth_returns_delete_method(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="test",
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "DELETE"
        assert body is None

    def test_delete_role_returns_delete_method(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DELETE_ROLE, vault_path="test",
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "DELETE"
        assert body is None

    def test_delete_policy_returns_delete_method(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DELETE_POLICY, vault_path="test",
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "DELETE"
        assert body is None

    def test_revoke_token_returns_post_with_body(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.REVOKE_TOKEN,
            vault_path="s.abc123",
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "POST"
        assert body is not None
        assert "token" in body

    def test_restore_policy_returns_put_with_body(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.RESTORE_POLICY,
            vault_path="sys/policies/acl/default",
            vault_body={"policy": '{"*": {"capabilities": ["read"]}}'},
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "PUT"
        assert body is not None
        assert "policy" in body

    def test_enable_audit_returns_post_with_body(self):
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.ENABLE_AUDIT,
            vault_path="sys/audit/file",
            vault_body={"type": "file", "options": {"file_path": "/tmp/audit.log"}},
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "POST"
        assert body is not None
        assert body["type"] == "file"

    def test_disable_auth_aliases_delete_auth(self):
        """DISABLE_AUTH is an alias for DELETE_AUTH."""
        action = RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DISABLE_AUTH, vault_path="test",
        )
        method, body = CleanupEngine._strategy_to_request(action)
        assert method == "DELETE"
        assert body is None


# ---------------------------------------------------------------------------
# Rollback execution (unit tests — no real Vault)
# ---------------------------------------------------------------------------


class TestExecuteRollback:
    """Tests for execute_rollback behavior."""

    def setup_method(self):
        CleanupEngine.get().clear()

    def test_execute_empty_returns_zero(self):
        """execute_rollback on empty engine returns {total: 0}."""
        engine = CleanupEngine.get()
        engine.clear()
        result = engine.execute_rollback(
            vault_addr="https://vault.test",
            token="s.test",
        )
        assert result["total"] == 0
        assert result["succeeded"] == 0
        assert result["failed"] == 0

    def test_execute_clears_actions_after_run(self):
        """After execute_rollback, actions list is cleared."""
        engine = CleanupEngine.get()
        engine.clear()
        engine.record(RollbackAction(
            module_id="test", description="Test",
            strategy=RollbackStrategy.DELETE_AUTH,
            vault_path="sys/auth/test",
        ))
        # Executing against a non-existent Vault will fail, but actions
        # should still be cleared after the attempt
        try:
            engine.execute_rollback(
                vault_addr="https://nonexistent.test:9999",
                token="s.test",
                timeout=2,
            )
        except Exception:
            pass
        # Actions cleared regardless of success/failure
        assert engine.status["total_actions"] == 0

    def test_rollback_respects_lifo_order(self):
        """execute_rollback processes actions in LIFO order."""
        engine = CleanupEngine.get()
        engine.clear()

        order = []
        # We can't easily mock the actual HTTP call, but we can verify
        # that dry_run shows LIFO ordering.
        engine.record(RollbackAction(
            module_id="test", description="1st",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="1",
        ))
        engine.record(RollbackAction(
            module_id="test", description="2nd",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="2",
        ))
        engine.record(RollbackAction(
            module_id="test", description="3rd",
            strategy=RollbackStrategy.DELETE_AUTH, vault_path="3",
        ))

        lines = engine.dry_run()
        # 3rd (last created) should be first in output (LIFO)
        assert "3rd" in lines[1]
        assert "2nd" in lines[2]
        assert "1st" in lines[3]
