"""Tests for thread-safe DynamicCredentialStore and ExecutionContext."""

import concurrent.futures
import threading
import time

import pytest

from active_execution.context import ExecutionContext
from ai_core.dynamic_session import DynamicCredentialStore, TokenRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_token(n: int) -> str:
    """Deterministic fake Vault token for test *n*."""
    return f"hvs.thread-test-{n:04d}-{n*37:08x}-abcdef"


def _add_token(store: DynamicCredentialStore, n: int) -> TokenRecord | None:
    return store.add_token(_fake_token(n), source=f"thread-{n}")


# ---------------------------------------------------------------------------
# DynamicCredentialStore — concurrent token adds
# ---------------------------------------------------------------------------


class TestConcurrentTokenAdds:
    """Verify that parallel add_token calls do not lose data."""

    def test_many_unique_tokens_all_stored(self):
        """50 threads each adding a unique token — all 50 must be stored."""
        store = DynamicCredentialStore()
        N = 50

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
            futures = [pool.submit(_add_token, store, i) for i in range(N)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Every add should succeed (return a TokenRecord, not None)
        records = [r for r in results if r is not None]
        assert len(records) == N, f"Expected {N} successful adds, got {len(records)}"
        assert len(store.tokens) == N

    def test_same_token_added_from_many_threads_deduped(self):
        """50 threads adding the SAME token — only 1 must be stored."""
        store = DynamicCredentialStore()
        SAME_TOKEN = "hvs.same-token-thread-test-abcd1234567890ef"
        N = 50

        def _add_same():
            return store.add_token(SAME_TOKEN, source="dedup-test")

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
            futures = [pool.submit(_add_same) for _ in range(N)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Exactly one thread should succeed
        successes = [r for r in results if r is not None]
        assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
        assert len(store.tokens) == 1


# ---------------------------------------------------------------------------
# DynamicCredentialStore — stress test (reads during concurrent writes)
# ---------------------------------------------------------------------------


class TestConcurrentStress:
    """Verify no RuntimeError during concurrent reads + writes."""

    def test_read_during_writes_does_not_throw(self):
        """100 iterations of concurrent add_token + get_best_token + status_summary."""
        store = DynamicCredentialStore()
        ITERATIONS = 100
        errors: list[Exception] = []

        def writer():
            for i in range(ITERATIONS):
                try:
                    store.add_token(_fake_token(i), source=f"stress-{i}")
                except Exception as exc:
                    errors.append(exc)

        def reader():
            for _ in range(ITERATIONS):
                try:
                    store.get_best_token()
                    store.status_summary()
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, (
            f"Got {len(errors)} errors during concurrent stress test: "
            f"{[str(e) for e in errors[:3]]}"
        )

    def test_add_credential_concurrent_no_duplicates(self):
        """Concurrent adds of the same credential should dedup."""
        store = DynamicCredentialStore()
        N = 20

        def _add_same_cred():
            return store.add_credential(
                "password", "supersecret123", source="stress"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
            futures = [pool.submit(_add_same_cred) for _ in range(N)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        successes = [r for r in results if r is not None]
        assert len(successes) == 1
        assert len(store.credentials) == 1

    def test_parse_tool_result_concurrent(self):
        """Multiple threads scanning tool results simultaneously."""
        store = DynamicCredentialStore()
        # Tool result containing a token
        result = (
            '{"status": "completed", '
            '"auth": {"client_token": "hvs.concurrent-parse-test-token-abc"}}'
        )
        N = 30

        def _parse():
            return store.parse_tool_result("test_tool", result)

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
            futures = [pool.submit(_parse) for _ in range(N)]
            concurrent.futures.wait(futures)

        # The token should be added exactly once
        assert len(store.tokens) == 1
        assert any("hvs.concurrent-parse-test-token-abc" in t for t in store.tokens)


# ---------------------------------------------------------------------------
# ExecutionContext — concurrent add_finding
# ---------------------------------------------------------------------------


class TestExecutionContextConcurrent:
    """Verify ExecutionContext.add_finding is thread-safe."""

    def test_concurrent_add_findings_all_stored(self):
        """50 threads each add a finding — all 50 must be in the list."""
        ctx = ExecutionContext(vault_addr="https://vault.test")
        N = 50

        def _add(n: int):
            ctx.add_finding(
                title=f"Finding {n}",
                description=f"Description {n}",
                severity="HIGH",
            )
            return n

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
            futures = [pool.submit(_add, i) for i in range(N)]
            concurrent.futures.wait(futures)

        assert len(ctx.findings) == N, (
            f"Expected {N} findings, got {len(ctx.findings)}"
        )
        # Verify no corruption: each finding should have the expected keys
        for f in ctx.findings:
            assert "severity" in f
            assert "title" in f
            assert "description" in f


# ---------------------------------------------------------------------------
# Lock correctness
# ---------------------------------------------------------------------------


class TestLockCorrectness:
    """Verify the lock is actually an RLock and methods are reentrant."""

    def test_dynamic_session_uses_rlock(self):
        """The lock must be reentrant (RLock) so nested calls don't deadlock."""
        store = DynamicCredentialStore()
        # RLock is a factory function; the returned object type is _thread.RLock.
        # Verify reentrancy behaviourally: acquire twice from the same thread.
        acquired = store._lock.acquire(blocking=False)
        assert acquired, "Could not acquire lock — already held?"
        reacquired = store._lock.acquire(blocking=False)
        assert reacquired, "Lock is NOT reentrant — must use threading.RLock, not Lock"
        store._lock.release()
        store._lock.release()

    def test_execution_context_uses_lock(self):
        """ExecutionContext must have a lock attribute."""
        ctx = ExecutionContext(vault_addr="https://vault.test")
        assert hasattr(ctx, "_lock"), "ExecutionContext missing _lock"
        assert hasattr(ctx._lock, "acquire"), "_lock is not a lock object"

    def test_add_user_token_is_reentrant(self):
        """add_user_token → add_token chain works under RLock (no deadlock)."""
        store = DynamicCredentialStore()
        # Acquire the lock manually, then call add_user_token (which
        # internally calls add_token → also acquires lock). With RLock
        # this should succeed; with plain Lock it would deadlock.
        with store._lock:
            rec = store.add_user_token("hvs.reentrant-test-token-abc1234567890")
        # If we got here without deadlocking, RLock works correctly
        # add_user_token delegates to add_token which acquires the same lock
        assert rec is not None or rec is None  # just checking no deadlock

    def test_global_singleton_is_thread_safe_type(self):
        """The global_store singleton has a reentrant lock."""
        from ai_core.dynamic_session import global_store
        # Verify reentrant: acquire twice from same thread without deadlock.
        # Wrap in try/finally to guarantee cleanup of the global singleton.
        lock = global_store._lock
        try:
            acquired = lock.acquire(blocking=False)
            assert acquired
            reacquired = lock.acquire(blocking=False)
            assert reacquired, "global_store lock is NOT reentrant"
        finally:
            # Release all nested acquisitions
            while getattr(lock, '_is_owned', lambda: False)():
                try:
                    lock.release()
                except RuntimeError:
                    break
