"""Persistent read-only safety lock.

When the lock is enabled, ``scan`` and ``chat`` are hard-pinned to the
``read_only`` risk level regardless of ``--active-max-risk`` /
``--auto-max-risk`` and ``--confirm-active``. No state-changing or
destructive module can run until the lock is disabled with
``vaultcat safety off``.

The lock is stored in the user home directory (``~/.vaultcat/safety.lock``)
so it applies machine-wide — the intent is to prevent accidentally running
destructive modules against a live/production system.
"""

from __future__ import annotations

from pathlib import Path


def _lock_path() -> Path:
    return Path.home() / ".vaultcat" / "safety.lock"


def is_safe_mode() -> bool:
    """Return True when the read-only safety lock is enabled."""
    return _lock_path().exists()


def set_safe_mode(on: bool) -> None:
    """Enable (True) or disable (False) the read-only safety lock."""
    lock = _lock_path()
    if on:
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text("read_only", encoding="utf-8")
    else:
        lock.unlink(missing_ok=True)
