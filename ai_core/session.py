"""MCP session management.

Replaces the bare ``pentest_context`` dict with a typed ``PentestSession``
and a thread-safe ``SessionManager`` that supports multi-session isolation,
token history, plan tracking, and export/import.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TokenEntry:
    token: str
    source: str  # "user_provided" | "env_scan" | "privilege_escalation"
    power_level: str = "unknown"
    obtained_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class PentestSession:
    """Holds all state for a single pentest session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    targets: list[str] = field(default_factory=list)
    active_target: str | None = None
    token_history: list[TokenEntry] = field(default_factory=list)
    active_token: str | None = None
    escalated_token: str | None = None
    namespace: str | None = None
    current_phase: str = "recon"
    active_plan: dict | None = None
    plan_history: list[dict] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_activity: str = ""

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc).isoformat()

    def add_token(
        self,
        token: str,
        source: str = "user_provided",
        power_level: str = "unknown",
    ) -> None:
        entry = TokenEntry(
            token=token, source=source, power_level=power_level,
        )
        self.token_history.append(entry)
        self.active_token = token
        self.touch()

    def set_escalated_token(self, token: str) -> None:
        entry = TokenEntry(
            token=token, source="privilege_escalation", power_level="unknown",
        )
        self.token_history.append(entry)
        self.escalated_token = token
        self.touch()

    def get_resolved_token(self) -> str | None:
        """Return the best available token (escalated > active > first in history)."""
        return self.escalated_token or self.active_token or next(
            (t.token for t in reversed(self.token_history)), None
        )

    def set_target(self, addr: str) -> None:
        self.active_target = addr
        if addr not in self.targets:
            self.targets.append(addr)
        self.touch()

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "targets": self.targets,
            "active_target": self.active_target,
            "token_history": [
                {"token": t.token[:16] + "..." if len(t.token) > 16 else t.token,
                 "source": t.source, "power_level": t.power_level,
                 "obtained_at": t.obtained_at}
                for t in self.token_history
            ],
            "active_token": _redact(self.active_token),
            "escalated_token": _redact(self.escalated_token),
            "namespace": self.namespace,
            "current_phase": self.current_phase,
            "active_plan": self.active_plan,
            "plan_history": self.plan_history,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
        }


def _redact(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:12] + "..." if len(value) > 12 else value


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------


class SessionManager:
    """Thread-safe store of named pentest sessions."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._sessions: dict[str, PentestSession] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl_seconds

    def create_session(self) -> PentestSession:
        session = PentestSession()
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_or_create(self, session_id: str) -> PentestSession:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = PentestSession()
            session = self._sessions[session_id]
            session.touch()
            return session

    def get(self, session_id: str) -> PentestSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def cleanup_expired(self, ttl_seconds: int | None = None) -> int:
        """Remove sessions idle longer than *ttl_seconds*. Returns count removed."""
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.time()
        expired: list[str] = []
        with self._lock:
            for sid, s in self._sessions.items():
                last = s.last_activity
                if last:
                    try:
                        dt = datetime.fromisoformat(last).timestamp()
                        if now - dt > ttl:
                            expired.append(sid)
                    except (ValueError, OSError):
                        pass
            for sid in expired:
                del self._sessions[sid]
        return len(expired)

    def export_session(self, session_id: str) -> dict | None:
        session = self.get(session_id)
        return session.to_dict() if session else None

    def session_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())


# Module-level default manager
session_manager = SessionManager()
