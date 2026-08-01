"""Dynamic credential store — tracks discovered tokens and auto-escalates.

Every discovered token, credential, or AppRole pair is registered here.
The store then provides the best available token for each subsequent
tool call, enabling dynamic privilege escalation during a pentest.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Token power-level ordering (higher = more privileged)
# ---------------------------------------------------------------------------

POWER_RANK: dict[str, int] = {
    "root": 5,
    "sudo": 4,
    "high": 3,
    "elevated": 2,
    "user": 1,
    "unknown": 0,
}


# Patterns for scanning tool results
_VAULT_TOKEN_RE = re.compile(r'\b(hvs\.[A-Za-z0-9_\-]{20,})\b')
_VAULT_TOKEN_RE_2 = re.compile(r'\b(hvb\.[A-Za-z0-9_\-]{20,})\b')
_VAULT_TOKEN_RE_3 = re.compile(r'\b(s\.[A-Za-z0-9]{24,})\b')
_TOKEN_PREVIEW_RE = re.compile(r'([A-Za-z0-9_\-]{10,}\.{0,1}[A-Za-z0-9_\-]{20,})')

# JSON field names that might contain tokens
_TOKEN_JSON_FIELDS = {
    "token", "captured_token", "escalated_token", "client_token",
    "new_token", "created_token", "accessor_token", "auth_token",
    "root_token",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TokenRecord:
    token: str
    source: str  # tool name or "user"
    power_level: str = "unknown"  # root, sudo, high, elevated, user, unknown
    capabilities: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class CredentialRecord:
    cred_type: str  # "password", "api_key", "approle_role_id", "approle_secret_id", "db_conn"
    value: str
    source: str
    metadata: dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ---------------------------------------------------------------------------
# Dynamic store
# ---------------------------------------------------------------------------


class DynamicCredentialStore:
    """Thread-safe store of all credentials discovered during a pentest.

    Used by ChatUI, PentestAgent, and AutoPentestRunner to track
    escalating privileges and auto-inject the best token.
    """

    def __init__(self):
        self.tokens: dict[str, TokenRecord] = {}  # keyed by token value
        self.credentials: dict[str, CredentialRecord] = {}  # keyed by type:value
        self._escalation_log: list[str] = []
        self._lock = threading.RLock()  # protects all state access

    # ── token management ──────────────────────────────────────────────────

    def add_token(
        self,
        token: str,
        source: str = "unknown",
        power_level: str = "unknown",
        capabilities: list[str] | None = None,
        policies: list[str] | None = None,
    ) -> TokenRecord | None:
        """Register a discovered token. Returns None if already known.

        Thread-safe: the check-then-act on ``self.tokens`` is protected by
        ``self._lock`` (``RLock``) so that two threads adding the same token
        concurrently cannot both succeed.
        """
        if not token or not _looks_like_vault_token(token):
            return None

        # Normalize
        token = token.strip().strip('"').strip("'")

        with self._lock:
            if token in self.tokens:
                return None  # already tracked

            # Try to infer power level from capabilities/policies
            if power_level == "unknown":
                power_level = _infer_power(capabilities or [], policies or [])

            rec = TokenRecord(
                token=token,
                source=source,
                power_level=power_level,
                capabilities=capabilities or [],
                policies=policies or [],
            )
            self.tokens[token] = rec

            prev_best = self._previous_best_power()
            new_best = POWER_RANK.get(power_level, 0)

            msg = (
                f"[SESSION] Token discovered: {source} -> "
                f"{token} (power: {power_level})"
            )
            if new_best > prev_best:
                msg += " *** ESCALATED ***"
            self._escalation_log.append(msg)

            return rec

    def add_user_token(self, token: str) -> TokenRecord | None:
        """Register the user-provided token (initial auth)."""
        return self.add_token(token, source="user", power_level="unknown")

    def get_best_token(self) -> TokenRecord | None:
        """Return the highest-privilege token currently known.

        Thread-safe: dict iteration is protected against concurrent writes.
        """
        with self._lock:
            if not self.tokens:
                return None
            return max(
                self.tokens.values(),
                key=lambda t: (POWER_RANK.get(t.power_level, 0), len(t.capabilities)),
            )

    def get_best_token_value(self) -> str | None:
        best = self.get_best_token()
        return best.token if best else None

    # ── credential management ─────────────────────────────────────────────

    def add_credential(
        self,
        cred_type: str,
        value: str,
        source: str = "unknown",
        metadata: dict | None = None,
    ) -> CredentialRecord | None:
        """Register a discovered credential (password, API key, etc.).

        Thread-safe: the check-then-act on ``self.credentials`` is atomic.
        """
        key = f"{cred_type}:{value[:30]}"
        with self._lock:
            if key in self.credentials:
                return None

            rec = CredentialRecord(
                cred_type=cred_type,
                value=value,
                source=source,
                metadata=metadata or {},
            )
            self.credentials[key] = rec
            return rec

    # ── result parsing ────────────────────────────────────────────────────

    def parse_tool_result(self, tool_name: str, result_text: str) -> list[str]:
        """Scan a tool result for new tokens and credentials.

        Returns list of discovery messages (empty if nothing new).

        Thread-safe: the entire scan-and-add pipeline runs under the lock
        so no other thread can interleave a concurrent token/credential add.
        """
        messages: list[str] = []

        with self._lock:
            try:
                data = json.loads(result_text)
            except (json.JSONDecodeError, TypeError):
                data = result_text  # might be plain text

            # ---- scan JSON for token fields ----
            if isinstance(data, dict):
                messages.extend(self._scan_dict_for_tokens(data, tool_name))
                messages.extend(self._scan_dict_for_credentials(data, tool_name))

            # ---- scan plain text for Vault token patterns ----
            if isinstance(result_text, str):
                for match in _VAULT_TOKEN_RE.finditer(result_text):
                    token = match.group(1)
                    rec = self.add_token(token, source=tool_name)
                    if rec:
                        messages.append(f"token:{rec.power_level}:{token}")

            return messages

    def _scan_dict_for_tokens(self, data: dict, source: str) -> list[str]:
        """Recursively scan a JSON dict for token-like fields.

        Caller must hold ``self._lock`` (this method mutates ``self.tokens``
        values and iterates over ``self.tokens.values()``).
        """
        messages: list[str] = []
        stack = [data]

        while stack:
            obj = stack.pop()
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in _TOKEN_JSON_FIELDS and isinstance(value, str):
                        if _looks_like_vault_token(value):
                            rec = self.add_token(str(value), source=source)
                            if rec:
                                messages.append(f"token:{rec.power_level}:{value}")
                    elif isinstance(value, (dict, list)):
                        stack.append(value)
                    elif isinstance(value, str) and _looks_like_vault_token(value):
                        rec = self.add_token(value, source=source)
                        if rec:
                            messages.append(f"token:{rec.power_level}:{value}")
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        stack.append(item)
                    elif isinstance(item, str) and _looks_like_vault_token(item):
                        rec = self.add_token(item, source=source)
                        if rec:
                            messages.append(f"token:{rec.power_level}:{item}")

        # Also parse token capabilities from capability audit results
        findings = data.get("findings", [])
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    desc = f.get("description", "")
                    title = f.get("title", "")
                    combined = f"{title} {desc}"
                    # Check for root/sudo mentions
                    if any(w in combined.lower() for w in ("root", "sudo", "wildcard")):
                        # Update existing tokens with this info
                        for rec in self.tokens.values():
                            if rec.power_level == "unknown":
                                if "root" in combined.lower():
                                    rec.power_level = "root"
                                elif "sudo" in combined.lower():
                                    rec.power_level = "sudo"
                                elif "wildcard" in combined.lower():
                                    rec.power_level = "high"

        return messages

    def _scan_dict_for_credentials(self, data: dict, source: str) -> list[str]:
        """Scan a JSON dict for non-token credentials (passwords, API keys)."""
        messages: list[str] = []

        # leaked_payloads from secret exfiltration
        payloads = data.get("leaked_payloads", {})
        if isinstance(payloads, dict):
            for path, secrets in payloads.items():
                if isinstance(secrets, dict):
                    for key, value in secrets.items():
                        if isinstance(value, str) and len(value) > 3:
                            cred_type = _classify_credential(key)
                            self.add_credential(
                                cred_type, str(value), source=source,
                                metadata={"path": path, "key": key},
                            )
                            messages.append(f"cred:{cred_type}:{key}")

        # evidence tokens
        evidence = data.get("evidence", {})
        if isinstance(evidence, dict):
            for key in ("escalated_token", "captured_token", "root_token"):
                val = evidence.get(key)
                if isinstance(val, str) and _looks_like_vault_token(val):
                    rec = self.add_token(val, source=source)
                    if rec:
                        messages.append(f"token:{rec.power_level}:{val}")

        return messages

    # ── status ────────────────────────────────────────────────────────────

    def status_summary(self) -> dict:
        """Thread-safe snapshot of the current credential store state."""
        with self._lock:
            best = self.get_best_token()
            return {
                "total_tokens": len(self.tokens),
                "total_credentials": len(self.credentials),
                "best_token_power": best.power_level if best else "none",
                "best_token_preview": best.token if best else "none",
                "best_token_source": best.source if best else "none",
                "token_powers": {
                    power: sum(1 for t in self.tokens.values() if t.power_level == power)
                    for power in POWER_RANK
                },
                "escalation_count": sum(
                    1 for msg in self._escalation_log if "ESCALATED" in msg
                ),
            }

    def _previous_best_power(self) -> int:
        best = self.get_best_token()
        return POWER_RANK.get(best.power_level, 0) if best else 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _looks_like_vault_token(value: str) -> bool:
    """Quick check: does this string look like a Vault token?"""
    if not value or not isinstance(value, str):
        return False
    if len(value) < 20:
        return False
    return value.startswith(("hvs.", "hvb.", "s."))


def _infer_power(capabilities: list[str], policies: list[str]) -> str:
    """Infer token power level from capabilities and policy names."""
    caps_lower = " ".join(capabilities).lower()
    pols_lower = " ".join(policies).lower()

    if "root" in caps_lower or "root" in pols_lower:
        return "root"
    if "sudo" in caps_lower:
        return "sudo"
    if any(w in caps_lower for w in ("sys/*", "auth/*", "identity/*", "*")):
        return "sudo"
    if any(w in caps_lower for w in ("secret/*", "kv/*")):
        return "high"
    if any(w in caps_lower for w in ("read", "list", "create")):
        return "user"
    return "unknown"


def _classify_credential(key: str) -> str:
    """Classify a credential key by name."""
    key_lower = key.lower()
    if any(w in key_lower for w in ("password", "passwd", "pass", "pwd")):
        return "password"
    if any(w in key_lower for w in ("api_key", "apikey", "token", "secret")):
        return "api_key"
    if any(w in key_lower for w in ("role_id", "roleid")):
        return "approle_role_id"
    if any(w in key_lower for w in ("secret_id", "secretid")):
        return "approle_secret_id"
    if any(w in key_lower for w in ("conn", "dsn", "database_url", "db_url", "uri")):
        return "db_conn"
    if any(w in key_lower for w in ("access_key", "secret_key", "aws_")):
        return "cloud_key"
    return "unknown"


# ---------------------------------------------------------------------------
# Global singleton — shared across CLI, scanners, agent, active modules
# ---------------------------------------------------------------------------

global_store = DynamicCredentialStore()
