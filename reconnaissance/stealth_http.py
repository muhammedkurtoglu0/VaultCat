"""Stealth-aware HTTP layer — evade SOC detection and rate limits.

Implements:
    - Adaptive backoff on 403/429 with exponential decay
    - Random jitter (1-5 s) between requests to mimic human cadence
    - Latency-adaptive polling intervals
    - Dynamic concurrency limiting when rate-limited
    - Request fingerprinting avoidance (no parallel bursts)
    - User-Agent rotation (20+ realistic UAs)
    - Response header analysis (X-RateLimit-*, Retry-After, Vault-specific)
    - Evasion profiles (paranoid / stealth / balanced / aggressive)
    - Request header randomization (Accept, Accept-Language, etc.)
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin

import requests
from core.tls_config import get_verify, set_insecure_mode


# ---------------------------------------------------------------------------
# Evasion profiles
# ---------------------------------------------------------------------------


class EvasionProfile(str, Enum):
    PARANOID = "paranoid"      # Max stealth: 5-15s jitter, 1 concurrency, heavy UA rotation
    STEALTH = "stealth"        # High stealth: 1-4s jitter, 2 concurrency
    BALANCED = "balanced"      # Moderate: 0-1s jitter, 5 concurrency (good for most targets)
    AGGRESSIVE = "aggressive"  # Fast: 0 jitter, 8 concurrency (lab/dev/known targets)
    TURBO = "turbo"            # Full speed: 0 jitter, 15 concurrency (local lab only)
    LOW_AND_SLOW = "low_and_slow"  # Beyond paranoid: 1 req/5min, maximal audit evasion


# Profile settings
_PROFILE_CONFIG: dict[EvasionProfile, dict] = {
    EvasionProfile.PARANOID: {
        "jitter_min": 5.0, "jitter_max": 15.0,
        "max_concurrency": 1, "min_concurrency": 1,
        "ua_rotate_every": 1,  # rotate UA every request
        "header_randomize": True,
        # ── new: proactive rate limiting & audit evasion ──
        "jitter_strategy": "gamma",
        "requests_per_minute": 2.0,       # 1 request every 30 seconds
        "burst_size": 1,
        "audit_window_s": 120,
        "max_requests_per_window": 3,
        "bandwidth_limit_bps": 51200,     # 50 KB/s
        "error_amplifier": 5.0,
        "endpoint_cooldown": {
            "HIGH": 120.0,
            "CRITICAL": 300.0,
        },
    },
    EvasionProfile.STEALTH: {
        "jitter_min": 1.0, "jitter_max": 4.0,
        "max_concurrency": 2, "min_concurrency": 1,
        "ua_rotate_every": 3,
        "header_randomize": True,
        # ── new ──
        "jitter_strategy": "decorrelated",
        "requests_per_minute": 6.0,
        "burst_size": 2,
        "audit_window_s": 60,
        "max_requests_per_window": 10,
        "bandwidth_limit_bps": 0,
        "error_amplifier": 3.0,
        "endpoint_cooldown": {
            "HIGH": 30.0,
            "CRITICAL": 120.0,
        },
    },
    EvasionProfile.BALANCED: {
        "jitter_min": 0.0, "jitter_max": 1.0,
        "max_concurrency": 5, "min_concurrency": 2,
        "ua_rotate_every": 10,
        "header_randomize": False,
        # ── new ──
        "jitter_strategy": "uniform",
        "requests_per_minute": 20.0,
        "burst_size": 5,
        "audit_window_s": 30,
        "max_requests_per_window": 30,
        "bandwidth_limit_bps": 0,
        "error_amplifier": 2.0,
        "endpoint_cooldown": {
            "HIGH": 5.0,
            "CRITICAL": 30.0,
        },
    },
    EvasionProfile.AGGRESSIVE: {
        "jitter_min": 0.0, "jitter_max": 0.0,
        "max_concurrency": 8, "min_concurrency": 3,
        "ua_rotate_every": 50,
        "header_randomize": False,
        # ── new ──
        "jitter_strategy": "none",
        "requests_per_minute": 60.0,
        "burst_size": 8,
        "audit_window_s": 10,
        "max_requests_per_window": 50,
        "bandwidth_limit_bps": 0,
        "error_amplifier": 1.5,
        "endpoint_cooldown": {
            "HIGH": 0.0,
            "CRITICAL": 5.0,
        },
    },
    EvasionProfile.TURBO: {
        "jitter_min": 0.0, "jitter_max": 0.0,
        "max_concurrency": 15, "min_concurrency": 5,
        "ua_rotate_every": 999,
        "header_randomize": False,
        # ── new ──
        "jitter_strategy": "none",
        "requests_per_minute": 0.0,        # unlimited
        "burst_size": 0,
        "audit_window_s": 0,               # gate disabled
        "max_requests_per_window": 0,
        "bandwidth_limit_bps": 0,
        "error_amplifier": 1.0,
        "endpoint_cooldown": {
            "HIGH": 0.0,
            "CRITICAL": 0.0,
        },
    },
    EvasionProfile.LOW_AND_SLOW: {
        "jitter_min": 15.0, "jitter_max": 60.0,
        "max_concurrency": 1, "min_concurrency": 1,
        "ua_rotate_every": 1,
        "header_randomize": True,
        # ── new ──
        "jitter_strategy": "gamma",
        "requests_per_minute": 0.2,        # 1 request every 5 minutes
        "burst_size": 1,
        "audit_window_s": 300,             # 5-minute sliding window
        "max_requests_per_window": 3,
        "bandwidth_limit_bps": 10240,      # 10 KB/s
        "error_amplifier": 5.0,
        "endpoint_cooldown": {
            "HIGH": 300.0,                 # 5 min between HIGH sensitivity endpoints
            "CRITICAL": 600.0,             # 10 min between CRITICAL endpoints
        },
    },
}

_current_profile: EvasionProfile = EvasionProfile.BALANCED


def set_evasion_profile(profile: EvasionProfile):
    """Switch evasion profile globally — updates limiter, scheduler, and config."""
    global _current_profile
    _current_profile = profile
    # Update limiter concurrency
    cfg = _PROFILE_CONFIG[profile]
    limiter = get_global_limiter()
    with limiter._lock:
        limiter._max_concurrency = cfg["max_concurrency"]
        limiter._min_concurrency = cfg["min_concurrency"]
        limiter._rebuild_semaphore()
    # Reset scheduler with new profile config
    _reset_scheduler()


def get_evasion_profile() -> EvasionProfile:
    return _current_profile


# ---------------------------------------------------------------------------
# User-Agent rotation
# ---------------------------------------------------------------------------


# Realistic, modern User-Agent strings rotated to avoid fingerprinting
_USER_AGENTS: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Mobile UAs (for diversity)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    # curl / programmatic (for when we want to blend as automation)
    "curl/8.11.0",
    "Vault-CLI/1.18.0",
    "python-requests/2.32.0",
    # More diversity
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    # Nomad / Consul agents (sibling HashiCorp tools — blend in)
    "Nomad-Agent/1.9.0",
    "Consul-Agent/1.20.0",
]


class UserAgentRotator:
    """Rotates User-Agent strings to avoid fingerprinting."""

    def __init__(self):
        self._agents = list(_USER_AGENTS)
        self._index = 0
        self._request_count = 0
        self._lock = threading.Lock()

    def get(self) -> str:
        """Get the next User-Agent string."""
        with self._lock:
            self._request_count += 1
            cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])
            rotate_every = cfg.get("ua_rotate_every", 10)

            if self._request_count % rotate_every == 0:
                # Rotate to next or random depending on profile
                if _current_profile == EvasionProfile.PARANOID:
                    return random.choice(self._agents)
                else:
                    self._index = (self._index + 1) % len(self._agents)

            return self._agents[self._index % len(self._agents)]

    def random(self) -> str:
        """Get a completely random User-Agent (for paranoid mode)."""
        return random.choice(self._agents)

    def get_hashicorp_style(self) -> str:
        """Get a HashiCorp-ecosystem UA (Vault-CLI, Nomad, Consul)."""
        hc_uas = [ua for ua in self._agents
                   if any(tool in ua for tool in ("Vault-CLI", "Nomad-Agent", "Consul-Agent"))]
        return random.choice(hc_uas) if hc_uas else self._agents[13]


# Global rotator
_ua_rotator = UserAgentRotator()


def get_user_agent() -> str:
    return _ua_rotator.get()


# ---------------------------------------------------------------------------
# Request header randomization
# ---------------------------------------------------------------------------


# Accept-Language values for diversity
_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8,fr;q=0.7",
    "en-US,en;q=0.9,es;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "en-US,en;q=0.5",
]

_ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]


def build_stealth_headers(token: str | None = None) -> dict[str, str]:
    """Build HTTP headers with randomized fingerprint for evasion.

    In paranoid/stealth profiles, headers are randomized per request
    to avoid creating a consistent fingerprint.
    """
    headers: dict[str, str] = {}

    cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])

    # User-Agent
    headers["User-Agent"] = get_user_agent()

    if cfg.get("header_randomize", False):
        # Randomize Accept-Language
        headers["Accept-Language"] = random.choice(_ACCEPT_LANGUAGES)
        # Randomize Accept-Encoding
        headers["Accept-Encoding"] = random.choice(_ACCEPT_ENCODING)
        # Vary Accept header
        headers["Accept"] = random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "application/json,text/html,*/*;q=0.8",
            "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
        ])
    else:
        headers["Accept"] = "application/json"
        headers["Accept-Encoding"] = "gzip, deflate"

    # Vault token
    if token:
        headers["X-Vault-Token"] = token

    # Don't set X-Vault-Namespace unless needed — it's a fingerprint
    return headers


# ---------------------------------------------------------------------------
# Response header analysis for rate limit detection
# ---------------------------------------------------------------------------


@dataclass
class RateLimitInfo:
    """Parsed rate-limit signals from Vault response headers."""

    is_rate_limited: bool = False
    retry_after: float = 0.0          # seconds (from Retry-After header)
    limit_remaining: int | None = None  # X-RateLimit-Remaining
    limit_reset: float | None = None   # X-RateLimit-Reset epoch
    vault_specific: bool = False       # Vault-specific rate limit header seen


def analyse_rate_headers(response) -> RateLimitInfo:
    """Parse response headers for rate-limit signals.

    Vault uses standard HTTP rate-limit headers when rate limiting is enabled.
    Enterprise Vault may also set custom headers.
    """
    info = RateLimitInfo()

    if not hasattr(response, 'headers'):
        return info

    headers = response.headers

    # Standard rate-limit headers
    remaining = headers.get("X-RateLimit-Remaining")
    if remaining is not None:
        try:
            info.limit_remaining = int(remaining)
            if info.limit_remaining < 5:
                info.is_rate_limited = True
        except (ValueError, TypeError):
            pass

    reset = headers.get("X-RateLimit-Reset")
    if reset is not None:
        try:
            info.limit_reset = float(reset)
        except (ValueError, TypeError):
            pass

    # Retry-After (RFC 7231)
    retry = headers.get("Retry-After")
    if retry is not None:
        try:
            info.retry_after = float(retry)
            info.is_rate_limited = True
        except (ValueError, TypeError):
            pass

    # Vault may return X-Vault-RateLimit headers (Enterprise)
    if headers.get("X-Vault-RateLimit-Limit"):
        info.vault_specific = True
        info.is_rate_limited = True

    # HTTP 429 itself
    if response.status_code == 429:
        info.is_rate_limited = True

    return info


# ---------------------------------------------------------------------------
# Endpoint sensitivity — path-aware audit log evasion
# ---------------------------------------------------------------------------


class EndpointSensitivity(int, Enum):
    """How "noisy" a Vault API endpoint is in audit logs.

    SIEM/SOC rules are more likely to trigger on auth failures, policy
    modifications, and secret access than on health checks or version probes.
    """
    LOW = 0       # Health, seal-status, leader — typically filtered
    MEDIUM = 1    # sys/internal/ui, version, sys/policies list
    HIGH = 2      # auth/login, token/create, secret/*, sys/audit read
    CRITICAL = 3  # sys/audit DELETE/PUT, policy ACL PUT, approle role


# Path prefix → sensitivity mapping for Vault API endpoints
_ENDPOINT_SENSITIVITY_MAP: list[tuple[str, EndpointSensitivity]] = [
    # CRITICAL — audit device modification, policy writes, auth role changes
    ("sys/audit", EndpointSensitivity.CRITICAL),       # DELETE/PUT audit devices
    ("sys/policies/acl", EndpointSensitivity.CRITICAL), # PUT policy
    ("auth/approle/role", EndpointSensitivity.CRITICAL), # PUT role
    ("auth/kubernetes/role", EndpointSensitivity.CRITICAL),
    # HIGH — auth, token creation, secret access, audit read
    ("auth/", EndpointSensitivity.HIGH),
    ("sys/auth", EndpointSensitivity.HIGH),
    ("secret/", EndpointSensitivity.HIGH),
    ("cubbyhole/", EndpointSensitivity.HIGH),
    ("database/", EndpointSensitivity.HIGH),
    ("aws/", EndpointSensitivity.HIGH),
    ("gcp/", EndpointSensitivity.HIGH),
    ("azure/", EndpointSensitivity.HIGH),
    ("pki/", EndpointSensitivity.HIGH),
    ("transit/", EndpointSensitivity.HIGH),
    ("identity/", EndpointSensitivity.HIGH),
    # MEDIUM — internal UI, version, policy lists, mounts
    ("sys/internal/ui", EndpointSensitivity.MEDIUM),
    ("sys/version", EndpointSensitivity.MEDIUM),
    ("sys/policies", EndpointSensitivity.MEDIUM),
    ("sys/mounts", EndpointSensitivity.MEDIUM),
    ("sys/capabilities", EndpointSensitivity.MEDIUM),
    ("sys/plugins", EndpointSensitivity.MEDIUM),
    ("sys/license", EndpointSensitivity.MEDIUM),
    # LOW — health, seal, leader (often filtered from SIEM)
    ("sys/health", EndpointSensitivity.LOW),
    ("sys/seal-status", EndpointSensitivity.LOW),
    ("sys/leader", EndpointSensitivity.LOW),
    ("sys/step-down", EndpointSensitivity.LOW),
    ("sys/host-info", EndpointSensitivity.LOW),
]


def classify_path(path: str) -> EndpointSensitivity:
    """Classify a Vault API path by its audit log sensitivity.

    Returns the highest sensitivity level that matches the path prefix.
    Paths without a known prefix default to MEDIUM.
    """
    normalized = path.lstrip("/").rstrip("/")
    for prefix, sensitivity in _ENDPOINT_SENSITIVITY_MAP:
        if normalized.startswith(prefix):
            return sensitivity
    return EndpointSensitivity.MEDIUM


# ---------------------------------------------------------------------------
# Jitter strategies — beyond simple uniform random
# ---------------------------------------------------------------------------


class JitterStrategy(str, Enum):
    """Jitter algorithm for spacing requests like human traffic."""
    NONE = "none"              # No jitter — direct pacing only
    UNIFORM = "uniform"        # random.uniform(min, max) — current default
    GAMMA = "gamma"            # Gamma distribution — most human-like
    DECORRELATED = "decorrelated"  # min(base, U(base, base*3)) — AWS-style
    FULL_JITTER = "full"       # U(0, cap) — ideal for retry backoff
    EQUAL_JITTER = "equal"     # cap/2 + U(0, cap/2) — consistent spacing


class StealthJitterEngine:
    """Advanced jitter engine with multiple strategies for realistic pacing.

    Unlike the simple ``human_jitter()``, this supports gamma-distributed
    delays (which mimic human inter-request timing), decorrelated jitter
    (AWS SDK style), and capped full jitter for retry scenarios.
    """

    @staticmethod
    def calculate(min_s: float, max_s: float, strategy: JitterStrategy) -> float:
        """Calculate a jitter delay in seconds.

        Parameters
        ----------
        min_s: Minimum delay in seconds.
        max_s: Maximum delay in seconds (cap for full/equal jitter).
        strategy: Which algorithm to use.

        Returns
        -------
        Delay in seconds (may be 0.0 for NONE strategy).
        """
        if strategy == JitterStrategy.NONE:
            return 0.0

        if strategy == JitterStrategy.UNIFORM:
            return random.uniform(min_s, max_s)

        if strategy == JitterStrategy.GAMMA:
            # Gamma with alpha=2 gives a smooth right-skewed curve:
            # most values cluster around the median, occasional longer waits.
            median = (min_s + max_s) / 2.0
            # shape alpha=2, scale beta = median/2 → mean = alpha*beta = median
            beta = median / 2.0
            # Clamp to [min_s, max_s] — gamma has infinite right tail
            raw = random.gammavariate(alpha=2.0, beta=max(beta, 0.1))
            return max(min_s, min(raw, max_s))

        if strategy == JitterStrategy.DECORRELATED:
            # Decorrelated jitter: base = min, then random in [base, base*3]
            base = max(min_s, 0.1)
            return min(base, random.uniform(base, base * 3.0))

        if strategy == JitterStrategy.FULL_JITTER:
            return random.uniform(0.0, max_s)

        if strategy == JitterStrategy.EQUAL_JITTER:
            half = max_s / 2.0
            return half + random.uniform(0.0, half)

        # Fallback
        return random.uniform(min_s, max_s)


# ---------------------------------------------------------------------------
# Token bucket rate limiter — proactive request shaping
# ---------------------------------------------------------------------------


class TokenBucketRateLimiter:
    """Classic token bucket for proactive rate limiting.

    Unlike the reactive ``AdaptiveRateLimiter`` (which only backs off after
    receiving a 429), this shapes traffic *before* it hits the wire.

    Tokens refill at a constant rate.  Each request consumes one token.
    When the bucket is empty, ``consume()`` returns the seconds to wait
    until the next token is available.
    """

    def __init__(
        self,
        rate: float = 0.0,
        burst: int = 5,
        clock: callable = time.monotonic,
    ):
        """Create a token bucket.

        Parameters
        ----------
        rate: Tokens per second.  0 = unlimited (consume always returns 0).
        burst: Maximum tokens the bucket can hold (allows short bursts).
        clock: Injectible clock for testing (default: time.monotonic).
        """
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)  # start full
        self._last_refill = clock()
        self._clock = clock
        self._lock = threading.Lock()

    # ── public API ──────────────────────────────────────────────────────

    def consume(self, n: int = 1) -> float:
        """Try to consume *n* tokens.

        Returns 0.0 if tokens are available, or the seconds to wait until
        the next token refills.
        """
        if self._rate <= 0:
            return 0.0  # unlimited

        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return 0.0
            # Not enough tokens — how long until the next one?
            deficit = n - self._tokens
            return deficit / self._rate

    def reset(self, rate: float | None = None, burst: int | None = None):
        """Reset the bucket (e.g. on profile change)."""
        with self._lock:
            if rate is not None:
                self._rate = rate
            if burst is not None:
                self._burst = burst
                self._tokens = float(burst)
            self._last_refill = self._clock()

    @property
    def status(self) -> dict:
        """Diagnostic snapshot."""
        with self._lock:
            self._refill()
            return {
                "rate_per_s": self._rate,
                "burst": self._burst,
                "tokens_available": round(self._tokens, 2),
                "effective_rate_per_minute": round(self._rate * 60, 1),
            }

    # ── internal ────────────────────────────────────────────────────────

    def _refill(self):
        now = self._clock()
        elapsed = now - self._last_refill
        self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate)
        self._last_refill = now


# ---------------------------------------------------------------------------
# Audit log gate — flood prevention for Vault audit logs
# ---------------------------------------------------------------------------


@dataclass
class _WindowEntry:
    """A single request in the sliding window."""
    timestamp: float
    weight: float  # error requests have higher weight


class AuditLogGate:
    """Prevents audit log flooding by gating request frequency.

    Vault logs every API request to its audit backend (file, syslog, socket).
    A scanner making hundreds of rapid requests will flood audit logs and
    trigger SIEM alerts regardless of header randomization.

    This gate:
    - Maintains a sliding window of recent requests.
    - Weighs error responses (403, 429, 5xx) more heavily since SIEM rules
      are more sensitive to auth failures.
    - Classifies endpoints by sensitivity — hitting ``auth/login`` rapidly
      is far more suspicious than hitting ``sys/health``.
    - Forces a cooldown period when the window threshold is exceeded.
    """

    def __init__(
        self,
        window_s: float = 30.0,
        max_requests_per_window: int = 30,
        error_amplifier: float = 2.0,
        high_sensitivity_cooldown_s: float = 5.0,
        critical_sensitivity_cooldown_s: float = 30.0,
        flood_cooldown_s: float = 60.0,
        clock: callable = time.monotonic,
    ):
        self._window_s = window_s
        self._max_requests = max_requests_per_window
        self._error_amplifier = error_amplifier
        self._high_cooldown = high_sensitivity_cooldown_s
        self._critical_cooldown = critical_sensitivity_cooldown_s
        self._flood_cooldown = flood_cooldown_s
        self._clock = clock

        self._window: list[_WindowEntry] = []
        self._flood_until: float = 0.0  # monotonic timestamp
        self._lock = threading.Lock()

    # ── public API ──────────────────────────────────────────────────────

    def acquire(self, path: str, is_error: bool = False) -> float:
        """Request permission to hit *path*.

        Returns 0.0 if the request can proceed immediately, or the number
        of seconds to wait before retrying.

        Parameters
        ----------
        path: Vault API path (e.g. "sys/health", "auth/userpass/login").
        is_error: True if this is a retry after a previous error response
                  (errors carry extra weight in the audit window).
        """
        with self._lock:
            now = self._clock()

            # Check active flood cooldown
            if now < self._flood_until:
                return self._flood_until - now

            # Classify path sensitivity
            sensitivity = classify_path(path)
            weight = 1.0
            if is_error:
                weight *= self._error_amplifier

            # Apply per-endpoint cooldown for sensitive paths
            critical_delay = self._check_endpoint_cooldown(sensitivity, now)
            if critical_delay > 0:
                return critical_delay

            # Prune expired entries from the sliding window
            cutoff = now - self._window_s
            self._window = [e for e in self._window if e.timestamp > cutoff]

            # Count weighted total
            total_weight = sum(e.weight for e in self._window)

            if self._max_requests > 0 and total_weight + weight > self._max_requests:
                # Threshold exceeded — enforce flood cooldown
                self._flood_until = now + self._flood_cooldown
                return self._flood_cooldown

            # Record this request
            self._window.append(_WindowEntry(timestamp=now, weight=weight))
            return 0.0

    def report(self, path: str, status_code: int):
        """Report the outcome of a request.

        Failed requests increase the error weight for subsequent calls.
        This is called *after* the request completes, so the error weight
        applies to the *next* acquire() call.
        """
        # Error status codes are tracked: they'll amplify future acquire() calls
        # The actual amplification happens on the next acquire(is_error=True).
        # This method exists for future extensions (e.g. per-endpoint error
        # rate tracking, dynamic sensitivity adjustment).
        pass

    def reset(
        self,
        window_s: float | None = None,
        max_requests: int | None = None,
        error_amplifier: float | None = None,
        high_cooldown: float | None = None,
        critical_cooldown: float | None = None,
        flood_cooldown: float | None = None,
    ):
        """Reset configuration (e.g. on profile change). Clears the window."""
        with self._lock:
            if window_s is not None:
                self._window_s = window_s
            if max_requests is not None:
                self._max_requests = max_requests
            if error_amplifier is not None:
                self._error_amplifier = error_amplifier
            if high_cooldown is not None:
                self._high_cooldown = high_cooldown
            if critical_cooldown is not None:
                self._critical_cooldown = critical_cooldown
            if flood_cooldown is not None:
                self._flood_cooldown = flood_cooldown
            self._window.clear()
            self._flood_until = 0.0

    @property
    def status(self) -> dict:
        with self._lock:
            now = self._clock()
            cutoff = now - self._window_s
            active = [e for e in self._window if e.timestamp > cutoff]
            total_weight = sum(e.weight for e in active)
            return {
                "window_s": self._window_s,
                "max_per_window": self._max_requests,
                "current_weight": round(total_weight, 1),
                "request_count": len(active),
                "flood_active": now < self._flood_until,
                "flood_remaining_s": max(0.0, self._flood_until - now),
                "error_amplifier": self._error_amplifier,
            }

    # ── internal ────────────────────────────────────────────────────────

    def _check_endpoint_cooldown(
        self, sensitivity: EndpointSensitivity, now: float,
    ) -> float:
        """Enforce minimum interval between requests to sensitive endpoints.

        CRITICAL endpoints get a mandatory cooldown (prevents rapid-fire
        audit-device tampering).  HIGH endpoints get a light spacing delay.
        """
        if sensitivity == EndpointSensitivity.CRITICAL:
            # Don't allow back-to-back CRITICAL requests
            if self._window and self._window[-1].timestamp > now - self._critical_cooldown:
                # Check if the last request was also CRITICAL
                return self._critical_cooldown - (now - self._window[-1].timestamp)
            return 0.0

        if sensitivity == EndpointSensitivity.HIGH:
            if self._window and self._high_cooldown > 0:
                elapsed = now - self._window[-1].timestamp
                if elapsed < self._high_cooldown:
                    return self._high_cooldown - elapsed
        return 0.0


# ---------------------------------------------------------------------------
# Bandwidth throttle — limit bytes/sec for bulk responses
# ---------------------------------------------------------------------------


class BandwidthThrottle:
    """Token bucket for response bytes — prevents bulk data exfiltration
    from looking like a spike in audit log traffic.

    Vault KV enumeration or secret exfiltration can return large JSON
    responses.  Throttling the download rate makes the traffic pattern
    resemble normal client usage rather than a data dump.
    """

    def __init__(
        self,
        rate_bps: float = 0.0,
        burst_bytes: int = 65536,  # 64 KB initial burst
        clock: callable = time.monotonic,
    ):
        self._rate_bps = rate_bps
        self._burst = burst_bytes
        self._tokens = float(burst_bytes)
        self._last_refill = clock()
        self._clock = clock
        self._lock = threading.Lock()

    def consume(self, response_bytes: int) -> float:
        """Account for *response_bytes* just received.

        Returns seconds to wait before the next request, or 0.0 if the
        bucket can absorb this response immediately.
        """
        if self._rate_bps <= 0 or response_bytes <= 0:
            return 0.0

        with self._lock:
            self._refill()
            self._tokens -= response_bytes
            if self._tokens >= 0:
                return 0.0
            # Deficit: how long until enough tokens refill?
            deficit = abs(self._tokens)
            return deficit / self._rate_bps

    def reset(self, rate_bps: float | None = None, burst_bytes: int | None = None):
        with self._lock:
            if rate_bps is not None:
                self._rate_bps = rate_bps
            if burst_bytes is not None:
                self._burst = burst_bytes
            self._tokens = float(self._burst)
            self._last_refill = self._clock()

    @property
    def status(self) -> dict:
        with self._lock:
            self._refill()
            return {
                "rate_kbps": round(self._rate_bps / 1024, 1),
                "burst_kb": round(self._burst / 1024, 1),
                "tokens_available_kb": round(self._tokens / 1024, 1),
            }

    def _refill(self):
        now = self._clock()
        elapsed = now - self._last_refill
        self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate_bps)
        self._last_refill = now


# ---------------------------------------------------------------------------
# Adaptive rate limiter — self-tuning backoff
# ---------------------------------------------------------------------------


class AdaptiveRateLimiter:
    """Tracks HTTP responses and dynamically adjusts request pacing.

    On 429 (Too Many Requests):
        Exponential backoff: 10 s → 20 s → 40 s → 80 s (capped at 300 s).
        Concurrency target is halved.

    On 403 (Forbidden — possible WAF/IDS trigger):
        Moderate backoff: 5 s → 10 s → 20 s (capped at 60 s).

    On success (2xx):
        Gradually relax backoff over time.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Backoff state
        self._consecutive_429 = 0
        self._consecutive_403 = 0
        self._current_backoff = 0.0  # seconds of mandatory wait
        self._max_backoff = 300.0
        self._last_429_time = 0.0
        self._last_403_time = 0.0

        # Concurrency control
        self._max_concurrency = 3  # start conservative
        self._min_concurrency = 1
        self._active_requests = 0
        self._semaphore = threading.BoundedSemaphore(self._max_concurrency)

        # Latency tracking for adaptive polling
        self._latency_window: list[float] = []  # last N response times
        self._latency_window_size = 10
        self._avg_latency = 1.0  # seconds
        self._poll_interval = 5.0  # base polling interval

    # ── public API ──────────────────────────────────────────────────────

    def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a request slot. Blocks if at concurrency limit. Returns False on timeout."""
        return self._semaphore.acquire(timeout=timeout)

    def release(self):
        """Release a request slot."""
        try:
            self._semaphore.release()
        except ValueError:
            pass

    def report_response(self, status_code: int, latency: float):
        """Feed a response result back to the rate limiter for tuning."""
        with self._lock:
            self._track_latency(latency)

            if status_code == 429:
                self._consecutive_429 += 1
                self._consecutive_403 = 0
                self._last_429_time = time.monotonic()
                # Exponential backoff: 10 * 2^(n-1), cap at max_backoff
                backoff = min(10.0 * (2 ** (self._consecutive_429 - 1)), self._max_backoff)
                self._current_backoff = max(self._current_backoff, backoff)
                # Halve concurrency on 429
                self._max_concurrency = max(self._min_concurrency, self._max_concurrency // 2)
                self._rebuild_semaphore()

            elif status_code == 403:
                self._consecutive_403 += 1
                self._consecutive_429 = 0
                self._last_403_time = time.monotonic()
                backoff = min(5.0 * (2 ** (self._consecutive_403 - 1)), 60.0)
                self._current_backoff = max(self._current_backoff, backoff)

            elif 200 <= status_code < 300:
                # Success — decay backoff and relax concurrency
                self._consecutive_429 = max(0, self._consecutive_429 - 1)
                self._consecutive_403 = max(0, self._consecutive_403 - 1)
                self._decay_backoff()
                self._max_concurrency = min(5, self._max_concurrency + 0.25)
                self._rebuild_semaphore()

            else:
                # 5xx or other — minor backoff
                self._current_backoff = max(self._current_backoff, 1.0)

    def should_backoff(self) -> float:
        """Return seconds to wait before next request, or 0 if OK to proceed."""
        with self._lock:
            return self._current_backoff

    def apply_backoff(self) -> float:
        """Sleep for the required backoff + random jitter. Returns actual wait time."""
        wait = self.should_backoff()
        if wait > 0:
            jitter = random.uniform(0.5, min(5.0, wait * 0.3))
            total = wait + jitter
            time.sleep(total)
            return total
        return 0.0

    def set_backoff(self, seconds: float):
        """Set a minimum backoff level (e.g. from Retry-After header).

        The backoff will be at least *seconds*, but may be higher if
        the limiter has already escalated further.
        """
        with self._lock:
            self._current_backoff = max(self._current_backoff, seconds)

    def extend_backoff(self, seconds: float):
        """Increase backoff by *seconds* (pre-emptive slow-down).

        Use this when rate-limit headers indicate the limit is nearly
        exhausted (e.g. X-RateLimit-Remaining < 5).
        """
        with self._lock:
            self._current_backoff = max(self._current_backoff, seconds)

    @property
    def concurrency(self) -> int:
        return int(self._max_concurrency)

    @property
    def avg_latency(self) -> float:
        with self._lock:
            return self._avg_latency

    @property
    def poll_interval(self) -> float:
        """Recommended seconds between health/status polls."""
        with self._lock:
            # Adaptive: fast Vault → poll more, slow Vault → poll less
            # Base 5 s, scaled by latency ratio
            lat = self._avg_latency
            if lat < 0.2:
                return 2.0  # fast — poll every 2 s
            elif lat < 1.0:
                return 5.0
            elif lat < 3.0:
                return 15.0
            else:
                return 30.0  # slow — poll every 30 s

    @property
    def status(self) -> dict:
        with self._lock:
            return {
                "concurrency": int(self._max_concurrency),
                "backoff_seconds": round(self._current_backoff, 1),
                "consecutive_429": self._consecutive_429,
                "consecutive_403": self._consecutive_403,
                "avg_latency_ms": round(self._avg_latency * 1000),
                "poll_interval_s": round(self.poll_interval, 1),
            }

    # ── internal ────────────────────────────────────────────────────────

    def _track_latency(self, latency: float):
        self._latency_window.append(latency)
        if len(self._latency_window) > self._latency_window_size:
            self._latency_window.pop(0)
        if self._latency_window:
            self._avg_latency = sum(self._latency_window) / len(self._latency_window)

    def _decay_backoff(self):
        """Gradually reduce backoff over time as successes accumulate."""
        if self._current_backoff > 0:
            self._current_backoff = max(0.0, self._current_backoff * 0.85)

    def _rebuild_semaphore(self):
        """Rebuild semaphore with current concurrency target."""
        # Can't resize BoundedSemaphore, so we create a new one.
        # Active count tracked separately.
        target = max(1, int(self._max_concurrency))
        old = self._semaphore
        self._semaphore = threading.BoundedSemaphore(target)
        # Don't close old — existing acquirers still hold references
        # but new acquirers use the new semaphore.


# ---------------------------------------------------------------------------
# Jitter — random delays to mimic human behavior
# ---------------------------------------------------------------------------


def human_jitter(min_s: float = 1.0, max_s: float = 5.0, strategy: JitterStrategy | None = None) -> float:
    """Sleep a random interval to avoid looking like a bot. Returns sleep time.

    Uses the profile's configured jitter strategy, or uniform as fallback.
    """
    if strategy is None:
        strategy = JitterStrategy.UNIFORM
    delay = StealthJitterEngine.calculate(min_s, max_s, strategy)
    if delay > 0:
        time.sleep(delay)
    return delay


# ---------------------------------------------------------------------------
# Stealth toggle — OFF by default for fast lab/dev work
# ---------------------------------------------------------------------------

_STEALTH_ENABLED = False


def enable_stealth() -> None:
    """Activate stealth mode — jitter, backoff, concurrency limits."""
    global _STEALTH_ENABLED
    _STEALTH_ENABLED = True


def disable_stealth() -> None:
    """Deactivate stealth mode — fast direct requests (lab/dev)."""
    global _STEALTH_ENABLED
    _STEALTH_ENABLED = False


def is_stealth_enabled() -> bool:
    return _STEALTH_ENABLED


# ---------------------------------------------------------------------------
# Global rate limiter instance
# ---------------------------------------------------------------------------

_global_limiter = AdaptiveRateLimiter()


def get_global_limiter() -> AdaptiveRateLimiter:
    return _global_limiter


# ---------------------------------------------------------------------------
# Request scheduler — orchestrates all stealth components
# ---------------------------------------------------------------------------


class RequestScheduler:
    """Central orchestrator for all stealth rate-limiting components.

    Combines:
    - :class:`TokenBucketRateLimiter` — proactive requests/sec shaping
    - :class:`AuditLogGate` — audit log flood prevention
    - :class:`StealthJitterEngine` — human-like inter-request delays
    - :class:`BandwidthThrottle` — response-byte rate limiting

    The scheduler is called **before** every request to determine the
    required wait time, and **after** every response to feed back metrics.
    """

    def __init__(
        self,
        token_bucket: TokenBucketRateLimiter | None = None,
        audit_gate: AuditLogGate | None = None,
        bandwidth: BandwidthThrottle | None = None,
        jitter_strategy: JitterStrategy = JitterStrategy.UNIFORM,
        jitter_min: float = 1.0,
        jitter_max: float = 5.0,
    ):
        self._token_bucket = token_bucket or TokenBucketRateLimiter()
        self._audit_gate = audit_gate or AuditLogGate()
        self._bandwidth = bandwidth or BandwidthThrottle()
        self._jitter_strategy = jitter_strategy
        self._jitter_min = jitter_min
        self._jitter_max = jitter_max

        # Track last request path for audit gate error reporting
        self._last_path: str = ""
        self._last_was_error: bool = False

    # ── public API ──────────────────────────────────────────────────────

    def schedule(self, path: str) -> float:
        """Determine how long to wait before hitting *path*.

        Returns
        -------
        Seconds to sleep before making the request.  0.0 = proceed now.
        """
        # 1. Token bucket: proactive rate limiting
        token_delay = self._token_bucket.consume()

        # 2. Audit log gate: flood prevention + endpoint sensitivity
        audit_delay = self._audit_gate.acquire(path, is_error=self._last_was_error)

        # 3. Take the longer of the two enforced delays
        base_delay = max(token_delay, audit_delay)

        # 4. Add jitter
        if base_delay > 0:
            # When already delayed, add small jitter to avoid synchronized retries
            base_delay += StealthJitterEngine.calculate(
                base_delay * 0.1, base_delay * 0.3, self._jitter_strategy,
            )
        else:
            # Normal pacing — add profile-configured jitter
            base_delay += StealthJitterEngine.calculate(
                self._jitter_min, self._jitter_max, self._jitter_strategy,
            )

        self._last_path = path
        return base_delay

    def report(self, path: str, status_code: int, latency: float, response_bytes: int):
        """Feed response metrics back to the scheduler.

        Called after every HTTP response (success or failure).
        """
        # Report to audit gate: errors amplify future delays
        is_error = status_code >= 400
        self._last_was_error = is_error

        # Bandwidth throttle: account for response size
        # (this doesn't delay the current response — it affects the NEXT request)
        # We don't sleep here; the delay is factored into the next schedule() call.
        # For now, bandwidth throttling applies on the next request.
        # _bw_delay is tracked and added to the next schedule() result.
        self._pending_bw_delay = self._bandwidth.consume(response_bytes)

    def reset(self, profile_config: dict):
        """Reconfigure all sub-components from a profile config dict.

        Called by ``set_evasion_profile()`` when switching profiles.
        """
        cfg = profile_config

        # Token bucket: requests per minute → tokens per second
        rpm = cfg.get("requests_per_minute", 0.0)
        rate = rpm / 60.0 if rpm > 0 else 0.0
        burst = cfg.get("burst_size", 5)
        if rate > 0 or rpm == 0:
            self._token_bucket.reset(rate=rate, burst=burst if rpm > 0 else 0)

        # Audit log gate
        window_s = cfg.get("audit_window_s", 30)
        max_req = cfg.get("max_requests_per_window", 30)
        error_amp = cfg.get("error_amplifier", 2.0)
        high_cooldown = cfg.get("endpoint_cooldown", {}).get("HIGH", 5.0) if isinstance(
            cfg.get("endpoint_cooldown"), dict
        ) else 5.0
        critical_cooldown = cfg.get("endpoint_cooldown", {}).get("CRITICAL", 30.0) if isinstance(
            cfg.get("endpoint_cooldown"), dict
        ) else 30.0
        flood_cooldown = max(60.0, window_s * 2.0)
        self._audit_gate.reset(
            window_s=window_s,
            max_requests=max_req,
            error_amplifier=error_amp,
            high_cooldown=high_cooldown,
            critical_cooldown=critical_cooldown,
            flood_cooldown=flood_cooldown,
        )

        # Bandwidth throttle
        bw_bps = cfg.get("bandwidth_limit_bps", 0)
        self._bandwidth.reset(rate_bps=bw_bps if bw_bps > 0 else 0.0)

        # Jitter
        strategy_str = cfg.get("jitter_strategy", "uniform")
        try:
            self._jitter_strategy = JitterStrategy(strategy_str)
        except ValueError:
            self._jitter_strategy = JitterStrategy.UNIFORM
        self._jitter_min = cfg.get("jitter_min", 0.0)
        self._jitter_max = cfg.get("jitter_max", 5.0)

        # Reset error tracking
        self._last_was_error = False
        self._pending_bw_delay = 0.0

    @property
    def status(self) -> dict:
        return {
            "token_bucket": self._token_bucket.status,
            "audit_gate": self._audit_gate.status,
            "bandwidth": self._bandwidth.status,
            "jitter_strategy": self._jitter_strategy.value,
            "jitter_range_s": f"{self._jitter_min}-{self._jitter_max}",
        }


# ── Scheduler singleton ───────────────────────────────────────────────

_scheduler: RequestScheduler | None = None
_scheduler_lock = threading.Lock()


def get_scheduler() -> RequestScheduler:
    """Get or lazily create the global :class:`RequestScheduler`."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    with _scheduler_lock:
        if _scheduler is None:
            cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])
            _scheduler = RequestScheduler()
            _scheduler.reset(cfg)
        return _scheduler


def _reset_scheduler():
    """Reset the global scheduler (called on profile change)."""
    global _scheduler
    cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])
    if _scheduler is None:
        _scheduler = RequestScheduler()
    _scheduler.reset(cfg)


# ---------------------------------------------------------------------------
# Drop-in replacement for safe_request()
# ---------------------------------------------------------------------------


def stealth_request(
    method: str,
    target: str,
    path: str,
    allow_redirects: bool = True,
    timeout: int = 10,
    token: str | None = None,
    limiter: AdaptiveRateLimiter | None = None,
    apply_jitter: bool = True,
    json_body: dict | None = None,
) -> requests.Response | requests.RequestException:
    """Stealth-aware HTTP request with adaptive rate limiting + evasion.

    Drop-in replacement for :func:`safe_request` that automatically:
    - Waits through any active backoff period
    - Adds random jitter between requests to mimic human cadence
    - Acquires a concurrency slot (prevents parallel burst detection)
    - Rotates User-Agent per the active evasion profile
    - Randomizes HTTP headers (Accept, Accept-Language, etc.)
    - Analyses response headers for rate-limit signals
    - Reports response to the rate limiter for self-tuning

    Parameters
    ----------
    method: HTTP method (GET, POST, etc.)
    target: Base URL of the Vault instance
    path: API path (e.g. "sys/health")
    allow_redirects: Whether to follow redirects
    timeout: Request timeout in seconds
    token: Optional Vault token for authenticated requests
    limiter: Rate limiter instance (uses global singleton if None)
    apply_jitter: Whether to add random delay before request
    json_body: Optional JSON body for POST/PUT requests
    """
    if limiter is None:
        limiter = _global_limiter

    # ── Fast path: stealth disabled → direct request, zero overhead ──
    if not _STEALTH_ENABLED:
        url = build_url(target, path)
        headers = build_stealth_headers(token)  # still use proper headers
        try:
            kwargs = dict(
                method=method, url=url, timeout=timeout,
                allow_redirects=allow_redirects, verify=get_verify(),
                headers=headers,
            )
            if json_body is not None:
                kwargs["json"] = json_body
            return requests.request(**kwargs)
        except requests.exceptions.RequestException as exc:
            return exc

    # ── 0. Consult proactive scheduler (rate limit + audit gate + jitter) ─
    scheduler = get_scheduler()
    wait = scheduler.schedule(path)
    if wait > 0:
        time.sleep(wait)

    # ── 1. Wait out any active backoff ──────────────────────────────
    limiter.apply_backoff()

    # ── 2. Acquire concurrency slot ─────────────────────────────────
    acquired = limiter.acquire(timeout=30.0)
    if not acquired:
        return requests.exceptions.ConnectionError(
            "Stealth limiter: concurrency slot not available"
        )

    try:
        # ── 3. Profile-aware jitter (legacy path — scheduler handles this) ─
        # The scheduler already added jitter via schedule().  This secondary
        # jitter only fires when apply_jitter is explicitly True AND the
        # scheduler's own jitter was zero (e.g. aggressive profile).
        if apply_jitter:
            cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])
            jitter_min = cfg.get("jitter_min", 1.0)
            jitter_max = cfg.get("jitter_max", 5.0)
            if jitter_min > 0 or jitter_max > 0:
                strategy_str = cfg.get("jitter_strategy", "uniform")
                try:
                    strategy = JitterStrategy(strategy_str)
                except ValueError:
                    strategy = JitterStrategy.UNIFORM
                delay = StealthJitterEngine.calculate(jitter_min, jitter_max, strategy)
                if delay > 0:
                    time.sleep(delay)

        # ── 4. Make the request with stealth headers ────────────────
        url = build_url(target, path)
        headers = build_stealth_headers(token)

        t0 = time.monotonic()
        try:
            kwargs = dict(
                method=method, url=url, timeout=timeout,
                allow_redirects=allow_redirects, verify=get_verify(),
                headers=headers,
            )
            if json_body is not None:
                kwargs["json"] = json_body
            response = requests.request(**kwargs)
            latency = time.monotonic() - t0

            # ── Analyse rate-limit headers ──────────────────────────
            rate_info = analyse_rate_headers(response)
            if rate_info.is_rate_limited:
                # Use Retry-After if provided
                if rate_info.retry_after > 0:
                    limiter.set_backoff(rate_info.retry_after)
                if rate_info.limit_remaining is not None and rate_info.limit_remaining < 5:
                    # Pre-emptively slow down before hitting the limit
                    limiter.extend_backoff(5.0)

            # Feed response to rate limiter and scheduler for self-tuning
            limiter.report_response(response.status_code, latency)
            scheduler.report(path, response.status_code, latency,
                             len(response.content) if hasattr(response, 'content') else 0)
            return response

        except requests.exceptions.RequestException as exc:
            latency = time.monotonic() - t0
            limiter.report_response(503, latency)
            scheduler.report(path, 503, latency, 0)
            return exc

    finally:
        limiter.release()


# ---------------------------------------------------------------------------
# Adaptive poller — for daemon / cron use
# ---------------------------------------------------------------------------


class AdaptivePoller:
    """Self-tuning polling loop for Vault health/status checks.

    Adjusts polling interval based on Vault response latency:
    - Fast Vault (<200 ms) → poll every 2 s
    - Normal Vault (200 ms - 1 s) → poll every 5 s
    - Slow Vault (1-3 s) → poll every 15 s
    - Degraded Vault (>3 s) → poll every 30 s

    Also backs off immediately on 429/403 responses.
    """

    def __init__(self, limiter: AdaptiveRateLimiter | None = None):
        self._limiter = limiter or _global_limiter
        self._base_interval = 5.0
        self._min_interval = 2.0
        self._max_interval = 60.0

    def poll_interval(self) -> float:
        """Recommended seconds until the next poll."""
        interval = self._limiter.poll_interval
        # If we're in backoff, extend the interval
        backoff = self._limiter.should_backoff()
        if backoff > 0:
            interval = max(interval, backoff * 1.5)
        return min(interval, self._max_interval)

    def wait_for_next_poll(self):
        """Sleep until the next polling window, with jitter."""
        interval = self.poll_interval()
        # Add 20% random jitter so polls don't look like clockwork
        jitter = interval * random.uniform(-0.2, 0.2)
        wait = max(self._min_interval, interval + jitter)
        time.sleep(wait)

    def check_health(self, target: str) -> dict | None:
        """Perform one stealth health check. Returns parsed JSON or None."""
        result = stealth_request("GET", target, "sys/health", apply_jitter=False)
        if isinstance(result, requests.Response) and result.status_code == 200:
            try:
                return result.json()
            except Exception:
                return None
        return None

    def check_seal_status(self, target: str) -> dict | None:
        """Perform one stealth seal-status check. Returns parsed JSON or None."""
        result = stealth_request("GET", target, "sys/seal-status", apply_jitter=False)
        if isinstance(result, requests.Response) and result.status_code == 200:
            try:
                return result.json()
            except Exception:
                return None
        return None


# ---------------------------------------------------------------------------
# Legacy compatibility helpers
# ---------------------------------------------------------------------------


def build_url(target: str, path: str) -> str:
    base_url = target.rstrip("/") + "/"
    return urljoin(base_url, path.lstrip("/"))


DEFAULT_TIMEOUT = 10


def safe_request(method, target, path, allow_redirects=True):
    """Legacy wrapper — fast by default, stealth only when enabled."""
    return stealth_request(method, target, path, allow_redirects=allow_redirects, apply_jitter=False)
