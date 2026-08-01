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
    PARANOID = "paranoid"    # Max stealth: 5-15s jitter, 1 concurrency, heavy UA rotation
    STEALTH = "stealth"      # High stealth: 2-8s jitter, 2 concurrency
    BALANCED = "balanced"    # Moderate: 1-3s jitter, 3 concurrency
    AGGRESSIVE = "aggressive"  # Fast: 0-1s jitter, 5 concurrency (lab/dev)


# Profile settings
_PROFILE_CONFIG: dict[EvasionProfile, dict] = {
    EvasionProfile.PARANOID: {
        "jitter_min": 5.0, "jitter_max": 15.0,
        "max_concurrency": 1, "min_concurrency": 1,
        "ua_rotate_every": 1,  # rotate UA every request
        "header_randomize": True,
    },
    EvasionProfile.STEALTH: {
        "jitter_min": 2.0, "jitter_max": 8.0,
        "max_concurrency": 2, "min_concurrency": 1,
        "ua_rotate_every": 3,
        "header_randomize": True,
    },
    EvasionProfile.BALANCED: {
        "jitter_min": 1.0, "jitter_max": 3.0,
        "max_concurrency": 3, "min_concurrency": 1,
        "ua_rotate_every": 10,
        "header_randomize": False,
    },
    EvasionProfile.AGGRESSIVE: {
        "jitter_min": 0.0, "jitter_max": 1.0,
        "max_concurrency": 5, "min_concurrency": 2,
        "ua_rotate_every": 50,
        "header_randomize": False,
    },
}

_current_profile: EvasionProfile = EvasionProfile.BALANCED


def set_evasion_profile(profile: EvasionProfile):
    """Switch evasion profile globally."""
    global _current_profile
    _current_profile = profile
    # Update limiter concurrency
    cfg = _PROFILE_CONFIG[profile]
    limiter = get_global_limiter()
    with limiter._lock:
        limiter._max_concurrency = cfg["max_concurrency"]
        limiter._min_concurrency = cfg["min_concurrency"]
        limiter._rebuild_semaphore()


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


def human_jitter(min_s: float = 1.0, max_s: float = 5.0) -> float:
    """Sleep a random interval to avoid looking like a bot. Returns sleep time."""
    delay = random.uniform(min_s, max_s)
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

    # ── 1. Wait out any active backoff ──────────────────────────────
    limiter.apply_backoff()

    # ── 2. Acquire concurrency slot ─────────────────────────────────
    acquired = limiter.acquire(timeout=30.0)
    if not acquired:
        return requests.exceptions.ConnectionError(
            "Stealth limiter: concurrency slot not available"
        )

    try:
        # ── 3. Profile-aware jitter ─────────────────────────────────
        if apply_jitter:
            cfg = _PROFILE_CONFIG.get(_current_profile, _PROFILE_CONFIG[EvasionProfile.BALANCED])
            jitter_min = cfg.get("jitter_min", 1.0)
            jitter_max = cfg.get("jitter_max", 5.0)
            human_jitter(jitter_min, jitter_max)

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
                # Use Retry-After if provided, otherwise use limiter's backoff
                if rate_info.retry_after > 0:
                    with limiter._lock:
                        limiter._current_backoff = max(
                            limiter._current_backoff, rate_info.retry_after,
                        )
                if rate_info.limit_remaining is not None and rate_info.limit_remaining < 5:
                    # Pre-emptively slow down before hitting the limit
                    with limiter._lock:
                        limiter._current_backoff = max(
                            limiter._current_backoff, 5.0,
                        )

            # Feed response to rate limiter for self-tuning
            limiter.report_response(response.status_code, latency)
            return response

        except requests.exceptions.RequestException as exc:
            latency = time.monotonic() - t0
            limiter.report_response(503, latency)
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
