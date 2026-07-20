"""Stealth-aware HTTP layer — evade SOC detection and rate limits.

Implements:
    - Adaptive backoff on 403/429 with exponential decay
    - Random jitter (1-5 s) between requests to mimic human cadence
    - Latency-adaptive polling intervals
    - Dynamic concurrency limiting when rate-limited
    - Request fingerprinting avoidance (no parallel bursts)
"""

from __future__ import annotations

import random
import threading
import time
from urllib.parse import urljoin

import requests
from core.tls_config import get_verify, set_insecure_mode


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
) -> requests.Response | requests.RequestException:
    """Stealth-aware HTTP request with adaptive rate limiting.

    Drop-in replacement for :func:`safe_request` that automatically:
    - Waits through any active backoff period
    - Adds random jitter between requests (1-5 s) to mimic human cadence
    - Acquires a concurrency slot (prevents parallel burst detection)
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
    """
    if limiter is None:
        limiter = _global_limiter

    # ── Fast path: stealth disabled → direct request, zero overhead ──
    if not _STEALTH_ENABLED:
        url = build_url(target, path)
        headers = {"X-Vault-Token": token} if token else None
        try:
            return requests.request(
                method, url, timeout=timeout, allow_redirects=allow_redirects,
                verify=get_verify(), headers=headers,
            )
        except requests.exceptions.RequestException as exc:
            return exc

    # ── 1. Wait out any active backoff ──────────────────────────────
    limiter.apply_backoff()

    # ── 2. Acquire concurrency slot ─────────────────────────────────
    acquired = limiter.acquire(timeout=30.0)
    if not acquired:
        # Too many requests queued — fail gracefully
        return requests.exceptions.ConnectionError(
            "Stealth limiter: concurrency slot not available"
        )

    try:
        # ── 3. Random jitter — mimic human cadence ──────────────────
        if apply_jitter:
            human_jitter(1.0, 5.0)

        # ── 4. Make the request ─────────────────────────────────────
        url = build_url(target, path)
        headers = {}
        if token:
            headers["X-Vault-Token"] = token

        t0 = time.monotonic()
        try:
            response = requests.request(
                method,
                url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=get_verify(),
                headers=headers if headers else None,
            )
            latency = time.monotonic() - t0

            # Feed response to rate limiter for self-tuning
            limiter.report_response(response.status_code, latency)
            return response

        except requests.exceptions.RequestException as exc:
            latency = time.monotonic() - t0
            # Treat connectivity errors as potential rate-limit triggers
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
