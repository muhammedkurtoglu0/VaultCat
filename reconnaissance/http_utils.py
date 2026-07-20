"""HTTP utilities — stealth-aware request layer.

All functions delegate to :mod:`reconnaissance.stealth_http` which
provides adaptive rate limiting, random jitter, and latency-aware
polling to evade SOC detection.
"""

from urllib.parse import urljoin

import requests
from core.tls_config import get_verify, set_insecure_mode

# Re-export stealth primitives for direct use by scanners
from reconnaissance.stealth_http import (
    AdaptivePoller,
    AdaptiveRateLimiter,
    DEFAULT_TIMEOUT,
    build_url,
    enable_stealth,
    disable_stealth,
    is_stealth_enabled,
    get_global_limiter,
    human_jitter,
    safe_request,
    stealth_request,
)


def set_verify_tls(verify: bool):
    """Legacy wrapper — delegates to core.tls_config."""
    if not verify:
        set_insecure_mode()


def get_verify_tls() -> bool:
    return get_verify()
