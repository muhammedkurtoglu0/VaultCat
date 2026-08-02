"""Global TLS verification toggle for the entire tool.

Call ``set_insecure_mode()`` once at startup (e.g. from --skip-tls-verify)
and every Vault-targeted HTTP call will skip certificate validation.
"""

from __future__ import annotations

import warnings

_verify: bool = True


def set_insecure_mode():
    """Disable TLS certificate verification globally.

    Suppresses InsecureRequestWarning so the console stays clean.
    """
    global _verify
    _verify = False

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    # Also suppress Python's own SSL warnings
    warnings.filterwarnings("ignore", message="unverified HTTPS request")


def get_verify() -> bool:
    """Return the current TLS verification setting."""
    return _verify


def vault_request(method: str, url: str, **kwargs):
    """Wrapper around requests.request with TLS + 429 retry.

    Use this everywhere the tool talks to a Vault instance (or any
    internal host with self-signed certs).

    Automatically retries on 429 (rate limit) with exponential backoff:
    1s → 2s → 4s (max 3 retries).  Does NOT retry on 403, 5xx, or
    connection errors — those are handled by the caller.
    """
    import time as _time
    import requests as _requests

    kwargs.setdefault("verify", _verify)
    kwargs.setdefault("timeout", 10)

    max_retries = 3
    for attempt in range(max_retries + 1):
        resp = _requests.request(method, url, **kwargs)
        if resp.status_code != 429 or attempt >= max_retries:
            return resp
        delay = 1.0 * (2 ** attempt)  # 1s, 2s, 4s
        _time.sleep(delay)
    return resp
