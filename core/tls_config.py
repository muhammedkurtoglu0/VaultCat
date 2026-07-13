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
    """Thin wrapper around requests.request that respects the global TLS setting.

    Use this everywhere the tool talks to a Vault instance (or any
    internal host with self-signed certs).
    """
    import requests
    kwargs.setdefault("verify", _verify)
    kwargs.setdefault("timeout", 10)
    return requests.request(method, url, **kwargs)
