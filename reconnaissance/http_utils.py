from urllib.parse import urljoin

import requests
from core.tls_config import get_verify, set_insecure_mode


DEFAULT_TIMEOUT = 5


def set_verify_tls(verify: bool):
    """Legacy wrapper — delegates to core.tls_config."""
    if not verify:
        set_insecure_mode()


def get_verify_tls() -> bool:
    return get_verify()


def build_url(target, path):
    base_url = target.rstrip("/") + "/"
    return urljoin(base_url, path.lstrip("/"))


def safe_request(method, target, path, allow_redirects=True):
    url = build_url(target, path)
    try:
        return requests.request(
            method,
            url,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=allow_redirects,
            verify=get_verify(),
        )
    except requests.exceptions.RequestException as error:
        return error

