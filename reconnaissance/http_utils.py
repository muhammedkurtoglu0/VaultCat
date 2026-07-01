from urllib.parse import urljoin

import requests


DEFAULT_TIMEOUT = 5


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
            allow_redirects=allow_redirects
        )
    except requests.exceptions.RequestException as error:
        return error

