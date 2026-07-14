from requests import Response

from reconnaissance.http_utils import safe_request


class ReconContext:
    def __init__(self, target):
        self.target = target
        self._responses: dict = {}

    def request_once(self, method, path, allow_redirects=True):
        key = (method.upper(), path, allow_redirects)
        if key not in self._responses:
            resp = safe_request(method, self.target, path, allow_redirects=allow_redirects)
            # Only cache successful responses — errors may be transient or
            # caused by TLS settings that change between calls.
            if isinstance(resp, Response):
                self._responses[key] = resp
            return resp
        return self._responses[key]

    def fetch_health_once(self):
        return self.request_once("GET", "/v1/sys/health")


def fetch_health_once(target):
    return ReconContext(target).fetch_health_once()
