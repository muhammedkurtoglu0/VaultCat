from reconnaissance.http_utils import safe_request


class ReconContext:
    def __init__(self, target):
        self.target = target
        self._responses = {}

    def request_once(self, method, path, allow_redirects=True):
        key = (method.upper(), path, allow_redirects)
        if key not in self._responses:
            self._responses[key] = safe_request(
                method,
                self.target,
                path,
                allow_redirects=allow_redirects,
            )
        return self._responses[key]

    def fetch_health_once(self):
        return self.request_once("GET", "/v1/sys/health")


def fetch_health_once(target):
    return ReconContext(target).fetch_health_once()
