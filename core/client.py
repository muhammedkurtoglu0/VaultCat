import requests
from core.tls_config import get_verify


class VaultClient:
    def __init__(self, vault_addr, token):
        self.vault_addr = vault_addr.rstrip("/")
        self.token = token

    def request(self, method, path):
        url = f"{self.vault_addr}/v1/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self.token}
        try:
            return requests.request(
                method, url, headers=headers, timeout=5, verify=get_verify(),
            )
        except requests.exceptions.RequestException as error:
            print(f"[!] Request error: {error}")
            return None