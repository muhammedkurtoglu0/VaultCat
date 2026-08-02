from typing import Optional
import os
import re
from core.tls_config import vault_request
from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel

class UnsealKeyExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="unseal_key.exfiltration",
            title="Unseal Key Exfiltration",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="seal",
            description="Finds Vault unseal keys from filesystem, environment, or memory",
            default_enabled=False,
        )

    def can_run(self, context):
        return bool(getattr(context, "vault_addr", None) and getattr(context, "token", None))

    def execute(self, context, params=None):
        results = {"unseal_keys": [], "sources": []}
        
        # 1. Environment'da ara
        for key, value in os.environ.items():
            if "unseal" in key.lower() or "vault_unseal" in key.lower():
                results["unseal_keys"].append({"source": "env", "key": key, "value": value[:8] + "..."})
                results["sources"].append("env")
        
        # 2. Dosya sisteminde ara (varsayılan path'ler)
        search_paths = [
            "/etc/vault/unseal",
            "/opt/vault/unseal",
            "/var/lib/vault/unseal",
            "./unseal",
            "./keys",
            "/tmp/vault-unseal",
        ]
        for path in search_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Base64 veya hex pattern'leri ara
                        matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
                        for m in matches:
                            results["unseal_keys"].append({"source": "file", "path": path, "value": m[:8] + "..."})
                except Exception as e:
                    from core.logger import logger
                    logger.warning(f"Unseal key file read failed: {path} — {e}")
                    pass
        
        # 3. Vault API ile sealed durumunu kontrol et
        try:
            url = f"{context.vault_addr}/v1/sys/seal-status"
            headers = {"X-Vault-Token": context.token}
            response = vault_request("GET", url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                results["sealed"] = data.get("sealed", False)
                results["progress"] = data.get("progress", 0)
                results["threshold"] = data.get("t", 0)
        except Exception as e:
            from core.logger import logger
            logger.warning(f"Vault seal-status request failed: {e}")
            pass

        if results["unseal_keys"]:
            context.add_finding(
                title="HIGH: Unseal Keys Discovered",
                description=f"Found {len(results['unseal_keys'])} potential unseal keys",
                severity="HIGH",
                evidence=results,
            )
            return ExecutionResult(status="success", message="Unseal keys found", evidence=results)
        else:
            return ExecutionResult(status="failed", message="No unseal keys found", evidence=results)