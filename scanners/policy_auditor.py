from core.report import add_finding
from core.tls_config import get_verify
from scanners.policy_scanner import analyze_hcl_policy
from core.logger import logger


MODULE = "policy_auditor"
TIMEOUT = 5


def scan_policy_audit(vault_addr, token, namespace=None, timeout=TIMEOUT):
    """Enumerate every ACL policy the token can read and analyze each one.

    Lists /v1/sys/policies/acl, reads each policy definition, and runs the
    shared HCL analyzer (policy_scanner.analyze_hcl_policy) against it. Does
    not modify any Vault state.

    When the token lacks the ``list`` capability on the parent path it falls
    back to individual reads using candidate names derived from the token's
    own policies and well-known built-in names (default, root).
    """
    logger.info("\n[+] Auditing readable Vault ACL policies (sys/policies/acl)...")

    if not vault_addr or not token:
        add_finding(
            "INFO",
            "Policy audit skipped",
            "Policy audit requires both a Vault address and a token.",
            recommendation="Provide an authorized Vault address and token.",
            evidence="missing target or token",
            module=MODULE,
            target=vault_addr or "policy-audit",
        )
        return None

    try:
        import hvac
    except ImportError:
        add_finding(
            "LOW",
            "Policy audit dependency missing",
            "The hvac Python package is required to enumerate Vault ACL policies.",
            recommendation="Install project dependencies with pip install -r requirements.txt.",
            evidence="missing package: hvac",
            module=MODULE,
            target=vault_addr,
        )
        return None

    try:
        client = hvac.Client(
            url=vault_addr.rstrip("/"),
            token=token,
            namespace=namespace,
            timeout=timeout,
            verify=get_verify(),
        )
        policy_names = _list_acl_policies(client)
        listing_worked = True
    except Exception:
        listing_worked = False
        policy_names = []

    # ── Fallback: when LIST fails, collect candidate names from the token
    #    itself and a small set of well-known built-in policies, then try
    #    reading each one individually.  Many tokens have "read" on
    #    sys/policies/acl/* even when they lack "list" on the parent path.
    fallback_used = False
    if not listing_worked:
        candidates = _build_fallback_candidates(client)
        policy_names = []
        for name in candidates:
            policy_text = _read_acl_policy(client, name)
            if policy_text is not None:
                policy_names.append(name)
        if policy_names:
            fallback_used = True
        else:
            add_finding(
                "LOW",
                "Policy listing failed",
                "The token could not list ACL policies at sys/policies/acl "
                "and individual-policy fallback reads also returned nothing.",
                recommendation="Confirm the token has 'list' or 'read' on sys/policies/acl.",
                evidence="listing and fallback reads both failed",
                module=MODULE,
                target=vault_addr,
            )
            return None

    if not policy_names:
        add_finding(
            "INFO",
            "No readable ACL policies",
            "The token could not enumerate any ACL policies at sys/policies/acl.",
            recommendation="This usually means the token lacks 'list' on sys/policies/acl.",
            evidence="policies_listed: 0",
            module=MODULE,
            target=vault_addr,
        )
        return {"policies": [], "audited": [], "denied": []}

    audited = []
    denied = []

    for name in policy_names:
        policy_text = _read_acl_policy(client, name)
        if policy_text is None:
            denied.append(name)
            add_finding(
                "INFO",
                "ACL policy read denied",
                f"The token can see but not read the ACL policy: {name}",
                recommendation="Grant 'read' on the specific sys/policies/acl path if this policy is in scope.",
                evidence=f"policy: {name}",
                module=MODULE,
                target=vault_addr,
            )
            continue

        analyze_hcl_policy(policy_text, policy_name=name, target=vault_addr)
        audited.append(name)

    add_finding(
        "INFO",
        "ACL policy audit completed",
        "Enumerated and analyzed the ACL policies readable by the supplied token.",
        recommendation="Review each policy finding against least-privilege expectations.",
        evidence=(
            f"policies_listed: {len(policy_names)}, "
            f"analyzed: {len(audited)}, read_denied: {len(denied)}, "
            f"fallback_used: {fallback_used}"
        ),
        module=MODULE,
        target=vault_addr,
    )

    logger.info(f"[+] Policy audit completed: {len(audited)} analyzed, {len(denied)} denied"
          f"{' (fallback)' if fallback_used else ''}.")
    return {"policies": policy_names, "audited": audited, "denied": denied}


def _list_acl_policies(client):
    """Return the list of ACL policy names visible to the token."""
    try:
        response = client.sys.list_acl_policies()
    except (AttributeError, TypeError):
        response = client.adapter.get(url="/v1/sys/policies/acl?list=true")
        if hasattr(response, "json"):
            response = response.json()

    return _extract_policy_names(response)


def _read_acl_policy(client, name):
    """Return the raw HCL text of a policy, or None if it cannot be read."""
    try:
        response = client.sys.read_acl_policy(name)
    except (AttributeError, TypeError):
        response = client.adapter.get(url=f"/v1/sys/policies/acl/{name}")
        if hasattr(response, "json"):
            response = response.json()
    except Exception:
        return None

    return _extract_policy_text(response)


def _extract_policy_names(response):
    if not isinstance(response, dict):
        return []

    data = response.get("data") if isinstance(response.get("data"), dict) else response
    keys = data.get("keys") or data.get("policies") or []
    names = []
    for key in keys:
        name = str(key).strip()
        if name and name not in names:
            names.append(name)
    return names


def _extract_policy_text(response):
    if not isinstance(response, dict):
        return None

    data = response.get("data") if isinstance(response.get("data"), dict) else response
    policy_text = data.get("policy") or data.get("rules")
    if isinstance(policy_text, str):
        if policy_text.strip():
            return policy_text
        # Empty policy content = built-in special policy (root/default grants all)
        return "# Built-in policy — no explicit HCL rules (grants full access)"
    return None


def _build_fallback_candidates(client):
    """Build a list of policy names to try when LIST on sys/policies/acl fails.

    Derives names from the token's own metadata (lookup-self) and adds
    well-known built-in policies so the scanner can still read individual
    ACL policies when the token has ``read`` on ``sys/policies/acl/*`` but
    not ``list`` on the parent collection endpoint.
    """
    candidates = []

    # ── Token's own policies ──────────────────────────────────────────
    try:
        response = client.adapter.get(url="/v1/auth/token/lookup-self")
        if hasattr(response, "json"):
            response_data = response.json()
        else:
            response_data = response
        token_data = (
            response_data.get("data", {})
            if isinstance(response_data, dict)
            else {}
        )
        for policy_list_key in ("policies", "identity_policies"):
            for name in token_data.get(policy_list_key) or []:
                name = str(name).strip()
                if name and name not in candidates:
                    candidates.append(name)
    except Exception:
        pass

    # ── Well-known built-in policies ─────────────────────────────────
    for name in ("default", "root"):
        if name not in candidates:
            candidates.append(name)

    return candidates
