from core.report import add_finding


MODULE_NAME = "hijack_impact_analyzer"


def analyze_token_metadata(token_data, target, evidence_prefix):
    data = token_data.get("data", {})
    policies = data.get("policies") or []
    ttl = data.get("ttl")
    renewable = data.get("renewable")

    if "root" in policies:
        add_finding(
            "CRITICAL",
            "Validated token has root policy",
            "A validated Vault token includes the root policy.",
            recommendation="Immediately revoke or rotate the exposed token and investigate access logs.",
            evidence=f"{evidence_prefix}, policies: {policies}",
            module=MODULE_NAME,
            target=target,
        )

    if ttl == 0:
        add_finding(
            "HIGH",
            "Validated token appears non-expiring",
            "A validated Vault token reports ttl=0, which may indicate a long-lived token.",
            recommendation="Avoid long-lived exposed tokens and enforce appropriate TTLs.",
            evidence=f"{evidence_prefix}, ttl: {ttl}",
            module=MODULE_NAME,
            target=target,
        )
    elif isinstance(ttl, int) and ttl > 86400:
        add_finding(
            "MEDIUM",
            "Validated token has long TTL",
            "A validated Vault token has a TTL longer than 24 hours.",
            recommendation="Review token TTL and max TTL settings for least privilege.",
            evidence=f"{evidence_prefix}, ttl: {ttl}",
            module=MODULE_NAME,
            target=target,
        )

    if renewable:
        add_finding(
            "INFO",
            "Validated token is renewable",
            "A validated Vault token is renewable.",
            recommendation="Review renewal policy and ensure renewable tokens are tightly scoped.",
            evidence=f"{evidence_prefix}, renewable: {renewable}",
            module=MODULE_NAME,
            target=target,
        )

    if _has_broad_policy_hint(policies):
        add_finding(
            "MEDIUM",
            "Validated token has broad policy hint",
            "A validated token references a policy name that may indicate broad access.",
            recommendation="Review policy contents for wildcard paths, sudo, update, delete, and broad list capabilities.",
            evidence=f"{evidence_prefix}, policies: {policies}",
            module=MODULE_NAME,
            target=target,
        )


def _has_broad_policy_hint(policies):
    broad_terms = ("admin", "sudo", "superuser", "all", "wildcard")
    return any(
        any(term in str(policy).lower() for term in broad_terms)
        for policy in policies
    )

