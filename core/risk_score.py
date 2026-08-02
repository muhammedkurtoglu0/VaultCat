"""Risk score calculation with sqrt-damping to prevent volume inflation.

Uses ``sqrt(N)`` instead of raw ``N`` so that 26 identical CRITICAL
findings don't produce a 100/100 score through quantity alone.  Each
additional finding of the same severity contributes progressively
less to the total.

Also detects the "token paradox" — when the user provides a root token
and the scanner reports "CRITICAL: token has sudo on *" — and flags
it as expected-credential context rather than a real finding.
"""

from __future__ import annotations

import math

SEVERITY_SCORES = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 1,
    "PASS": 0,
}

# Maximum contribution per severity tier (prevents single-severity spam)
_MAX_CONTRIBUTION: dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 20,
    "LOW": 10,
    "INFO": 5,
}


def _deduplicate_title_groups(findings: list[dict]) -> dict[str, int]:
    """Group findings by normalized title prefix and return effective counts.

    e.g. 3 findings titled "Token has sudo capability — secret/*",
    "Token has sudo capability — secret/data/*",
    "Token has sudo capability — kv/*"
    → grouped under "Token has sudo capability" → count 3 → sqrt(3) ≈ 1.7
    """
    from collections import Counter

    groups: Counter[str] = Counter()
    for f in findings:
        title = f.get("title", "")
        # Normalize: strip path suffix after " — " and common prefixes
        base = title.split(" — ")[0] if " — " in title else title
        # Merge near-identical titles
        if "sudo capability" in base:
            base = "sudo_capability"
        elif "write capability" in base:
            base = "write_capability"
        elif "root capability" in base:
            base = "root_capability"
        elif "over-privileged" in base.lower():
            base = "over_privileged"
        groups[base] += 1

    return dict(groups)


def _detect_token_paradox(findings: list[dict]) -> dict | None:
    """Return context info when findings suggest a root/admin token was used.

    The "token paradox": user gives the tool a high-privilege token, the tool
    reports "CRITICAL: token too powerful."  This is circular.  We surface
    this explicitly so the report reader understands the context.
    """
    root_paths = [f for f in findings
                  if f.get("title", "").startswith("Token has root capability")
                  and "*" in f.get("evidence", "")]
    sudo_wildcards = [f for f in findings
                      if "sudo" in f.get("title", "").lower()
                      and f.get("evidence", "").count("path: ") > 0]
    # If the token has root on * or sudo on many wildcards, it's likely admin
    if root_paths and len(root_paths) >= 1:
        return {
            "paradox": True,
            "note": (
                "The token used for this assessment appears to be a ROOT or "
                "full-admin token. Findings marked 'Token has root/sudo on *' "
                "are EXPECTED for this privilege level — they are not "
                "vulnerabilities. Real pentest value comes from assessing what "
                "a LOW-PRIVILEGE token could escalate to. Consider re-running "
                "with a restricted token to find actual privilege escalation paths."
            ),
        }
    return None


def calculate_risk(findings: list[dict]) -> dict:
    """Calculate a damped 0-100 risk score from a list of findings.

    Uses ``sqrt(effective_count) * severity_weight`` per severity tier
    so that 50 copies of the same finding don't produce 100/100.
    """
    counts = {sev: 0 for sev in SEVERITY_SCORES}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    # ── Effective counts: sqrt-damp to prevent volume inflation ────────
    groups = _deduplicate_title_groups(findings)

    # Per-severity effective count = sum of sqrt(group_size) for that severity
    eff_counts = {sev: 0.0 for sev in SEVERITY_SCORES}
    for f in findings:
        sev = f.get("severity", "INFO")
        title = f.get("title", "")
        base = title.split(" — ")[0] if " — " in title else title
        if "sudo capability" in base:
            base = "sudo_capability"
        elif "write capability" in base:
            base = "write_capability"
        elif "root capability" in base:
            base = "root_capability"
        elif "over-privileged" in base.lower():
            base = "over_privileged"

    # Distribute group contributions
    for base, group_size in groups.items():
        # Determine which severity tier this group belongs to
        group_sev = "INFO"
        for f in findings:
            t = f.get("title", "")
            b = t.split(" — ")[0] if " — " in t else t
            if "sudo capability" in b:
                b = "sudo_capability"
            elif "write capability" in b:
                b = "write_capability"
            elif "root capability" in b:
                b = "root_capability"
            elif "over-privileged" in b.lower():
                b = "over_privileged"
            if b == base:
                group_sev = f.get("severity", "INFO")
                break

        effective_count = math.sqrt(group_size)
        weight = SEVERITY_SCORES.get(group_sev, 1)
        max_contrib = _MAX_CONTRIBUTION.get(group_sev, 40)
        eff_counts[group_sev] += effective_count

    # Weighted sum, capped per severity
    raw_score = 0.0
    for sev, weight in SEVERITY_SCORES.items():
        effective = eff_counts.get(sev, 0.0)
        contrib = min(effective * weight, _MAX_CONTRIBUTION.get(sev, weight))
        raw_score += contrib

    # Normalize to 0-100 (max possible with sqrt damping is ~90)
    score = min(round(raw_score), 100)

    # ── Token paradox detection ────────────────────────────────────────
    paradox = _detect_token_paradox(findings)

    return {
        "score": score,
        "grade": _grade_for_score(score),
        "raw_counts": {
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        },
        "effective_groups": len(groups),
        "damping_applied": any(v > 1 for v in groups.values()),
        "token_paradox": paradox,
    }


def _grade_for_score(score: int) -> str:
    if score <= 10:
        return "A"
    if score <= 30:
        return "B"
    if score <= 50:
        return "C"
    if score <= 70:
        return "D"
    return "F"
