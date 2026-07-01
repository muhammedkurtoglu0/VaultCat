SEVERITY_SCORES = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 1,
    "PASS": 0,
}


def calculate_risk(findings):
    counts = {severity: 0 for severity in SEVERITY_SCORES}

    for finding in findings:
        severity = finding.get("severity", "INFO")
        counts[severity] = counts.get(severity, 0) + 1

    raw_score = (
        counts.get("CRITICAL", 0) * SEVERITY_SCORES["CRITICAL"]
        + counts.get("HIGH", 0) * SEVERITY_SCORES["HIGH"]
        + min(counts.get("MEDIUM", 0) * SEVERITY_SCORES["MEDIUM"], 50)
        + min(counts.get("LOW", 0) * SEVERITY_SCORES["LOW"], 30)
        + min(counts.get("INFO", 0) * SEVERITY_SCORES["INFO"], 10)
    )

    score = min(raw_score, 100)

    return {
        "score": score,
        "grade": _grade_for_score(score),
    }


def _grade_for_score(score):
    if score <= 10:
        return "A"
    if score <= 30:
        return "B"
    if score <= 60:
        return "C"
    if score <= 85:
        return "D"
    return "F"
