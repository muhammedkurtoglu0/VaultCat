import json
from pathlib import Path

from core.risk_score import calculate_risk


findings = []
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS")
REPORT_MIN_SEVERITY = None
SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "PASS": 0,
}


def set_report_min_severity(severity):
    global REPORT_MIN_SEVERITY
    if not severity:
        REPORT_MIN_SEVERITY = None
        return

    normalized = severity.upper()
    if normalized not in SEVERITY_RANK:
        print(f"[!] Unknown severity filter ignored: {severity}")
        REPORT_MIN_SEVERITY = None
        return

    REPORT_MIN_SEVERITY = normalized


def add_finding(
    severity,
    title,
    description,
    recommendation=None,
    evidence=None,
    module=None,
    target=None
):
    finding = {
        "severity": severity,
        "title": title,
        "description": description
    }

    if evidence:
        finding["evidence"] = evidence
    if module:
        finding["module"] = module
    if target:
        finding["target"] = target

    duplicate_key = (
        finding.get("severity"),
        finding.get("title"),
        finding.get("module"),
        finding.get("target"),
        finding.get("evidence"),
    )
    for existing_finding in findings:
        existing_key = (
            existing_finding.get("severity"),
            existing_finding.get("title"),
            existing_finding.get("module"),
            existing_finding.get("target"),
            existing_finding.get("evidence"),
        )
        if existing_key == duplicate_key:
            return existing_finding

    findings.append(finding)
    return finding


def print_report():
    print("\n===============================")
    print("Vault Pentest Findings Report")
    print("===============================")

    visible_findings = _visible_findings()

    if not visible_findings:
        print("[PASS] No major findings detected.")
        print_risk_summary()
        return

    for finding in visible_findings:
        print(f"\n[{finding['severity']}] {finding['title']}")
        print(f"Description: {finding['description']}")
        if finding.get("evidence"):
            print(f"Evidence: {finding['evidence']}")
        if finding.get("module"):
            print(f"Module: {finding['module']}")
        if finding.get("target"):
            print(f"Target: {finding['target']}")

    print_risk_summary()
    print_overall_risk()


def get_risk_summary():
    summary = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in _visible_findings():
        severity = finding.get("severity", "INFO")
        if severity not in summary:
            summary[severity] = 0
        summary[severity] += 1

    summary["total"] = len(_visible_findings())
    return summary


def print_risk_summary():
    summary = get_risk_summary()

    print("\nRisk Summary")
    print("------------")
    for severity in SEVERITY_ORDER:
        print(f"{severity:<8} : {summary.get(severity, 0)}")
    print(f"\nTotal Findings: {summary['total']}")


def print_overall_risk():
    risk = calculate_risk(_visible_findings())

    print("\nOverall Risk")
    print("------------")
    print(f"Risk Score : {risk['score']} / 100")
    print(f"Grade      : {risk['grade']}")


def export_json_report(output_path, target=None):
    report_path = _resolve_report_path(output_path)
    report_data = {
        "tool": "vault-pentest-tool",
        "target": target,
        "summary": get_risk_summary(),
        "risk": calculate_risk(_visible_findings()),
        "findings": _visible_findings(),
    }

    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8") as report_file:
            json.dump(report_data, report_file, indent=2, ensure_ascii=False)
        print(f"\n[+] JSON report written: {report_path}")
        return report_path
    except OSError as error:
        print(f"\n[!] Could not write JSON report: {error}")
        return None


def export_markdown_report(output_path, target=None):
    report_path = _resolve_report_path(output_path)
    summary = get_risk_summary()
    risk = calculate_risk(_visible_findings())

    lines = [
        "# Vault Pentest Tool Report",
        "",
        f"Target: `{target}`",
        "",
        "## Overall Risk",
        "",
        f"- Risk Score: `{risk['score']} / 100`",
        f"- Grade: `{risk['grade']}`",
        "",
        "## Risk Summary",
        "",
    ]

    for severity in SEVERITY_ORDER:
        lines.append(f"- {severity}: {summary.get(severity, 0)}")
    lines.append(f"- Total Findings: {summary['total']}")
    lines.extend(["", "## Findings", ""])

    visible_findings = _visible_findings()
    if not visible_findings:
        lines.append("No findings were recorded.")
    else:
        for index, finding in enumerate(visible_findings, start=1):
            lines.extend([
                f"### {index}. [{finding.get('severity')}] {finding.get('title')}",
                "",
                f"- Module: `{finding.get('module', '')}`",
                f"- Target: `{finding.get('target', '')}`",
                f"- Description: {finding.get('description', '')}",
                f"- Evidence: `{finding.get('evidence', '')}`",
                "",
            ])

    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"\n[+] Markdown report written: {report_path}")
        return report_path
    except OSError as error:
        print(f"\n[!] Could not write Markdown report: {error}")
        return None


def _resolve_report_path(output_path):
    report_path = Path(output_path)

    if report_path.parent == Path("."):
        return Path("reports") / report_path

    return report_path


def _visible_findings():
    if not REPORT_MIN_SEVERITY:
        return findings

    min_rank = SEVERITY_RANK[REPORT_MIN_SEVERITY]
    return [
        finding for finding in findings
        if SEVERITY_RANK.get(finding.get("severity", "INFO"), 1) >= min_rank
    ]
