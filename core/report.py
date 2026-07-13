import json
from pathlib import Path

from core.risk_score import calculate_risk


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS")
SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "PASS": 0,
}


class Report:
    """Encapsulates findings list and severity filter for a single assessment run.

    Each CLI invocation or MCP tool call should operate against a clean Report
    instance (or call :meth:`clear` on the shared default).  The module-level
    ``findings`` list and ``add_finding`` / ``print_report`` / … functions are
    retained for backward compatibility and delegate to the module-level
    ``_default_report`` singleton.
    """

    def __init__(self):
        self.findings: list[dict] = []
        self._min_severity: str | None = None

    # ── severity filter ────────────────────────────────────────────────

    def set_min_severity(self, severity: str | None):
        if not severity:
            self._min_severity = None
            return

        normalized = severity.upper()
        if normalized not in SEVERITY_RANK:
            print(f"[!] Unknown severity filter ignored: {severity}")
            self._min_severity = None
            return

        self._min_severity = normalized

    # ── findings ───────────────────────────────────────────────────────

    def add_finding(
        self,
        severity: str,
        title: str,
        description: str,
        recommendation=None,
        evidence=None,
        module=None,
        target=None,
    ) -> dict:
        finding: dict[str, str] = {
            "severity": severity,
            "title": title,
            "description": description,
        }

        if evidence:
            finding["evidence"] = evidence
        if module:
            finding["module"] = module
        if target:
            finding["target"] = target

        # deduplicate on (severity, title, module, target, evidence)
        duplicate_key = (
            finding.get("severity"),
            finding.get("title"),
            finding.get("module"),
            finding.get("target"),
            finding.get("evidence"),
        )
        for existing in self.findings:
            existing_key = (
                existing.get("severity"),
                existing.get("title"),
                existing.get("module"),
                existing.get("target"),
                existing.get("evidence"),
            )
            if existing_key == duplicate_key:
                return existing

        self.findings.append(finding)
        return finding

    def clear(self):
        """Reset findings and severity filter for a fresh assessment run."""
        self.findings.clear()
        self._min_severity = None

    # ── visible findings ───────────────────────────────────────────────

    def _visible_findings(self) -> list[dict]:
        if not self._min_severity:
            return self.findings

        min_rank = SEVERITY_RANK[self._min_severity]
        return [
            f for f in self.findings
            if SEVERITY_RANK.get(f.get("severity", "INFO"), 1) >= min_rank
        ]

    # ── reporting ──────────────────────────────────────────────────────

    def print_report(self):
        print("\n===============================")
        print("Vault Pentest Findings Report")
        print("===============================")

        visible = self._visible_findings()

        if not visible:
            print("[PASS] No major findings detected.")
            self.print_risk_summary()
            return

        for finding in visible:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"Description: {finding['description']}")
            if finding.get("evidence"):
                print(f"Evidence: {finding['evidence']}")
            if finding.get("module"):
                print(f"Module: {finding['module']}")
            if finding.get("target"):
                print(f"Target: {finding['target']}")

        self.print_risk_summary()
        self.print_overall_risk()

    def get_risk_summary(self) -> dict:
        summary: dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self._visible_findings():
            severity = finding.get("severity", "INFO")
            if severity not in summary:
                summary[severity] = 0
            summary[severity] += 1
        summary["total"] = len(self._visible_findings())
        return summary

    def print_risk_summary(self):
        summary = self.get_risk_summary()
        print("\nRisk Summary")
        print("------------")
        for severity in SEVERITY_ORDER:
            print(f"{severity:<8} : {summary.get(severity, 0)}")
        print(f"\nTotal Findings: {summary['total']}")

    def print_overall_risk(self):
        risk = calculate_risk(self._visible_findings())
        print("\nOverall Risk")
        print("------------")
        print(f"Risk Score : {risk['score']} / 100")
        print(f"Grade      : {risk['grade']}")

    def export_json_report(self, output_path: str, target=None):
        report_path = _resolve_report_path(output_path)
        report_data = {
            "tool": "vault-pentest-tool",
            "target": target,
            "summary": self.get_risk_summary(),
            "risk": calculate_risk(self._visible_findings()),
            "findings": self._visible_findings(),
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

    def export_markdown_report(self, output_path: str, target=None):
        report_path = _resolve_report_path(output_path)
        summary = self.get_risk_summary()
        risk = calculate_risk(self._visible_findings())

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

        visible = self._visible_findings()
        if not visible:
            lines.append("No findings were recorded.")
        else:
            for index, finding in enumerate(visible, start=1):
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


# ── module-level singleton (backward-compatible) ─────────────────────────────

_default_report = Report()

# Expose the findings list for consumers that need direct access (tests, MCP).
findings = _default_report.findings


def set_report_min_severity(severity: str | None):
    _default_report.set_min_severity(severity)


def add_finding(
    severity: str,
    title: str,
    description: str,
    recommendation=None,
    evidence=None,
    module=None,
    target=None,
) -> dict:
    return _default_report.add_finding(
        severity, title, description,
        recommendation=recommendation,
        evidence=evidence,
        module=module,
        target=target,
    )


def clear_findings():
    """Discard all accumulated findings and reset the severity filter.

    Call this at the start of each CLI invocation and at the beginning of
    every MCP tool call that runs scanners, so that long-lived processes
    (FastMCP server, interactive chat) do not leak findings between sessions.
    """
    _default_report.clear()


def get_default_report() -> Report:
    """Return the module-level shared :class:`Report` instance."""
    return _default_report


def print_report():
    _default_report.print_report()


def get_risk_summary() -> dict:
    return _default_report.get_risk_summary()


def print_risk_summary():
    _default_report.print_risk_summary()


def print_overall_risk():
    _default_report.print_overall_risk()


def export_json_report(output_path: str, target=None):
    return _default_report.export_json_report(output_path, target=target)


def export_markdown_report(output_path: str, target=None):
    return _default_report.export_markdown_report(output_path, target=target)


# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_report_path(output_path: str) -> Path:
    report_path = Path(output_path)
    if report_path.parent == Path("."):
        return Path("reports") / report_path
    return report_path
