import json
import threading
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
        self._lock = threading.Lock()

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
        with self._lock:
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

    def get_findings_snapshot(self) -> list[dict]:
        """Return a thread-safe snapshot of current findings."""
        with self._lock:
            return list(self.findings)

    def clear(self):
        """Reset findings and severity filter for a fresh assessment run."""
        with self._lock:
            self.findings.clear()
            self._min_severity = None

    # ── visible findings ───────────────────────────────────────────────

    def _visible_findings(self) -> list[dict]:
        with self._lock:
            if not self._min_severity:
                return list(self.findings)

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
        print(f"Deduplicated groups: {risk.get('effective_groups', '?')}")
        if risk.get("damping_applied"):
            print("(sqrt-damping applied — duplicate findings deduplicated)")
        paradox = risk.get("token_paradox")
        if paradox and paradox.get("paradox"):
            print(f"\n⚠️  TOKEN PARADOX: {paradox['note'][:300]}")

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
                ])
                # Vault CLI fix commands
                try:
                    from core.fix_commands import get_fix_commands
                    for cmd in get_fix_commands(finding):
                        lines.append(f"  - Fix: `vault {cmd}`")
                except ImportError:
                    pass
                lines.extend([
                ])

        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text("\n".join(lines), encoding="utf-8")
            print(f"\n[+] Markdown report written: {report_path}")
            return report_path
        except OSError as error:
            print(f"\n[!] Could not write Markdown report: {error}")
            return None

    def export_pdf_report(self, output_path: str, target=None):
        """Export findings as a professional PDF report.

        Uses fpdf2 with a Unicode-capable system font for Turkish
        character support.  Falls back to ASCII-only output if no
        suitable font is found.
        """
        from fpdf import FPDF

        report_path = _resolve_report_path(output_path)
        summary = self.get_risk_summary()
        risk = calculate_risk(self._visible_findings())
        visible = self._visible_findings()
        font_path = _find_unicode_font()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)

        # ── Try to load a Unicode font ──────────────────────────────────
        if font_path:
            try:
                pdf.add_font("Uni", "", font_path)
                pdf.add_font("Uni", "B", font_path)  # same file, bold simulated
                body_font = "Uni"
                title_font = "Uni"
                _use_unicode = True
            except Exception:
                body_font = "Helvetica"
                title_font = "Helvetica"
                _use_unicode = False
        else:
            body_font = "Helvetica"
            title_font = "Helvetica"
            _use_unicode = False

        # ── Cover / Title page ──────────────────────────────────────────
        pdf.add_page()
        pdf.ln(40)
        pdf.set_font(title_font, "B", 28)
        pdf.cell(0, 14, "Vault Pentest Report", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(8)
        pdf.set_font(body_font, "", 14)
        if target:
            pdf.cell(0, 10, f"Target: {target}", align="C", new_x="LMARGIN", new_y="NEXT")
        from datetime import datetime
        pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        # Risk score highlight
        pdf.set_font(title_font, "B", 48)
        pdf.cell(0, 20, f"{risk['score']}/100", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(body_font, "", 16)
        pdf.cell(0, 10, f"Grade: {risk['grade']}", align="C", new_x="LMARGIN", new_y="NEXT")

        # ── Risk Summary table ──────────────────────────────────────────
        pdf.add_page()
        pdf.set_font(title_font, "B", 18)
        pdf.cell(0, 12, "Risk Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        col_w = [70, 40]
        pdf.set_font(body_font, "B", 11)
        pdf.set_fill_color(50, 50, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_w[0], 9, "Severity", border=1, fill=True)
        pdf.cell(col_w[1], 9, "Count", border=1, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

        sev_colors = {
            "CRITICAL": (220, 50, 50),
            "HIGH": (230, 140, 50),
            "MEDIUM": (220, 200, 50),
            "LOW": (100, 160, 220),
            "INFO": (160, 160, 160),
            "PASS": (80, 180, 80),
        }

        for severity in SEVERITY_ORDER:
            count = summary.get(severity, 0)
            if count == 0:
                pdf.set_font(body_font, "", 10)
            else:
                pdf.set_font(body_font, "B", 10)
            r, g, b = sev_colors.get(severity, (100, 100, 100))
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(col_w[0], 8, f"  {severity}", border=1, fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_fill_color(245, 245, 245)
            pdf.cell(col_w[1], 8, str(count), border=1, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)
        pdf.set_font(body_font, "B", 12)
        pdf.cell(0, 8, f"Total Findings: {summary['total']}", new_x="LMARGIN", new_y="NEXT")

        # ── Findings ────────────────────────────────────────────────────
        if visible:
            pdf.add_page()
            pdf.set_font(title_font, "B", 18)
            pdf.cell(0, 12, "Findings", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

            for idx, finding in enumerate(visible, start=1):
                sev = finding.get("severity", "INFO")
                title = finding.get("title", "")
                desc = finding.get("description", "")
                evidence = finding.get("evidence", "")
                mod = finding.get("module", "")

                # Severity label with color
                r, g, b = sev_colors.get(sev, (100, 100, 100))
                pdf.set_fill_color(r, g, b)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(body_font, "B", 10)
                pdf.cell(28, 7, f" {sev} ", border=1, fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font(body_font, "B", 11)
                # Title next to severity badge
                safe_title = title if _use_unicode else title.encode("ascii", errors="replace").decode()
                pdf.cell(0, 7, f"  {idx}. {safe_title}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(1)

                # Description
                pdf.set_font(body_font, "", 9)
                safe_desc = desc if _use_unicode else desc.encode("ascii", errors="replace").decode()
                pdf.set_x(15)
                pdf.multi_cell(0, 5, safe_desc)
                pdf.ln(1)

                # Evidence
                if evidence:
                    pdf.set_font(body_font, "", 8)
                    pdf.set_text_color(100, 100, 100)
                    ev_str = evidence if isinstance(evidence, str) else json.dumps(evidence, ensure_ascii=False)
                    safe_ev = ev_str[:200] if _use_unicode else ev_str[:200].encode("ascii", errors="replace").decode()
                    pdf.set_x(15)
                    pdf.multi_cell(0, 4, f"Evidence: {safe_ev}")
                    pdf.set_text_color(0, 0, 0)

                # Module
                if mod:
                    pdf.set_font(body_font, "", 8)
                    pdf.set_text_color(100, 100, 100)
                    pdf.set_x(15)
                    pdf.cell(0, 4, f"Module: {mod}", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)

                # ── Vault CLI Fix Commands ──────────────────────────────
                try:
                    from core.fix_commands import get_fix_commands
                    commands = get_fix_commands(finding)
                    if commands:
                        pdf.ln(2)
                        pdf.set_font(body_font, "B", 8)
                        pdf.set_fill_color(40, 120, 40)
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_x(15)
                        pdf.cell(18, 5, " FIX ", border=1, fill=True, new_x="RIGHT", new_y="TOP")
                        pdf.set_text_color(0, 0, 0)
                        pdf.set_font(body_font, "", 7.5)
                        for cmd in commands:
                            if pdf.get_y() > pdf.h - 15:
                                pdf.add_page()
                            safe_cmd = cmd if _use_unicode else cmd.encode("ascii", errors="replace").decode()
                            pdf.set_x(36)
                            pdf.set_font(body_font, "", 7)
                            pdf.set_text_color(60, 60, 60)
                            pdf.multi_cell(0, 3.5, f"$ {safe_cmd}")
                            pdf.set_text_color(0, 0, 0)
                except ImportError:
                    pass

                pdf.ln(3)

        # ── Remediation Recommendations ─────────────────────────────────
        try:
            from core.remediation_engine import (
                get_remediation,
                group_by_category,
                generate_priority_action_plan,
            )

            advice_list = get_remediation(visible)
            if advice_list:
                grouped = group_by_category(advice_list)
                action_plan = generate_priority_action_plan(advice_list)

                pdf.add_page()
                pdf.set_font(title_font, "B", 18)
                pdf.cell(0, 12, "Remediation Recommendations", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)
                pdf.set_font(body_font, "", 10)
                pdf.multi_cell(0, 5,
                    "The following actionable fix steps address the root causes "
                    "identified during the assessment. Each finding is grouped "
                    "by category with concrete Vault CLI commands."
                )
                pdf.ln(4)

                for category, items in grouped.items():
                    # Category header
                    pdf.set_font(title_font, "B", 13)
                    r, g, b = _category_color(category)
                    pdf.set_text_color(r, g, b)
                    pdf.cell(0, 8, category, new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)
                    pdf.ln(2)

                    for item in items:
                        # Check if we need a new page (at least 40mm remaining)
                        if pdf.get_y() > pdf.h - 40:
                            pdf.add_page()

                        # Item title with priority badge
                        prio_labels = {1: "CRITICAL", 2: "URGENT", 3: "IMPORTANT", 4: "ROUTINE", 5: "COSMETIC"}
                        prio_label = prio_labels.get(item.priority, "INFO")
                        prio_r, prio_g, prio_b = {
                            1: (220, 50, 50), 2: (230, 140, 50), 3: (220, 200, 50),
                            4: (100, 160, 220), 5: (160, 160, 160),
                        }.get(item.priority, (100, 100, 100))

                        pdf.set_fill_color(prio_r, prio_g, prio_b)
                        pdf.set_text_color(255, 255, 255)
                        pdf.set_font(body_font, "B", 8)
                        pdf.cell(20, 5, f" {prio_label} ", border=1, fill=True, new_x="RIGHT", new_y="TOP")
                        pdf.set_text_color(0, 0, 0)
                        pdf.set_font(body_font, "B", 10)
                        safe_item_title = item.title if _use_unicode else item.title.encode("ascii", errors="replace").decode()
                        pdf.multi_cell(0, 5, f"  {safe_item_title}")
                        pdf.ln(1)

                        # Root cause
                        pdf.set_font(body_font, "", 8)
                        pdf.set_text_color(100, 100, 100)
                        safe_root_cause = item.root_cause if _use_unicode else item.root_cause.encode("ascii", errors="replace").decode()
                        pdf.set_x(18)
                        pdf.multi_cell(0, 4, f"Root Cause: {safe_root_cause}")
                        pdf.set_text_color(0, 0, 0)
                        pdf.ln(1)

                        # Fix steps
                        pdf.set_font(body_font, "", 8)
                        for step in item.fix_steps:
                            if pdf.get_y() > pdf.h - 15:
                                pdf.add_page()
                            safe_step = step if _use_unicode else step.encode("ascii", errors="replace").decode()
                            pdf.set_x(15)
                            pdf.set_font(body_font, "", 7.5)
                            pdf.multi_cell(0, 3.5, safe_step)
                        pdf.ln(2)

                        # References
                        if item.references:
                            pdf.set_font(body_font, "", 7)
                            pdf.set_text_color(50, 100, 180)
                            for ref in item.references:
                                pdf.set_x(15)
                                pdf.cell(0, 3.5, ref, new_x="LMARGIN", new_y="NEXT")
                            pdf.set_text_color(0, 0, 0)
                        pdf.ln(2)

                # ── Priority Action Plan ───────────────────────────────
                pdf.add_page()
                pdf.set_font(title_font, "B", 18)
                pdf.cell(0, 12, "Priority Action Plan", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(4)
                pdf.set_font(body_font, "", 10)
                pdf.multi_cell(0, 5,
                    "Execute the following steps in order. Address all CRITICAL items "
                    "immediately, HIGH items within 7 days, MEDIUM within 30 days, "
                    "and LOW items during the next maintenance window."
                )
                pdf.ln(4)

                pdf.set_font(body_font, "", 9)
                for line in action_plan:
                    if pdf.get_y() > pdf.h - 15:
                        pdf.add_page()
                    if line.startswith("──"):
                        pdf.set_font(body_font, "B", 10)
                        pdf.ln(2)
                        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
                        pdf.set_font(body_font, "", 9)
                    else:
                        pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")

        except ImportError:
            pass  # remediation engine not available — skip section
        except Exception:
            pass  # don't let remediation errors break PDF generation

        # ── Overall Risk Assessment ──────────────────────────────────────
        pdf.add_page()
        pdf.set_font(title_font, "B", 18)
        pdf.cell(0, 12, "Overall Risk Assessment", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)
        pdf.set_font(body_font, "", 11)

        grade_text = {
            "A": "Excellent security posture. No significant findings.",
            "B": "Good security with minor issues to address.",
            "C": "Moderate risk — several findings require attention.",
            "D": "Serious risk — critical vulnerabilities present.",
            "F": "Critical failure — immediate remediation required.",
        }.get(risk["grade"][0] if risk["grade"] else "C",
              "Risk assessment based on automated pentest findings.")

        pdf.multi_cell(0, 6,
            f"Risk Score: {risk['score']} / 100\n"
            f"Grade: {risk['grade']}\n\n"
            f"{grade_text}\n\n"
            f"This report was generated automatically by the Vault Pentest Tool.\n"
            f"Findings are categorized by severity and include evidence where available.\n"
            f"Review each finding and prioritize remediation based on risk level.\n\n"
            f"A detailed remediation plan with concrete CLI commands is included\n"
            f"in the 'Remediation Recommendations' section above."
        )

        # ── Write ───────────────────────────────────────────────────────
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            pdf.output(str(report_path))
            print(f"\n[+] PDF report written: {report_path}")
            return report_path
        except OSError as error:
            print(f"\n[!] Could not write PDF report: {error}")
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


def clear_module_findings(*module_names: str):
    """Discard findings from specific modules only.

    Use this in MCP tool handlers so re-running the same tool replaces its
    own findings without wiping findings from other tools — enabling
    cross-tool finding accumulation for the AI agent.
    """
    with _default_report._lock:
        _default_report.findings[:] = [
            f for f in _default_report.findings
            if f.get("module") not in module_names
        ]


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

def export_pdf_report(output_path: str, target=None):
    """Module-level wrapper for PDF export. Delegates to the default Report."""
    return _default_report.export_pdf_report(output_path, target=target)


def _resolve_report_path(output_path: str) -> Path:
    report_path = Path(output_path)
    if report_path.parent == Path("."):
        return Path("reports") / report_path
    return report_path


# ── Remediation category colors ────────────────────────────────────────────────


def _category_color(category: str) -> tuple[int, int, int]:
    """Return a consistent color for a remediation category."""
    palette = {
        "TLS": (30, 120, 200),
        "Information Disclosure": (150, 100, 50),
        "CORS": (180, 130, 30),
        "Authentication": (50, 150, 100),
        "Policy / ACL": (200, 50, 50),
        "Token Management": (200, 100, 50),
        "Secrets Management": (100, 50, 180),
        "Credential Leaks": (220, 30, 30),
        "Environment Security": (80, 140, 140),
        "Audit & Monitoring": (60, 60, 160),
        "Seal / Unseal": (180, 60, 60),
        "Patch Management": (40, 160, 40),
        "General Security": (100, 100, 100),
    }
    return palette.get(category, (80, 80, 80))


# ── PDF font helper ───────────────────────────────────────────────────────────

def _find_unicode_font() -> str | None:
    """Locate a TTF font with Turkish/Unicode support.

    Searches common locations across Windows, macOS, and Linux.
    Returns the path to the first found font, or None.
    """
    import os
    import glob
    import platform

    candidates: list[str] = []

    if platform.system() == "Windows":
        candidates = [
            r"C:\Windows\Fonts\segoeui.ttf",
            r"C:\Windows\Fonts\arial.ttf",
            r"C:\Windows\Fonts\calibri.ttf",
            r"C:\Windows\Fonts\times.ttf",
        ]
    elif platform.system() == "Darwin":
        candidates = [
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/SFNSDisplay.ttf",
            "/Library/Fonts/Arial.ttf",
        ]
    else:  # Linux
        candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
        ]

    # Also check project-bundled font
    project_root = Path(__file__).resolve().parent.parent
    bundled = project_root / "fonts" / "DejaVuSans.ttf"
    if bundled.exists():
        return str(bundled)

    for path in candidates:
        if os.path.isfile(path):
            return path

    # Glob fallback for DejaVu on Linux
    if platform.system() == "Linux":
        for pattern in [
            "/usr/share/fonts/**/DejaVuSans.ttf",
            "/usr/share/fonts/**/dejavu/DejaVuSans.ttf",
        ]:
            for match in glob.glob(pattern, recursive=True):
                return match

    return None
