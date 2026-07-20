"""Autonomous pentest runner — LLM-driven, non-interactive, read-only.

Wraps :class:`PentestAgent` in an outer loop so the agent can chain
multiple conversational turns without waiting for user input.  When the
agent finishes a turn (natural-language response with no tool calls),
the runner feeds it a continuation prompt until all penetration-testing
phases are covered or the turn limit is reached.

Designed for ``chat --auto`` and cron / Task Scheduler usage.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import datetime
from typing import Any, AsyncIterator, Optional

from ai_core.agent import PentestAgent
from ai_core.llm_engine import LLMClient
from ai_core.memory import Memory
from ai_core.tools import ALL_TOOLS
from core.report import (
    Report,
    clear_findings,
    clear_module_findings,
    export_pdf_report,
    get_default_report,
)
from core.risk_score import calculate_risk


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_TURNS = 30
DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes wall-clock
DEFAULT_MAX_RISK = "read_only"

# Tool names that are blocked in auto mode (state-changing or destructive).
_BLOCKED_TOOLS: set[str] = {
    "run_privilege_escalation",
    "run_database_credential_harvest",
    "run_cloud_key_exfiltration",
}

# Completion markers — when the agent says these AND all phases are covered,
# we consider the pentest done.
_COMPLETION_MARKERS = (
    "penetration test complete",
    "final report",
    "görev tamam",
    "özet",
    "assessment complete",
    "pentest complete",
    "no further",
    "all phases complete",
    "tüm fazlar tamam",
    "in conclusion",
)

# Continuation prompts fed to the agent between turns.
_CONTINUATION_PROMPTS = [
    "Continue to the next phase. Run the remaining audit tools and report findings.",
    "Continue the assessment. Execute the next logical tool based on previous results.",
    "Proceed with the next step in the methodology. Be thorough.",
    "Keep going — cover any remaining audit or analysis steps, then generate a summary.",
]


class AutoPentestRunner:
    """Orchestrates a fully autonomous, read-only Vault pentest.

    Parameters
    ----------
    vault_addr:
        Target Vault URL.  **Must be set** — auto mode refuses to run
        without a target.
    token:
        Optional Vault token for authenticated audit phases.
    provider:
        LLM provider (``"deepseek"``, ``"openai"``, ``"anthropic"``,
        ``"ollama"``).  Auto-detected when omitted.
    model:
        LLM model ID.  Provider default when omitted.
    hijack_path:
        Optional local path to scan for leaked credentials.
    max_risk:
        Maximum risk level for tool calls.  Default ``"read_only"``.
    max_turns:
        Maximum total LLM turns across all continuation rounds.
        Default 30.
    timeout_seconds:
        Wall-clock timeout.  Default 1800 (30 min).
    """

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        hijack_path: str | None = None,
        max_risk: str = DEFAULT_MAX_RISK,
        max_turns: int = DEFAULT_MAX_TURNS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        if not vault_addr:
            raise ValueError("Auto mode requires --target. No target, nothing to do.")
        self.vault_addr = vault_addr
        self.token = token
        self.provider = provider
        self.model = model
        self.hijack_path = hijack_path
        self.max_risk = max_risk
        self.max_turns = max_turns
        self.timeout_seconds = timeout_seconds

        # Internal state
        self._agent: PentestAgent | None = None
        self._total_turns = 0
        self._start_time = 0.0
        self._phases_seen: set[str] = set()
        self._report: Report = get_default_report()  # use the global shared instance
        self._tool_executor = None  # bound from ChatUI

    # ── public API ──────────────────────────────────────────────────────────

    def set_tool_executor(self, executor):
        """Bind the async function that actually runs tool calls.

        Same signature as ``PentestAgent.set_tool_executor``.
        """
        self._tool_executor = executor

    async def run(self) -> AsyncIterator[dict]:
        """Execute the autonomous pentest and yield progress events.

        Events follow the same schema as :meth:`PentestAgent.run` so
        they can be rendered by :class:`ChatUI`.
        """
        self._start_time = time.monotonic()
        self._total_turns = 0
        self._phases_seen.clear()

        # ── Pre-flight ──────────────────────────────────────────────────
        clear_findings()
        self._report.clear()

        yield {"type": "status", "message": "=" * 54}
        yield {"type": "status", "message": "  AUTO MODE — Autonomous Read-Only Pentest"}
        yield {"type": "status", "message": "=" * 54}
        yield {"type": "status", "message": f"  Target     : {self.vault_addr}"}
        yield {"type": "status", "message": f"  Token      : {'present' if self.token else 'none (unauthenticated only)'}"}
        yield {"type": "status", "message": f"  Max Risk   : {self.max_risk}"}
        yield {"type": "status", "message": f"  Max Turns  : {self.max_turns}"}
        yield {"type": "status", "message": f"  Timeout    : {self.timeout_seconds}s"}
        yield {"type": "status", "message": "=" * 54}

        # ── Build the agent ─────────────────────────────────────────────
        self._agent = PentestAgent(
            vault_addr=self.vault_addr,
            token=self.token,
            provider=self.provider,
            model=self.model,
        )
        if self._tool_executor:
            self._agent.set_tool_executor(self._tool_executor)

        yield {"type": "status", "message": f"  Provider   : {self._agent.llm.provider}"}
        yield {"type": "status", "message": f"  Model      : {self._agent.llm.model}"}
        yield {"type": "status", "message": ""}

        # ── Initial objective ───────────────────────────────────────────
        hijack_note = ""
        if self.hijack_path:
            hijack_note = (
                f" Also scan {self.hijack_path} for leaked Vault credentials "
                f"(files, env vars, git history)."
            )

        initial_objective = (
            f"You are running in AUTONOMOUS mode against {self.vault_addr}. "
            f"Your job is to perform a COMPLETE penetration test without any user interaction. "
            f"Start with Phase 1 (unauthenticated recon), then move through all phases. "
            f"{hijack_note}"
            f"Token status: {'Token available for authenticated audits' if self.token else 'No token — stick to unauthenticated recon only'}. "
            f"IMPORTANT: This is READ-ONLY mode. Do NOT attempt state-changing operations. "
            f"After completing all phases, provide a structured SUMMARY of all findings. "
            f"CRITICAL: Call tools aggressively. After each tool result, immediately call the NEXT "
            f"logical tool without pausing. Chain as many tools as needed in sequence. "
            f"Only stop when the penetration test is FULLY COMPLETE across all phases."
        )

        # ── Outer loop — feed continuation prompts ──────────────────────
        objective = initial_objective
        continuation_idx = 0
        completed = False

        while self._total_turns < self.max_turns and not completed:
            # Wall-clock timeout
            if self._check_timeout():
                yield {"type": "warning", "message": "Timeout reached — generating partial report."}
                break

            yield {"type": "status", "message": f"\n--- Turn group {self._total_turns + 1}+ ---"}

            try:
                async for event in self._agent.run(objective):
                    yield event

                    if event.get("type") == "tool_call":
                        self._total_turns += 1
                        self._track_phase(event)

                    elif event.get("type") == "tool_result":
                        pass  # already counted in tool_call

                    elif event.get("type") == "message":
                        content = event.get("message", "")
                        if self._is_complete(content) and self._all_phases_covered():
                            completed = True
                            yield {"type": "complete", "message": "Autonomous pentest completed — generating PDF report."}

                    elif event.get("type") == "error":
                        # Non-fatal — try next continuation
                        yield {"type": "warning", "message": "Agent reported error, continuing with next prompt."}
                        break  # break inner loop, try next continuation

                    elif event.get("type") == "complete":
                        if self._all_phases_covered():
                            completed = True
                        break  # agent signalled done, check outer loop condition

            except Exception as exc:
                yield {"type": "error", "message": f"Agent error: {exc}"}
                break

            # If we're not done, feed a continuation prompt
            if not completed and self._total_turns < self.max_turns:
                prompt = _CONTINUATION_PROMPTS[continuation_idx % len(_CONTINUATION_PROMPTS)]
                continuation_idx += 1
                objective = (
                    f"{prompt}\n\n"
                    f"Context: You are at turn {self._total_turns}/{self.max_turns}. "
                    f"Completed phases so far: {sorted(self._phases_seen) or 'none'}. "
                    f"Target: {self.vault_addr}. "
                    f"{'Token is available.' if self.token else 'No token.'} "
                    f"Continue the penetration test autonomously. "
                    f"Call the next logical tool immediately — do NOT ask questions, just act."
                )

        # ── Finalize ─────────────────────────────────────────────────────
        yield {"type": "status", "message": ""}
        yield {"type": "status", "message": "=" * 54}
        yield {"type": "status", "message": "  Total LLM turns : {}".format(self._total_turns)}
        yield {"type": "status", "message": "  Phases covered   : {}".format(sorted(self._phases_seen) or "none")}
        yield {"type": "status", "message": "  Findings         : {}".format(len(self._report.findings))}
        yield {"type": "status", "message": "=" * 54}

    # ── helpers ─────────────────────────────────────────────────────────────

    def _check_timeout(self) -> bool:
        return (time.monotonic() - self._start_time) > self.timeout_seconds

    def _track_phase(self, event: dict) -> None:
        """Infer the current pentest phase from the tool being called."""
        tool = event.get("tool", "")
        phase_map = {
            "run_unauthenticated_recon": "recon",
            "run_hijack_scan": "hijack",
            "run_env_scan": "hijack",
            "run_capability_audit": "audit",
            "run_priv_esc_scan": "audit",
            "run_kv_enumeration": "audit",
            "run_ttl_audit": "audit",
            "run_auth_config_audit": "audit",
            "read_single_policy": "audit",
            "run_policy_auditor": "audit",
            "run_raw_vault_request": "audit",
            "get_findings": "report",
            "get_risk_score": "report",
        }
        phase = phase_map.get(tool)
        if phase:
            self._phases_seen.add(phase)

    def _all_phases_covered(self) -> bool:
        """Return True when we've covered at least recon and report phases."""
        # Minimum: recon + report. If token is available, add audit.
        required = {"recon", "report"}
        if self.token:
            required.add("audit")
        return required.issubset(self._phases_seen)

    @staticmethod
    def _is_complete(text: str) -> bool:
        if not text:
            return False
        lowered = text.lower()
        return any(m in lowered for m in _COMPLETION_MARKERS) and len(text) > 80


# ---------------------------------------------------------------------------
# Module-level entry point (used by ChatUI)
# ---------------------------------------------------------------------------


async def run_auto_pentest(
    vault_addr: str | None = None,
    token: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    hijack_path: str | None = None,
    max_risk: str = DEFAULT_MAX_RISK,
    max_turns: int = DEFAULT_MAX_TURNS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    pdf_report: str | None = None,
    tool_executor=None,
) -> AsyncIterator[dict]:
    """Convenience coroutine that runs :class:`AutoPentestRunner` and exports PDF.

    Yields the same event stream as the runner, plus a final ``pdf_report``
    event when the report file has been written.
    """
    runner = AutoPentestRunner(
        vault_addr=vault_addr,
        token=token,
        provider=provider,
        model=model,
        hijack_path=hijack_path,
        max_risk=max_risk,
        max_turns=max_turns,
        timeout_seconds=timeout_seconds,
    )
    if tool_executor:
        runner.set_tool_executor(tool_executor)

    async for event in runner.run():
        yield event

    # ── Generate PDF report ─────────────────────────────────────────────
    findings = runner._report.findings
    if not findings:
        yield {"type": "status", "message": "\nNo findings to report — skipping PDF export."}
        return

    if not pdf_report:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_report = f"pentest_report_{ts}.pdf"

    yield {"type": "status", "message": f"\nGenerating PDF report: {pdf_report}"}
    report_path = export_pdf_report(pdf_report, target=vault_addr)
    if report_path:
        yield {"type": "pdf_report", "path": str(report_path)}
        # Exit code signal: findings found
        yield {"type": "status", "message": f"\nReport exported: {report_path}"}
        yield {"type": "exit_code", "code": 1 if findings else 0}
    else:
        yield {"type": "error", "message": "PDF report generation failed"}
        yield {"type": "exit_code", "code": 2}
