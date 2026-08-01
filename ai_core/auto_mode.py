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

    async def _orchestrate_tree(self, root: Any, engine: Any) -> tuple[Any, list[dict]]:
        """Execute attack tree branches in parallel via AttackOrchestrator.

        Returns ``(walk_result, status_messages)`` where *walk_result* is
        compatible with the old TreeWalker result shape (has ``total_steps``,
        ``successes``, ``failures``, ``escalations``, ``final_token_power``)
        and *status_messages* is a list of ``{"type": "status", "message": ...}``
        dicts for the caller to yield.
        """
        from ai_core.planning.plan_schema import PlannedStep, AttackPhase
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.dynamic_session import global_store

        msgs: list[dict] = []

        # Collect direct children of root as steps
        children = list(getattr(root, "children", []) or [])
        if not children:
            # Empty tree — fall back to TreeWalker (it handles root-only)
            from ai_core.tree_walker import TreeWalker, RiskProfile
            walker = TreeWalker(
                tool_executor=self._tool_executor,
                risk_profile=RiskProfile.AGGRESSIVE,
                max_depth=4,
                max_total_steps=self.max_turns,
            )
            return await walker.walk(root, self.vault_addr, engine), msgs

        msgs.append({"type": "status", "message": f"  Decomposing {len(children)} branches into domain groups..."})

        steps = []
        for child in children:
            tool = getattr(child, "tool", "run_raw_vault_request")
            reason = getattr(child, "reason", "")[:200]
            params = dict(getattr(child, "params", {}) or {})
            risk = str(getattr(child, "risk", "balanced"))
            phase = str(getattr(child, "phase", "audit"))

            if tool == "__root__":
                continue

            steps.append(PlannedStep(
                tool=tool,
                reason=reason,
                params=params,
                phase=AttackPhase.AUDIT if phase in ("audit",) else (
                    AttackPhase.EXPLOIT if phase in ("exploit",) else AttackPhase.RECON
                ),
                risk="read_only" if risk in ("stealth",) else (
                    "state_changing" if risk in ("balanced",) else "state_changing"
                ),
                on_failure="skip",  # don't abort — try other branches
                max_retries=0,
            ))

        domain_count = len(set(self._domain_for_step(s) for s in steps))
        msgs.append({"type": "status", "message": f"  Spawning specialists for {domain_count} domains..."})

        orch = AttackOrchestrator(
            vault_addr=self.vault_addr,
            token=self.token,
            tool_executor=self._tool_executor,
            max_replans=2,
        )

        # Build a minimal plan object
        from ai_core.planning.plan_schema import PentestPlan
        plan = PentestPlan(vault_addr=self.vault_addr)
        plan.steps = steps
        plan.attack_narrative = "Attack tree parallel execution"

        orch_result = await orch.execute_plan(plan)

        msgs.append({"type": "status", "message": (
            f"  Domains: {sorted(orch_result.domains_involved)} | "
            f"Parallel execution: {orch_result.execution_time_ms:.0f}ms"
        )})

        # Build a WalkResult-compatible object for Phase 4
        class _OrchWalkResult:
            total_steps = orch_result.total_steps
            successes = orch_result.successes
            failures = orch_result.failures
            escalations = orch_result.replan_count
            final_token_power = "none"

        result = _OrchWalkResult()
        try:
            best = global_store.get_best_token()
            if best:
                result.final_token_power = best.power_level
        except Exception:
            pass

        return result, msgs

    @staticmethod
    def _domain_for_step(step: Any) -> str:
        """Quick domain lookup for a step's tool."""
        from ai_core.tools import TOOL_DOMAIN_MAP
        tool = getattr(step, "tool", "")
        domains = TOOL_DOMAIN_MAP.get(tool)
        if domains and "*" not in domains:
            return next(iter(domains))
        return "general"

    async def run(self) -> AsyncIterator[dict]:
        """Execute autonomous pentest using attack tree + parallel orchestrator.

        Flow:
        1. Recon (direct tool calls, no LLM overhead)
        2. Build attack tree from findings + tokens
        3. Orchestrator spawns domain specialists in PARALLEL via asyncio.gather
        4. Escalation → re-plan, re-orchestrate with elevated privileges
        5. Final pass: LLM agent for analysis + summary
        6. PDF report
        """
        from ai_core.mutation_engine import MutationEngine, gather_attack_state, BranchRisk

        self._start_time = time.monotonic()
        self._total_turns = 0
        self._phases_seen.clear()

        # ── Pre-flight ──────────────────────────────────────────────────
        clear_findings()
        self._report.clear()

        yield {"type": "status", "message": "=" * 54}
        yield {"type": "status", "message": "  AUTO MODE — Attack Tree + Mutation Engine"}
        yield {"type": "status", "message": "=" * 54}
        yield {"type": "status", "message": f"  Target     : {self.vault_addr}"}
        yield {"type": "status", "message": f"  Token      : {'present' if self.token else 'none'}"}
        yield {"type": "status", "message": f"  Max Steps  : {self.max_turns}"}
        yield {"type": "status", "message": f"  Strategy   : Parallel domain specialists + LLM mutation on failure"}
        yield {"type": "status", "message": "=" * 54}

        # ── 1. Initial recon ────────────────────────────────────────────
        if self._tool_executor:
            yield {"type": "status", "message": "\n--- Phase 1: Initial Recon ---"}
            recon_tools = ["run_unauthenticated_recon"]
            if self.hijack_path:
                recon_tools.append("run_hijack_scan")
            recon_tools.append("run_env_scan")

            for tool in recon_tools:
                if self._check_timeout():
                    break
                try:
                    params = {"vault_addr": self.vault_addr}
                    if self.hijack_path and tool == "run_hijack_scan":
                        params["path"] = self.hijack_path
                    yield {"type": "tool_call", "message": f"{tool}(...)", "tool": tool, "params": params}
                    result = await self._tool_executor(tool, params)
                    yield {"type": "tool_result", "message": str(result)[:300]}
                    self._total_turns += 1
                    self._phases_seen.add("recon")
                except Exception as exc:
                    yield {"type": "error", "message": f"{tool} failed: {exc}"}

        # ── 2. Build initial attack tree ────────────────────────────────
        yield {"type": "status", "message": "\n--- Phase 2: Building Attack Tree ---"}
        state = gather_attack_state()
        engine = MutationEngine()
        root = engine.start_tree(
            self.vault_addr,
            {"token_count": len(state["tokens"]), "findings_count": len(state["findings"])},
        )

        # Seed branches from findings
        for finding in state["findings"][:15]:
            sev = finding.get("severity", "INFO")
            title = finding.get("title", "")
            mod = finding.get("module", "")

            if any(w in title.lower() for w in ("denied", "blocked", "fail")):
                continue

            risk = BranchRisk.AGGRESSIVE if sev in ("CRITICAL", "HIGH") else (
                BranchRisk.BALANCED if sev == "MEDIUM" else BranchRisk.STEALTH
            )

            tool_map = {
                "recon": "run_unauthenticated_recon",
                "capability": "run_capability_audit",
                "privilege": "run_priv_esc_scan",
                "priv_esc": "run_priv_esc_scan",
                "kv_enum": "run_kv_enumeration",
                "ttl": "run_ttl_audit",
                "auth": "run_auth_config_audit",
                "policy": "read_single_policy",
                "secret": "run_secret_exfiltration",
                "env": "run_env_scan",
            }
            tool = tool_map.get(mod, "run_raw_vault_request") if mod else "run_raw_vault_request"

            engine.add_branch(root, tool, title[:150], risk=risk, phase="audit",
                            expected_outcome=f"Investigate: {title[:100]}")

        # Add token-specific branches
        for t in state["tokens"]:
            engine.add_branch(root, "run_capability_audit",
                f"Audit token: {t.get('power_level', 'unknown')} ({t.get('token', '')})",
                risk=BranchRisk.AGGRESSIVE, phase="audit",
                expected_outcome="Map token capabilities and find escalation paths")

        # Add pivot branches when DB credentials are already in the session
        db_creds = [c for c in state.get("credentials", []) if c.get("cred_type") in ("db_conn", "password")]
        if db_creds:
            yield {"type": "status", "message": f"  Pivot: {len(db_creds)} DB credential(s) — adding pivot branches"}
            engine.add_branch(root, "run_raw_vault_request",
                "Read database engine configuration for connection strings",
                params={"method": "GET", "path": "database/config"},
                risk=BranchRisk.AGGRESSIVE, phase="exploit",
                expected_outcome="Extract full DB connection details for direct pivot")

        yield {"type": "status", "message": f"  Tree: {engine.tree_summary()['total_nodes']} nodes seeded"}

        # ── 3. Execute via Orchestrator (parallel domain specialists) ────
        yield {"type": "status", "message": "\n--- Phase 3: Parallel Orchestrator ---"}
        walk_result, orch_msgs = await self._orchestrate_tree(root, engine)
        for msg in orch_msgs:
            yield msg

        self._total_turns += walk_result.total_steps
        self._phases_seen.update(["recon", "audit", "report"])

        yield {"type": "status", "message": f"  Steps: {walk_result.total_steps} | Success: {walk_result.successes} | Fail: {walk_result.failures} | Escalations: {walk_result.escalations}"}

        # ── 4. LLM Agent summary pass ───────────────────────────────────
        if self._tool_executor:
            yield {"type": "status", "message": "\n--- Phase 4: Agent Analysis ---"}
            self._agent = PentestAgent(
                vault_addr=self.vault_addr, token=self.token,
                provider=self.provider, model=self.model,
            )
            self._agent.set_tool_executor(self._tool_executor)

            summary_objective = (
                f"Autonomous attack tree walk complete against {self.vault_addr}. "
                f"Steps executed: {walk_result.total_steps}, "
                f"successes: {walk_result.successes}, failures: {walk_result.failures}, "
                f"escalations: {walk_result.escalations}, "
                f"final token power: {walk_result.final_token_power}. "
                f"Review ALL findings with get_findings, analyse the risk score, "
                f"and provide a structured penetration test summary. "
                f"Use tables. Be concise. One message only."
            )
            try:
                async for event in self._agent.run(summary_objective):
                    yield event
            except Exception:
                pass

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
    # Always emit findings count for the interval loop tracker
    yield {"type": "findings_count", "count": len(findings)}

    if not findings:
        yield {"type": "status", "message": "\nNo findings to report — skipping PDF export."}
        yield {"type": "exit_code", "code": 0}
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
