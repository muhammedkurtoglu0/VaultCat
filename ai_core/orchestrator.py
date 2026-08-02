"""Parallel attack orchestrator — decompose and fan out by domain.

Takes a :class:`PentestPlan`, groups its steps by domain, spawns one
:class:`SpecialistAgent` per domain, and runs them in parallel via
:func:`asyncio.gather`.  Collects results, detects escalations, and
optionally re-plans when higher-privilege tokens are discovered.

Usage::

    from ai_core.orchestrator import AttackOrchestrator
    from ai_core.planning.plan_schema import PentestPlan

    orch = AttackOrchestrator(vault_addr="https://vault:8200",
                               tool_executor=my_executor)
    plan = PentestPlan(...)  # from planner or mutation engine
    result = await orch.execute_plan(plan)
    logger.info(f"{result.successes}/{result.total_steps} steps succeeded")
    logger.info(f"Domains involved: {result.domains_involved}")
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ai_core.tools import TOOL_DOMAIN_MAP, UNIVERSAL_TOOL_NAMES
from ai_core.specialist_agent import SpecialistAgent, SpecialistResult
from core.logger import logger


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorResult:
    """Aggregated result from a parallel plan execution."""

    plan_id: str = ""
    status: str = "completed"  # completed | partial | failed | escalated
    domains_involved: set[str] = field(default_factory=set)
    total_steps: int = 0
    successes: int = 0
    failures: int = 0
    escalated: bool = False
    specialist_results: dict[str, SpecialistResult] = field(default_factory=dict)
    synthesized_findings: list[dict] = field(default_factory=list)
    new_tokens: list[str] = field(default_factory=list)
    new_credentials: int = 0
    execution_time_ms: float = 0.0
    replan_count: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AttackOrchestrator:
    """Decompose a pentest plan by domain and execute in parallel.

    Parameters
    ----------
    vault_addr:
        Target Vault URL.  Injected into every step that lacks it.
    token:
        Initial Vault token (may be overridden by the global store at runtime).
    tool_executor:
        Async callable ``(tool_name, params) -> str`` passed to every specialist.
    max_replans:
        How many times the orchestrator may re-plan after escalation (default 2).
        Prevents infinite re-plan loops.
    llm_client:
        Optional :class:`LLMClient` for ReAct-powered specialists.  When set
        and ``use_llm=True``, each specialist runs its own mini ReAct loop
        instead of blindly executing steps sequentially.
    use_llm:
        Whether to use LLM-powered ReAct specialists.  Default ``False``.
        Requires ``llm_client`` to be set.
    """

    def __init__(
        self,
        vault_addr: str = "",
        token: str = "",
        tool_executor: Callable[..., Any] | None = None,
        max_replans: int = 2,
        llm_client: Any | None = None,
        use_llm: bool = False,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self._executor = tool_executor
        self._max_replans = max_replans
        self._llm_client = llm_client
        self._use_llm = use_llm

    # ── public API ──────────────────────────────────────────────────────

    async def execute_plan(self, plan: Any) -> OrchestratorResult:
        """Execute *plan* in parallel across domains.

        Parameters
        ----------
        plan:
            A :class:`PentestPlan` (or any object with a ``.steps`` attribute
            whose items have ``.tool``, ``.params``, ``.on_failure``, and
            ``.max_retries``).

        Returns
        -------
        :class:`OrchestratorResult` with per-domain metrics and merged findings.
        """
        started = time.monotonic()
        steps = list(getattr(plan, "steps", []) or [])
        plan_id = getattr(plan, "id", "") or ""

        if not steps:
            return OrchestratorResult(
                plan_id=plan_id,
                status="completed",
                execution_time_ms=(time.monotonic() - started) * 1000,
                errors=["Plan has no steps"],
            )

        # 1. Group steps by domain
        domain_groups = self._group_steps_by_domain(steps)

        # 2. Spawn parallel specialists
        specialist_results = await self._spawn_specialists(domain_groups)

        # 3. Aggregate
        result = self._aggregate(plan_id, specialist_results, started)

        # 4. Escalation → re-plan (if under limit)
        if result.escalated and self._max_replans > 0:
            new_plan = await self._maybe_replan(plan, specialist_results)
            if new_plan:
                # Create a fresh orchestrator with decremented replan budget
                sub = AttackOrchestrator(
                    vault_addr=self.vault_addr,
                    token=self.token,
                    tool_executor=self._executor,
                    max_replans=self._max_replans - 1,
                )
                sub_result = await sub.execute_plan(new_plan)
                # Merge
                result = self._merge_results(result, sub_result)

        return result

    # ── domain grouping ──────────────────────────────────────────────────

    def _group_steps_by_domain(
        self, steps: list[Any]
    ) -> dict[str, list[Any]]:
        """Assign each step to a domain based on its tool name.

        Steps whose tool isn't in :data:`TOOL_DOMAIN_MAP` go to ``"general"``.
        Universal tools are duplicated into every domain group that has at
        least one step, so every specialist can report findings and search.
        """
        groups: dict[str, list[Any]] = {}

        if not steps:
            return groups

        # First pass: assign domain-specific steps
        for step in steps:
            tool = getattr(step, "tool", "")
            domains = TOOL_DOMAIN_MAP.get(tool)

            if domains is None or "*" in (domains or set()):
                # Universal or unknown — handle in second pass
                continue

            # Pick the first domain (a tool can belong to multiple;
            # the first listed domain is the primary one).
            primary = next(iter(domains))
            groups.setdefault(primary, []).append(step)

        # Second pass: distribute universal + unknown tools
        if groups:
            for step in steps:
                tool = getattr(step, "tool", "")
                domains = TOOL_DOMAIN_MAP.get(tool)

                if domains is None:
                    # Unknown tool → general
                    groups.setdefault("general", []).append(step)
                elif "*" in domains:
                    # Universal → add to every existing domain group
                    for domain in groups:
                        groups[domain].append(step)
        else:
            # No domain-specific steps at all → everything goes to general
            groups["general"] = list(steps)

        return groups

    # ── parallel execution ──────────────────────────────────────────────

    async def _spawn_specialists(
        self, domain_groups: dict[str, list[Any]]
    ) -> dict[str, SpecialistResult]:
        """Create one :class:`SpecialistAgent` per domain, run all in parallel.

        Uses :func:`asyncio.gather` with ``return_exceptions=True`` so one
        crashing specialist never kills the others.

        When ``use_llm=True`` and ``llm_client`` is set, each specialist runs
        a ReAct loop: Think → Act → Observe → Adapt.  Otherwise they execute
        steps sequentially (fast, predictable).
        """
        async def _run_one(domain: str, steps: list[Any]) -> tuple[str, SpecialistResult]:
            agent = SpecialistAgent(
                domain=domain,
                vault_addr=self.vault_addr,
                token=self.token,
                tool_executor=self._executor,
            )

            if self._use_llm and self._llm_client:
                result = await agent.run_with_llm(
                    steps=steps,
                    llm_client=self._llm_client,
                    max_iterations=max(4, len(steps) * 2),
                )
            else:
                result = await agent.execute_steps(steps)

            return domain, result

        coroutines = [
            _run_one(domain, steps)
            for domain, steps in domain_groups.items()
        ]

        gathered = await asyncio.gather(*coroutines, return_exceptions=True)

        results: dict[str, SpecialistResult] = {}
        for item in gathered:
            if isinstance(item, Exception):
                # A specialist crashed entirely — create an error result
                results[str(item)] = SpecialistResult(
                    domain="unknown",
                    status="failed",
                    errors=[str(item)],
                )
            else:
                domain, sresult = item
                results[domain] = sresult

        return results

    # ── aggregation ─────────────────────────────────────────────────────

    def _aggregate(
        self,
        plan_id: str,
        specialist_results: dict[str, SpecialistResult],
        started: float,
    ) -> OrchestratorResult:
        """Merge specialist results into a single orchestrator result."""
        result = OrchestratorResult(
            plan_id=plan_id,
            specialist_results=specialist_results,
            domains_involved=set(specialist_results.keys()),
        )

        all_findings: list[dict] = []
        for sr in specialist_results.values():
            result.total_steps += sr.steps_total
            result.successes += sr.steps_succeeded
            result.failures += sr.steps_failed
            if sr.escalated:
                result.escalated = True
            result.new_tokens.extend(sr.new_tokens)
            result.new_credentials += sr.new_credentials
            result.errors.extend(sr.errors)
            all_findings.extend(sr.findings)

        # Deduplicate findings by (severity, title)
        seen: set[tuple[str, str]] = set()
        for f in all_findings:
            key = (f.get("severity", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                result.synthesized_findings.append(f)

        # Sort by severity
        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result.synthesized_findings.sort(
            key=lambda f: _sev_order.get(str(f.get("severity", "")), 99)
        )

        # Determine overall status
        if result.failures > 0 and result.successes == 0:
            result.status = "failed"
        elif result.failures > 0:
            result.status = "partial"
        elif result.escalated:
            result.status = "escalated"
        else:
            result.status = "completed"

        result.execution_time_ms = (time.monotonic() - started) * 1000
        return result

    # ── re-planning ─────────────────────────────────────────────────────

    async def _maybe_replan(
        self, plan: Any, specialist_results: dict[str, SpecialistResult]
    ) -> Any | None:
        """Generate a new plan when escalation occurred.

        Tries the planner factory; falls back to returning *None* (no re-plan).
        """
        try:
            from ai_core.dynamic_session import global_store
            from ai_core.planning.plan_schema import PentestPlan

            best = global_store.get_best_token()
            new_token = best.token if best else None
            if not new_token:
                return None

            # Build a simple follow-up plan: capability audit + exploit
            # using the newly elevated token
            new_plan = PentestPlan(vault_addr=self.vault_addr)
            new_plan.attack_narrative = (
                f"Re-plan after escalation — new token power: {best.power_level}"
            )

            # Minimal re-plan steps: audit + exploit the new privilege
            from ai_core.planning.plan_schema import PlannedStep, AttackPhase

            new_plan.steps = [
                PlannedStep(
                    tool="run_capability_audit",
                    reason="Audit the newly escalated token's capabilities",
                    params={"vault_addr": self.vault_addr, "token": new_token},
                    phase=AttackPhase.AUDIT,
                    risk="read_only",
                ),
                PlannedStep(
                    tool="run_priv_esc_scan",
                    reason="Check if the escalated token can escalate further",
                    params={"vault_addr": self.vault_addr, "token": new_token},
                    phase=AttackPhase.AUDIT,
                    risk="read_only",
                ),
                PlannedStep(
                    tool="run_kv_enumeration",
                    reason="Enumerate KV paths with the escalated token",
                    params={"vault_addr": self.vault_addr, "token": new_token},
                    phase=AttackPhase.AUDIT,
                    risk="read_only",
                ),
            ]
            return new_plan
        except ImportError:
            return None
        except Exception:
            return None

    def _merge_results(
        self, first: OrchestratorResult, second: OrchestratorResult
    ) -> OrchestratorResult:
        """Merge two orchestrator results (original + re-plan)."""
        first.total_steps += second.total_steps
        first.successes += second.successes
        first.failures += second.failures
        first.escalated = first.escalated or second.escalated
        first.domains_involved |= second.domains_involved
        first.specialist_results.update(second.specialist_results)
        first.new_tokens.extend(second.new_tokens)
        first.new_credentials += second.new_credentials
        first.errors.extend(second.errors)
        first.replan_count += second.replan_count + 1

        # Re-deduplicate findings
        seen: set[tuple[str, str]] = set()
        merged: list[dict] = []
        for f in first.synthesized_findings + second.synthesized_findings:
            key = (f.get("severity", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                merged.append(f)
        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        merged.sort(key=lambda f: _sev_order.get(str(f.get("severity", "")), 99))
        first.synthesized_findings = merged

        if first.status == "completed" and second.status != "completed":
            first.status = second.status

        return first
