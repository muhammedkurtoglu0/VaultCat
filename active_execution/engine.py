"""Active execution engine — sync and async plan execution."""

from __future__ import annotations

import asyncio
from typing import Any

from .registry import ExecutionResult, RiskLevel, risk_level_allowed


class ActiveExecutionEngine:
    """Executes ordered steps of active execution modules against a context.

    Two execution modes:
    - ``execute_plan`` — synchronous (CLI, scripts)
    - ``aexecute_plan`` — async (MCP server, agent loop)
    """

    def __init__(self, registry):
        self.registry = registry

    # ── public API ──────────────────────────────────────────────────────

    def execute_plan(
        self,
        steps: list[dict],
        context,
        max_risk=RiskLevel.READ_ONLY,
        confirm_state_changing: bool = False,
    ) -> list[ExecutionResult]:
        """Run *steps* synchronously. Returns a list of ExecutionResult."""
        if isinstance(max_risk, str):
            max_risk = RiskLevel(max_risk)

        return list(
            self._iter_steps(steps, context, max_risk, confirm_state_changing)
        )

    async def aexecute_plan(
        self,
        steps: list[dict],
        context,
        max_risk=RiskLevel.READ_ONLY,
        confirm_state_changing: bool = False,
    ) -> list[ExecutionResult]:
        """Run *steps* asynchronously — awaitable from agent / MCP tools.

        Each module's ``execute`` call is offloaded to a thread so the event
        loop stays responsive.
        """
        if isinstance(max_risk, str):
            max_risk = RiskLevel(max_risk)

        results: list[ExecutionResult] = []
        for step in steps:
            result = await self._execute_one_async(
                step, context, max_risk, confirm_state_changing
            )
            results.append(result)
            # Continue on failure/blocked — consistent with the sync path;
            # a blocked or failed step must not starve the remaining steps.
        return results

    # ── internal ────────────────────────────────────────────────────────

    async def _execute_one_async(
        self,
        step: dict,
        context,
        max_risk: RiskLevel,
        confirm_state_changing: bool,
    ) -> ExecutionResult:
        """Validate and execute a single module step asynchronously."""
        module_id = step.get("module_id")
        module = self.registry.get(module_id)
        if not module:
            return ExecutionResult(
                status="error",
                message=f"Active module not found: {module_id}",
                evidence={"module_id": module_id},
            )

        if not risk_level_allowed(module.risk_level, max_risk):
            return ExecutionResult(
                status="blocked",
                message=(
                    f"Active module risk '{module.risk_level.value}' exceeds "
                    f"allowed max_risk '{max_risk.value}'."
                ),
                evidence={
                    "module_id": module_id,
                    "module_risk": module.risk_level.value,
                    "max_risk": max_risk.value,
                },
            )

        if module.risk_level != RiskLevel.READ_ONLY and not confirm_state_changing:
            return ExecutionResult(
                status="blocked",
                message=f"Active module requires explicit confirmation: {module_id}",
                evidence={
                    "module_id": module_id,
                    "module_risk": module.risk_level.value,
                    "required_confirmation": "confirm_state_changing",
                },
            )

        if not module.can_run(context):
            return ExecutionResult(
                status="skipped",
                message=f"Active module cannot run with current context: {module_id}",
                evidence={"module_id": module_id},
            )

        params = step.get("params") or step.get("parameters") or {}
        print(f"[*] Running active module: {module_id}")

        try:
            # Offload synchronous module.execute to a thread
            result = await asyncio.to_thread(module.execute, context, params)
        except Exception as error:
            result = ExecutionResult(
                status="error",
                message=f"Active module execution failed: {error}",
                evidence={"module_id": module_id, "error": str(error)},
            )

        print(f"    -> {result.status}: {result.message}")
        if result.evidence:
            print(f"    Evidence: {result.evidence}")

        # Sync discovered tokens from context → global store for auto-escalation
        _sync_context_to_global_store(context)

        return result

    def _iter_steps(
        self,
        steps: list[dict],
        context,
        max_risk: RiskLevel,
        confirm_state_changing: bool,
    ):
        """Generator that yields ExecutionResult for each step (sync path)."""
        for step in steps:
            module_id = step.get("module_id")
            module = self.registry.get(module_id)
            if not module:
                yield ExecutionResult(
                    status="error",
                    message=f"Active module not found: {module_id}",
                    evidence={"module_id": module_id},
                )
                continue

            if not risk_level_allowed(module.risk_level, max_risk):
                yield ExecutionResult(
                    status="blocked",
                    message=(
                        f"Active module risk '{module.risk_level.value}' exceeds "
                        f"allowed max_risk '{max_risk.value}'."
                    ),
                    evidence={
                        "module_id": module_id,
                        "module_risk": module.risk_level.value,
                        "max_risk": max_risk.value,
                    },
                )
                continue

            if module.risk_level != RiskLevel.READ_ONLY and not confirm_state_changing:
                yield ExecutionResult(
                    status="blocked",
                    message=f"Active module requires explicit confirmation: {module_id}",
                    evidence={
                        "module_id": module_id,
                        "module_risk": module.risk_level.value,
                        "required_confirmation": "confirm_state_changing",
                    },
                )
                continue

            if not module.can_run(context):
                yield ExecutionResult(
                    status="skipped",
                    message=f"Active module cannot run with current context: {module_id}",
                    evidence={"module_id": module_id},
                )
                continue

            print(f"[*] Running active module: {module_id}")
            params = step.get("params") or step.get("parameters") or {}
            try:
                result = module.execute(context, params)
            except Exception as error:
                result = ExecutionResult(
                    status="error",
                    message=f"Active module execution failed: {error}",
                    evidence={"module_id": module_id, "error": str(error)},
                )
            yield result
            print(f"    -> {result.status}: {result.message}")
            if result.evidence:
                print(f"    Evidence: {result.evidence}")

            # Sync discovered tokens from context → global store
            _sync_context_to_global_store(context)


# ---------------------------------------------------------------------------
# Helper — feed context tokens back to global DynamicCredentialStore
# ---------------------------------------------------------------------------


def _sync_context_to_global_store(context) -> None:
    """If the context has captured/escalated tokens, register them globally."""
    try:
        from ai_core.dynamic_session import global_store, _looks_like_vault_token
    except ImportError:
        return

    for attr, power in (
        ("escalated_token", "elevated"),
        ("captured_token", "unknown"),
    ):
        token = getattr(context, attr, None)
        # The "token not in …" pre-check is a best-effort fast-path; the real
        # check-then-act atomicity lives inside add_token (RLock-protected).
        if token and _looks_like_vault_token(token) and token not in global_store.tokens:
            global_store.add_token(token, source=f"active_exec.{attr}", power_level=power)
