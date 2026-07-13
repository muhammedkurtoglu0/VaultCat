"""Async-capable executor that runs plans through the active execution engine.

Used by both the legacy ChatUI and the new PentestAgent to execute
multi-step attack plans.
"""

from __future__ import annotations

import asyncio
import sys
import os
from typing import Any

from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.registry import RiskLevel

# Allow importing main.py for registry building
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


RISK_MAP = {
    "read_only": RiskLevel.READ_ONLY,
    "state_changing": RiskLevel.STATE_CHANGING,
    "destructive": RiskLevel.DESTRUCTIVE,
}


class Executor:
    """Executes pentest plans using the active execution engine.

    Supports both sync (``execute_plan``) and async (``aexecute_plan``)
    call paths so it works from CLI scripts and async agent loops.
    """

    def __init__(self, capabilities, memory):
        self.capabilities = capabilities
        self.memory = memory
        self.registry = None
        self.engine = None
        self._build_registry()

    def _build_registry(self):
        try:
            from main import build_active_execution_registry
            self.registry = build_active_execution_registry()
            self.engine = ActiveExecutionEngine(self.registry)
        except ImportError as e:
            print(f"[!] Registry could not be built: {e}")

    # ── sync (legacy / CLI) ────────────────────────────────────────────

    def execute_plan(
        self,
        plan: dict,
        vault_addr: str | None = None,
        token: str | None = None,
    ) -> list[dict]:
        """Run a plan synchronously. Returns a list of result dicts."""
        if not self.engine:
            return [{"status": "error", "message": "Engine not started"}]

        context = ExecutionContext(
            vault_addr=vault_addr or plan.get("vault_addr"),
            token=token or plan.get("token"),
        )

        if not context.vault_addr:
            return [{"status": "error", "message": "Vault address not specified"}]
        if not context.token:
            return [{"status": "error", "message": "Token not specified"}]

        results = []
        for step in plan.get("steps", []):
            module_id = step["module"]
            params = step.get("params", {})
            risk = step.get("risk", "read_only")
            max_risk = RISK_MAP.get(risk, RiskLevel.READ_ONLY)

            print(f"\n  ▶ {module_id} running...")
            print(f"  📝 {step.get('description', '')}")

            try:
                engine_results = self.engine.execute_plan(
                    steps=[{"module_id": module_id, "params": params}],
                    context=context,
                    max_risk=max_risk,
                    confirm_state_changing=True,
                )
            except Exception as error:
                results.append({
                    "module": module_id,
                    "status": "error",
                    "message": str(error),
                    "evidence": {},
                })
                print(f"  ❌ {module_id} error: {error}")
                break

            for res in engine_results:
                result = {
                    "module": module_id,
                    "status": res.status,
                    "message": res.message,
                    "evidence": res.evidence,
                }
                results.append(result)
                self._record_result(module_id, res, context)

            if engine_results and engine_results[-1].status in ("error", "failed"):
                print(f"  ❌ {module_id} failed — chain stopped.")
                break

        return results

    # ── async (agent / MCP) ────────────────────────────────────────────

    async def aexecute_plan(
        self,
        plan: dict,
        vault_addr: str | None = None,
        token: str | None = None,
    ) -> list[dict]:
        """Run a plan asynchronously — awaitable from agent loops."""
        if not self.engine:
            return [{"status": "error", "message": "Engine not started"}]

        context = ExecutionContext(
            vault_addr=vault_addr or plan.get("vault_addr"),
            token=token or plan.get("token"),
        )

        if not context.vault_addr:
            return [{"status": "error", "message": "Vault address not specified"}]

        results = []
        for step in plan.get("steps", []):
            module_id = step["module"]
            params = step.get("params", {})
            risk = step.get("risk", "read_only")
            max_risk = RISK_MAP.get(risk, RiskLevel.READ_ONLY)

            print(f"\n  ▶ {module_id} running (async)...")
            print(f"  📝 {step.get('description', '')}")

            try:
                engine_results = await self.engine.aexecute_plan(
                    steps=[{"module_id": module_id, "params": params}],
                    context=context,
                    max_risk=max_risk,
                    confirm_state_changing=True,
                )
            except Exception as error:
                results.append({
                    "module": module_id,
                    "status": "error",
                    "message": str(error),
                    "evidence": {},
                })
                print(f"  ❌ {module_id} error: {error}")
                break

            for res in engine_results:
                result = {
                    "module": module_id,
                    "status": res.status,
                    "message": res.message,
                    "evidence": res.evidence,
                }
                results.append(result)
                self._record_result(module_id, res, context)

            if engine_results and engine_results[-1].status in ("error", "failed"):
                print(f"  ❌ {module_id} failed — chain stopped.")
                break

        return results

    # ── helpers ─────────────────────────────────────────────────────────

    def _record_result(self, module_id: str, res, context):
        """Persist execution outcome to memory and capture credentials."""
        self.memory.add_execution(module_id, res.status, res.evidence)

        if res.status == "success" and hasattr(context, "findings"):
            for finding in context.findings:
                if finding not in self.memory.findings:
                    self.memory.add_finding(finding)

        if res.status == "success" and res.evidence:
            captured_token = (
                res.evidence.get("captured_token")
                or res.evidence.get("token")
            )
            if captured_token:
                context.captured_token = captured_token
                context.escalated_token = captured_token
                self.memory.add_credential("captured_token", captured_token)

            for key in ("secret_id", "role_id", "username",
                         "password", "access_key"):
                if key in res.evidence:
                    self.memory.add_credential(key, res.evidence[key])
