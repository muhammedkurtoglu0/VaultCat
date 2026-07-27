"""Specialist Agent — domain-focused parallel worker for the orchestrator.

Each :class:`SpecialistAgent` owns exactly one domain (e.g. ``"token"``,
``"database"``).  Two execution modes are available:

* **Direct** (:meth:`execute_steps`) — runs planned steps sequentially with
  no LLM overhead.  Fast and predictable.
* **ReAct** (:meth:`run_with_llm`) — gives the specialist an LLM and lets it
  reason about tool selection, observe results, and adapt its strategy.
  Slower but smarter — handles unexpected responses and discovers new
  attack paths autonomously.

Usage::

    # Direct mode (fast, predictable)
    agent = SpecialistAgent("database", vault_addr="https://...",
                             tool_executor=my_executor)
    result = await agent.execute_steps(database_steps)

    # ReAct mode (smart, adaptive)
    result = await agent.run_with_llm(
        steps=database_steps,
        llm_client=my_llm,
        max_iterations=8,
    )
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ai_core.tools import ALL_TOOLS, TOOL_DOMAIN_MAP, UNIVERSAL_TOOL_NAMES, ToolDef


# ---------------------------------------------------------------------------
# Domain-specific system prompts
# ---------------------------------------------------------------------------

DOMAIN_PROMPTS: dict[str, str] = {
    "token": (
        "You are a Vault TOKEN specialist — you own everything related to "
        "authentication tokens, ACL policies, identity, and privilege escalation. "
        "Your tools: capability audit, privilege escalation scan, policy auditor, "
        "auth config audit, read_single_policy, run_privilege_escalation, "
        "list_active_modules, run_active_module, run_raw_vault_request. "
        "METHODOLOGY: audit the token's capabilities first → check for wildcard "
        "sudo paths → escalate via token creation or policy backdoor → report "
        "the new power level."
    ),
    "secrets": (
        "You are a Vault SECRETS specialist — you own KV enumeration, secret "
        "exfiltration (API-level and storage-level), TTL auditing, and PKI/Transit "
        "key extraction. "
        "Your tools: run_kv_enumeration, run_ttl_audit, run_secret_exfiltration, "
        "list_active_modules, run_active_module, run_raw_vault_request. "
        "METHODOLOGY: enumerate KV paths first → identify high-value targets → "
        "exfiltrate secrets → flag long-lived or unlimited TTLs."
    ),
    "database": (
        "You are a DATABASE specialist — you own dynamic database credential "
        "harvesting, database connection pivoting, and destructive DB exploitation. "
        "Your tools: run_database_credential_harvest, run_raw_vault_request, "
        "list_active_modules, run_active_module. "
        "METHODOLOGY: discover database mounts → harvest dynamic credentials → "
        "flag admin/DBA roles → optionally pivot to the actual database."
    ),
    "cloud": (
        "You are a CLOUD specialist — you own cloud IAM key exfiltration, "
        "cloud resource enumeration, and cloud exploitation. "
        "Your tools: run_cloud_key_exfiltration, run_auth_config_audit, "
        "run_raw_vault_request, list_active_modules, run_active_module. "
        "METHODOLOGY: locate cloud secrets engines → exfiltrate IAM keys → "
        "validate against the cloud provider → enumerate resources."
    ),
    "persistence": (
        "You are a PERSISTENCE specialist — you own backdoor installation "
        "(AppRole, Kubernetes, LDAP) and audit log evasion. "
        "Your tools: list_active_modules, run_active_module, "
        "run_raw_vault_request. "
        "METHODOLOGY: install backdoor auth methods → verify persistence → "
        "disable audit devices to cover tracks."
    ),
    "seal": (
        "You are a SEAL specialist — you own Vault seal/unseal operations "
        "and unseal key discovery. "
        "Your tools: list_active_modules, run_active_module, "
        "run_raw_vault_request. "
        "METHODOLOGY: check seal status → find unseal keys → seal/unseal "
        "as needed for DoS or recovery."
    ),
    "pivot": (
        "You are a PIVOT specialist — you own cross-service lateral movement "
        "from Vault to backend infrastructure (DB → OS → Infrastructure). "
        "Your tools: list_active_modules, run_active_module, "
        "run_raw_vault_request. "
        "METHODOLOGY: take harvested credentials → connect to backend → "
        "escalate to OS shell → pivot to filesystem/network."
    ),
    "general": (
        "You are a GENERALIST Vault specialist — you handle reconnaissance, "
        "CVE scanning, unauthenticated attacks, TTL auditing, and any tool "
        "not covered by a narrower domain specialist. "
        "Your tools: run_unauthenticated_recon, run_hijack_scan, run_env_scan, "
        "run_kv_enumeration, run_ttl_audit, run_policy_auditor, "
        "read_single_policy, run_priv_esc_scan, run_auth_config_audit, "
        "run_raw_vault_request, list_active_modules, run_active_module. "
        "METHODOLOGY: start with recon → identify the attack surface → "
        "hand off to domain specialists for deeper exploitation."
    ),
}


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------


@dataclass
class SpecialistResult:
    """Result from a single specialist agent's execution."""

    domain: str
    status: str = "completed"  # completed | partial | failed
    steps_total: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    steps_skipped: int = 0
    findings: list[dict] = field(default_factory=list)
    escalated: bool = False
    new_tokens: list[str] = field(default_factory=list)
    new_credentials: int = 0
    execution_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Specialist agent
# ---------------------------------------------------------------------------


class SpecialistAgent:
    """Execute a list of planned steps within a single domain.

    Parameters
    ----------
    domain:
        One of the 8 domain labels (``"token"``, ``"secrets"``, ``"database"``,
        ``"cloud"``, ``"persistence"``, ``"seal"``, ``"pivot"``, ``"general"``).
    vault_addr:
        Target Vault URL.  Injected into step params when missing.
    token:
        Initial Vault token.  May be overridden by the global store at runtime.
    tool_executor:
        Async callable ``(tool_name, params) -> str``.  Usually
        ``ChatUI._execute_tool`` or a mock in tests.
    """

    def __init__(
        self,
        domain: str,
        vault_addr: str = "",
        token: str = "",
        tool_executor: Callable[..., Any] | None = None,
    ):
        if domain not in DOMAIN_PROMPTS:
            raise ValueError(
                f"Unknown domain '{domain}'. Valid domains: "
                f"{sorted(DOMAIN_PROMPTS.keys())}"
            )
        self.domain = domain
        self.vault_addr = vault_addr
        self.token = token
        self._executor = tool_executor

        # Build filtered tool list
        self._tools = self._build_tool_list()
        self._system_prompt = DOMAIN_PROMPTS[domain]

    # ── tool filtering ───────────────────────────────────────────────────

    def _build_tool_list(self) -> list[ToolDef]:
        """Return the subset of ALL_TOOLS relevant to this domain.

        Includes:
        * Universal tools (``"*"`` sentinel in TOOL_DOMAIN_MAP)
        * Tools whose domain set contains this specialist's domain
        """
        result: list[ToolDef] = []
        for tool in ALL_TOOLS:
            domains = TOOL_DOMAIN_MAP.get(tool.name)
            if domains is None:
                continue  # tool not in the map — skip
            if "*" in domains or self.domain in domains:
                result.append(tool)
        return result

    @property
    def tool_names(self) -> list[str]:
        """Convenience: list of tool names available to this specialist."""
        return [t.name for t in self._tools]

    @property
    def system_prompt(self) -> str:
        """Domain-specific system prompt for LLM reasoning (if needed)."""
        return self._system_prompt

    # ── execution ────────────────────────────────────────────────────────

    async def execute_steps(
        self, steps: list[Any]  # PlannedStep-like objects
    ) -> SpecialistResult:
        """Execute *steps* sequentially within this domain.

        Parameters
        ----------
        steps:
            List of objects with ``tool``, ``params``, ``reason``,
            ``on_failure``, and ``max_retries`` attributes
            (typically :class:`PlannedStep` instances).

        Returns
        -------
        :class:`SpecialistResult` with aggregated metrics and findings.
        """
        started = time.monotonic()
        result = SpecialistResult(domain=self.domain)
        result.steps_total = len(steps)

        # Snapshot pre-execution token power for escalation detection
        prev_best_power = self._current_best_power()

        for step in steps:
            tool_name = getattr(step, "tool", "")
            params = dict(getattr(step, "params", {}) or {})
            max_retries = getattr(step, "max_retries", 1)

            # Inject vault_addr / token
            if self.vault_addr and "vault_addr" not in params:
                params["vault_addr"] = self.vault_addr
            best_token = self._best_token()
            if best_token and "token" not in params:
                params["token"] = best_token

            # Execute with retry
            step_ok = False
            for attempt in range(max_retries + 1):
                try:
                    if self._executor:
                        raw = await self._executor(tool_name, params)
                    else:
                        raw = json.dumps({
                            "status": "error",
                            "message": "no tool executor configured",
                        })
                except Exception as exc:
                    raw = json.dumps({"status": "error", "message": str(exc)})

                status = self._parse_status(raw)
                if status in ("success", "completed"):
                    result.steps_succeeded += 1
                    step_ok = True
                    # Scan for escalations in the raw result
                    self._scan_for_escalation(raw)
                    # Extract findings
                    findings = self._extract_findings(raw)
                    result.findings.extend(findings)
                    break
                elif status in ("skipped", "blocked"):
                    result.steps_skipped += 1
                    step_ok = True  # not a real failure
                    break
                else:
                    if attempt < max_retries:
                        continue
                    result.steps_failed += 1
                    on_failure = getattr(step, "on_failure", "abort") or "abort"
                    result.errors.append(
                        f"{tool_name}: {raw[:200]}"
                    )
                    if on_failure == "abort":
                        result.status = "failed"
                        result.execution_time_ms = (time.monotonic() - started) * 1000
                        return result
                    # "skip" or "continue" → move to next step

        # Check for escalation
        new_best_power = self._current_best_power()
        result.escalated = (
            _power_rank(new_best_power) > _power_rank(prev_best_power)
        )

        if result.steps_failed > 0 and result.steps_succeeded > 0:
            result.status = "partial"
        elif result.steps_total == 0:
            result.status = "completed"

        result.execution_time_ms = (time.monotonic() - started) * 1000
        return result

    # ── ReAct loop (LLM-powered) ────────────────────────────────────────

    async def run_with_llm(
        self,
        steps: list[Any],
        llm_client: Any | None = None,
        max_iterations: int = 8,
        temperature: float = 0.3,
    ) -> SpecialistResult:
        """Execute *steps* using a ReAct loop: Think → Act → Observe → Adapt.

        The specialist receives its domain system prompt, the list of planned
        steps, and access to its domain-filtered tools.  It uses an LLM to
        decide **which** tool to call **when**, observes results, and adapts
        its strategy accordingly.

        Parameters
        ----------
        steps:
            Planned steps (same format as :meth:`execute_steps`).
        llm_client:
            :class:`LLMClient` instance.  If ``None``, falls back to
            :meth:`execute_steps` (direct mode).
        max_iterations:
            Maximum ReAct loop iterations (safety limit).
        temperature:
            LLM temperature for tool-calling decisions.

        Returns
        -------
        :class:`SpecialistResult` with aggregated findings and metrics.
        """
        # ── Fall back to direct mode when no LLM is available ──────────
        if llm_client is None:
            return await self.execute_steps(steps)

        started = time.monotonic()
        result = SpecialistResult(domain=self.domain)
        result.steps_total = len(steps)
        prev_best_power = self._current_best_power()

        # ── Build the ReAct system prompt ──────────────────────────────
        step_descriptions = self._format_steps_for_llm(steps)
        tool_descriptions = self._format_tools_for_llm()

        system_prompt = (
            f"{self._system_prompt}\n\n"
            f"## TARGET\n"
            f"Vault address: {self.vault_addr or 'not set'}\n"
            f"Best available token power: {self._current_best_power()}\n\n"
            f"## ASSIGNED STEPS (pre-planned for your domain)\n"
            f"{step_descriptions}\n\n"
            f"## AVAILABLE TOOLS (DOMAIN-FILTERED)\n"
            f"{tool_descriptions}\n\n"
            f"## RULES\n"
            f"1. Execute the assigned steps in the most logical order.\n"
            f"2. Use ONLY the tools listed above — do not invent tools.\n"
            f"3. After each tool call, OBSERVE the result before deciding the next step.\n"
            f"4. If a tool returns an error or 'denied', try an alternative approach.\n"
            f"5. If you discover new tokens, automatically escalate and use them.\n"
            f"6. Stop after {max_iterations} tool calls maximum.\n"
            f"7. When all steps are done (or you cannot proceed further), respond with "
            f"a structured FINAL SUMMARY containing:\n"
            f"   - What you accomplished\n"
            f"   - Key findings discovered\n"
            f"   - Whether escalation occurred\n"
            f"   - Any errors encountered\n"
            f"8. Use markdown tables for structured data.\n"
            f"9. Be concise — this is automated pentesting, not a tutorial.\n"
        )

        # ── Build LLM-compatible tool list ─────────────────────────────
        llm_tools = [
            t.to_openai_function() if hasattr(t, 'to_openai_function')
            else t
            for t in self._tools
        ]

        messages: list[dict] = [
            {"role": "user", "content": (
                f"Execute the assigned {self.domain} domain steps against "
                f"{self.vault_addr or 'the target'}. Start with the first "
                f"logical tool call."
            )}
        ]

        # ── ReAct loop ─────────────────────────────────────────────────
        iteration = 0
        completed_steps: set[str] = set()
        tool_call_history: list[str] = []

        while iteration < max_iterations:
            iteration += 1

            try:
                # Call LLM in a thread to avoid blocking the event loop
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: llm_client.chat(
                        system_prompt=system_prompt,
                        messages=messages,
                        tools=llm_tools,
                        temperature=temperature,
                        max_tokens=2048,
                    )
                )
            except Exception as exc:
                result.errors.append(f"LLM call failed (iteration {iteration}): {exc}")
                break

            # ── No tool calls → agent is done ──────────────────────────
            tool_calls = response.get("tool_calls")
            if not tool_calls:
                content = response.get("content", "")
                if content:
                    # Agent is giving final summary
                    messages.append({"role": "assistant", "content": content})
                    result.findings.append({
                        "severity": "INFO",
                        "title": f"[{self.domain}] Specialist summary",
                        "description": content[:1000],
                        "module": f"specialist.{self.domain}",
                    })
                break

            # ── Execute each tool call ──────────────────────────────────
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool_args = tc.get("arguments", {})
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                # Inject vault_addr / token
                if self.vault_addr and "vault_addr" not in tool_args:
                    tool_args["vault_addr"] = self.vault_addr
                best = self._best_token()
                if best and "token" not in tool_args:
                    tool_args["token"] = best

                # Prevent duplicate identical calls
                call_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
                if call_key in tool_call_history:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", f"call_{iteration}"),
                        "content": json.dumps({
                            "status": "skipped",
                            "message": "Duplicate call — already executed with same params.",
                        }),
                    })
                    continue
                tool_call_history.append(call_key)

                # Execute
                try:
                    if self._executor:
                        raw_result = await self._executor(tool_name, tool_args)
                    else:
                        raw_result = json.dumps({
                            "status": "error",
                            "message": "no tool executor configured",
                        })
                except Exception as exc:
                    raw_result = json.dumps({"status": "error", "message": str(exc)})

                # Parse result
                status = self._parse_status(raw_result)
                findings = self._extract_findings(raw_result)
                self._scan_for_escalation(raw_result)

                # Track
                if status in ("success", "completed"):
                    result.steps_succeeded += 1
                    completed_steps.add(tool_name)
                elif status in ("skipped", "blocked"):
                    result.steps_skipped += 1
                else:
                    result.steps_failed += 1

                result.findings.extend(findings)

                # Truncate long results for the LLM context window
                truncated = raw_result
                if len(raw_result) > 2000:
                    truncated = raw_result[:2000] + f"\n... [truncated {len(raw_result) - 2000} chars]"

                # Feed result back to LLM
                messages.append({
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": tc.get("id", f"call_{iteration}"),
                        "name": tool_name,
                        "arguments": tool_args,
                    }],
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{iteration}"),
                    "content": truncated,
                })

        # ── Finalize ───────────────────────────────────────────────────
        new_best_power = self._current_best_power()
        result.escalated = _power_rank(new_best_power) > _power_rank(prev_best_power)

        if result.steps_failed > 0 and result.steps_succeeded > 0:
            result.status = "partial"
        elif result.steps_total == 0:
            result.status = "completed"
        elif result.steps_failed > 0 and result.steps_succeeded == 0:
            result.status = "failed"

        result.new_tokens = self._collect_new_tokens()
        result.execution_time_ms = (time.monotonic() - started) * 1000
        return result

    # ── internal helpers ─────────────────────────────────────────────────

    def _format_steps_for_llm(self, steps: list[Any]) -> str:
        """Render assigned steps as a concise table for the LLM prompt."""
        if not steps:
            return "(no pre-planned steps — use your domain expertise to explore)"

        lines = ["| # | Tool | Reason | Risk |", "|---|------|--------|------|"]
        for i, step in enumerate(steps, 1):
            tool = getattr(step, "tool", "unknown")
            reason = getattr(step, "reason", "")[:80]
            risk = getattr(step, "risk", "read_only")
            lines.append(f"| {i} | {tool} | {reason} | {risk} |")
        return "\n".join(lines)

    def _format_tools_for_llm(self) -> str:
        """Render available tools as a concise list for the LLM prompt."""
        lines = []
        for tool in self._tools:
            params = ", ".join(
                f"{p.name}:{p.type}"
                for p in tool.parameters[:5]
            ) if tool.parameters else "no params"
            lines.append(
                f"- **{tool.name}**({params})\n"
                f"  {tool.description[:150]}"
            )
        return "\n".join(lines)

    def _collect_new_tokens(self) -> list[str]:
        """Collect newly discovered tokens from the global store."""
        try:
            from ai_core.dynamic_session import global_store
            return [
                t.token[:24] + "..."
                for t in global_store.tokens.values()
                if t.source == self.domain
            ]
        except Exception:
            return []

    def _parse_status(self, raw_result: str) -> str:
        """Extract status field from a JSON tool result."""
        try:
            data = json.loads(raw_result)
            return data.get("status", "unknown")
        except (json.JSONDecodeError, TypeError):
            return "unknown"

    def _extract_findings(self, raw_result: str) -> list[dict]:
        """Pull findings out of a JSON tool result."""
        try:
            data = json.loads(raw_result)
            return data.get("findings", [])
        except (json.JSONDecodeError, TypeError):
            return []

    def _scan_for_escalation(self, raw_result: str) -> None:
        """Check *raw_result* for new tokens and feed them to the global store."""
        try:
            from ai_core.dynamic_session import global_store

            # Let the store's own parser do the heavy lifting; tokens are
            # registered with this specialist's domain as the source so
            # _collect_new_tokens() can attribute them later.
            global_store.parse_tool_result(self.domain, raw_result)
        except ImportError:
            pass

    def _best_token(self) -> str | None:
        """Return the best token available right now."""
        if self.token:
            return self.token
        try:
            from ai_core.dynamic_session import global_store
            best = global_store.get_best_token_value()
            if best:
                return best
        except ImportError:
            pass
        return self.token or None

    def _current_best_power(self) -> str:
        """Snapshot the current best token power level."""
        try:
            from ai_core.dynamic_session import global_store
            best = global_store.get_best_token()
            if best:
                return best.power_level
        except ImportError:
            pass
        return "none"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POWER_ORDER = {"root": 5, "sudo": 4, "high": 3, "elevated": 2, "user": 1,
                "unknown": 0, "none": -1}


def _power_rank(level: str) -> int:
    return _POWER_ORDER.get(level, 0)
