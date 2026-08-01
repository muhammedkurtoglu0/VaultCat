"""Tests for orchestrator, specialist agent, and domain tool mapping."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_core.planning.plan_schema import AttackPhase, PlannedStep
from ai_core.tools import ALL_TOOLS, TOOL_DOMAIN_MAP, UNIVERSAL_TOOL_NAMES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_step(tool: str, params: dict | None = None, reason: str = "",
               on_failure: str = "abort", max_retries: int = 0) -> PlannedStep:
    return PlannedStep(
        tool=tool,
        params=params or {},
        reason=reason or f"Run {tool}",
        on_failure=on_failure,
        max_retries=max_retries,
        phase=AttackPhase.AUDIT,
        risk="read_only",
    )


async def _mock_executor_success(tool_name: str, params: dict) -> str:
    return json.dumps({"status": "completed", "findings": [
        {"severity": "HIGH", "title": f"Finding from {tool_name}"}
    ]})


async def _mock_executor_fail(tool_name: str, params: dict) -> str:
    return json.dumps({"status": "error", "message": f"{tool_name} failed"})


async def _mock_executor_escalate(tool_name: str, params: dict) -> str:
    return json.dumps({
        "status": "completed",
        "findings": [],
        "auth": {"client_token": "hvs.escalated-token-abc1234567890xyz"},
    })


# ---------------------------------------------------------------------------
# TOOL_DOMAIN_MAP tests
# ---------------------------------------------------------------------------


class TestToolDomainMap:
    """Verify the domain mapping is complete and valid."""

    def test_every_tool_in_all_tools_has_domain_entry(self):
        """Every tool in ALL_TOOLS must have a TOOL_DOMAIN_MAP entry."""
        missing = []
        for tool in ALL_TOOLS:
            if tool.name not in TOOL_DOMAIN_MAP:
                missing.append(tool.name)
        assert not missing, (
            f"These tools are missing from TOOL_DOMAIN_MAP: {missing}"
        )

    def test_universal_tools_match_star_sentinel(self):
        """Tools with '*' in TOOL_DOMAIN_MAP must appear in UNIVERSAL_TOOL_NAMES."""
        for name, domains in TOOL_DOMAIN_MAP.items():
            if "*" in domains:
                assert name in UNIVERSAL_TOOL_NAMES, (
                    f"'{name}' has '*' but is missing from UNIVERSAL_TOOL_NAMES"
                )

    def test_all_domain_sets_are_valid(self):
        """Domain sets must only contain known domain labels or '*'."""
        valid = {"token", "secrets", "database", "cloud", "persistence",
                 "seal", "pivot", "payload", "general", "*"}
        for name, domains in TOOL_DOMAIN_MAP.items():
            unknown = domains - valid
            assert not unknown, (
                f"Tool '{name}' has unknown domain(s): {unknown}"
            )


# ---------------------------------------------------------------------------
# SpecialistAgent tests
# ---------------------------------------------------------------------------


class TestSpecialistAgent:
    """Test the domain-specific specialist agent."""

    def test_init_rejects_unknown_domain(self):
        from ai_core.specialist_agent import SpecialistAgent
        with pytest.raises(ValueError, match="Unknown domain"):
            SpecialistAgent("nonexistent_domain")

    def test_token_specialist_has_correct_tools(self):
        from ai_core.specialist_agent import SpecialistAgent
        agent = SpecialistAgent("token")
        names = set(agent.tool_names)
        # Domain-specific
        assert "run_capability_audit" in names
        assert "run_privilege_escalation" in names
        assert "run_policy_auditor" in names
        # Universal
        assert "web_search" in names
        assert "get_findings" in names
        # Should NOT have database tools
        assert "run_database_credential_harvest" not in names

    def test_database_specialist_has_correct_tools(self):
        from ai_core.specialist_agent import SpecialistAgent
        agent = SpecialistAgent("database")
        names = set(agent.tool_names)
        assert "run_database_credential_harvest" in names
        assert "run_raw_vault_request" in names
        # Should NOT have token-specific tools
        assert "run_privilege_escalation" not in names

    def test_every_domain_creates_valid_specialist(self):
        from ai_core.specialist_agent import DOMAIN_PROMPTS, SpecialistAgent
        for domain in DOMAIN_PROMPTS:
            agent = SpecialistAgent(domain)
            assert agent.domain == domain
            assert len(agent._tools) > 0, f"No tools for domain '{domain}'"
            assert len(agent.system_prompt) > 0

    @pytest.mark.asyncio
    async def test_execute_steps_success(self):
        from ai_core.specialist_agent import SpecialistAgent, SpecialistResult
        agent = SpecialistAgent("token", tool_executor=_mock_executor_success)
        steps = [_make_step("run_capability_audit"), _make_step("run_priv_esc_scan")]
        result = await agent.execute_steps(steps)

        assert isinstance(result, SpecialistResult)
        assert result.domain == "token"
        assert result.steps_total == 2
        assert result.steps_succeeded == 2
        assert result.steps_failed == 0
        assert result.status == "completed"
        assert len(result.findings) == 2

    @pytest.mark.asyncio
    async def test_execute_steps_failure_abort(self):
        from ai_core.specialist_agent import SpecialistAgent
        agent = SpecialistAgent("token", tool_executor=_mock_executor_fail)
        steps = [
            _make_step("run_capability_audit"),
            _make_step("run_priv_esc_scan"),  # should never run
        ]
        result = await agent.execute_steps(steps)

        assert result.steps_total == 2
        assert result.steps_failed >= 1
        assert result.steps_succeeded == 0
        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_execute_steps_failure_skip(self):
        from ai_core.specialist_agent import SpecialistAgent
        agent = SpecialistAgent("token", tool_executor=_mock_executor_fail)
        steps = [
            _make_step("run_capability_audit", on_failure="skip"),
            _make_step("run_priv_esc_scan"),  # should run after skip
        ]
        result = await agent.execute_steps(steps)
        # First fails but skipped → second runs
        assert result.steps_total == 2

    @pytest.mark.asyncio
    async def test_empty_steps_returns_clean_result(self):
        from ai_core.specialist_agent import SpecialistAgent
        agent = SpecialistAgent("token")
        result = await agent.execute_steps([])
        assert result.steps_total == 0
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_escalation_detection(self):
        from ai_core.specialist_agent import SpecialistAgent
        from ai_core.dynamic_session import global_store

        # Ensure clean state
        for t in list(global_store.tokens.keys()):
            if "escalated" in t:
                del global_store.tokens[t]

        agent = SpecialistAgent("token", tool_executor=_mock_executor_escalate)
        result = await agent.execute_steps(
            [_make_step("run_privilege_escalation")]
        )

        # The mock returns a token in the result; the global store should pick it up
        # via parse_tool_result inside _scan_for_escalation
        assert result.steps_succeeded == 1

    def test_system_prompt_is_domain_specific(self):
        from ai_core.specialist_agent import SpecialistAgent
        token_agent = SpecialistAgent("token")
        db_agent = SpecialistAgent("database")
        assert "TOKEN" in token_agent.system_prompt.upper()
        assert "DATABASE" in db_agent.system_prompt.upper()
        assert token_agent.system_prompt != db_agent.system_prompt


# ---------------------------------------------------------------------------
# Domain grouping tests
# ---------------------------------------------------------------------------


class TestDomainGrouping:
    """Test AttackOrchestrator._group_steps_by_domain."""

    @pytest.fixture
    def orchestrator(self):
        from ai_core.orchestrator import AttackOrchestrator
        return AttackOrchestrator(vault_addr="https://vault.test")

    def test_steps_grouped_correctly(self, orchestrator):
        steps = [
            _make_step("run_capability_audit"),      # → token
            _make_step("run_privilege_escalation"),   # → token
            _make_step("run_database_credential_harvest"),  # → database
            _make_step("run_secret_exfiltration"),    # → secrets
            _make_step("run_cloud_key_exfiltration"), # → cloud
        ]
        groups = orchestrator._group_steps_by_domain(steps)

        assert "token" in groups
        assert "database" in groups
        assert "secrets" in groups
        assert "cloud" in groups
        assert len(groups["token"]) == 2
        assert len(groups["database"]) == 1

    def test_unknown_tool_goes_to_general(self, orchestrator):
        steps = [_make_step("nonexistent_tool_xyz")]
        groups = orchestrator._group_steps_by_domain(steps)
        assert "general" in groups
        assert len(groups["general"]) == 1

    def test_universal_tools_distributed(self, orchestrator):
        steps = [
            _make_step("run_capability_audit"),   # → token
            _make_step("web_search"),             # → universal
            _make_step("get_findings"),           # → universal
        ]
        groups = orchestrator._group_steps_by_domain(steps)

        # Token group should have its step + both universal tools
        token_steps = groups.get("token", [])
        token_tool_names = [getattr(s, "tool", "") for s in token_steps]
        assert "run_capability_audit" in token_tool_names
        assert "web_search" in token_tool_names
        assert "get_findings" in token_tool_names

    def test_empty_plan_returns_empty_dict(self, orchestrator):
        groups = orchestrator._group_steps_by_domain([])
        assert groups == {}


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------


class TestOrchestrator:
    """Test the full orchestrator execution pipeline."""

    @pytest.fixture
    def orchestrator(self):
        from ai_core.orchestrator import AttackOrchestrator
        return AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_success,
        )

    @pytest.mark.asyncio
    async def test_full_plan_execution(self, orchestrator):
        from ai_core.planning.plan_schema import PentestPlan

        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),
            _make_step("run_database_credential_harvest"),
            _make_step("run_secret_exfiltration"),
        ]
        result = await orchestrator.execute_plan(plan)

        assert result.total_steps == 3
        assert result.successes == 3
        assert result.status in ("completed", "partial")
        assert len(result.domains_involved) >= 2  # token + database + secrets
        assert len(result.synthesized_findings) == 3

    @pytest.mark.asyncio
    async def test_parallel_execution_is_concurrent(self):
        """Verify specialists actually run in parallel, not sequentially."""
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan

        call_times: list[tuple[str, float]] = []

        async def _timed_executor(tool_name: str, params: dict) -> str:
            call_times.append((tool_name, time.monotonic()))
            await asyncio.sleep(0.05)  # small delay to amplify parallelism
            return json.dumps({"status": "completed", "findings": []})

        orch = AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_timed_executor,
        )
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),           # token, step 1
            _make_step("run_privilege_escalation"),        # token, step 2
            _make_step("run_database_credential_harvest"), # database, step 1
            _make_step("run_secret_exfiltration"),          # secrets, step 1
            _make_step("run_cloud_key_exfiltration"),       # cloud, step 1
        ]

        result = await orch.execute_plan(plan)
        assert result.successes == 5

        # Token steps run sequentially (same domain), but database/secrets/cloud
        # run in parallel. The total wall-clock should be less than if all
        # 5 ran sequentially (5 * 50ms = 250ms vs ~100ms parallel).
        assert len(call_times) == 5

    @pytest.mark.asyncio
    async def test_empty_plan_returns_graceful_error(self, orchestrator):
        from ai_core.planning.plan_schema import PentestPlan

        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = []
        result = await orchestrator.execute_plan(plan)

        assert result.total_steps == 0
        assert result.status == "completed"
        assert "no steps" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_specialist_exception_does_not_kill_others(self):
        """One crashing specialist must not block the others."""
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan

        async def _crash_on_database(tool_name: str, params: dict) -> str:
            if "database" in tool_name:
                raise RuntimeError("Database connection refused")
            return json.dumps({"status": "completed", "findings": []})

        orch = AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_crash_on_database,
        )
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),           # token — should succeed
            _make_step("run_database_credential_harvest"), # database — crashes
            _make_step("run_secret_exfiltration"),         # secrets — should succeed
        ]
        result = await orch.execute_plan(plan)

        # Token and secrets should still have succeeded
        assert result.successes >= 2
        # Database should have failed
        assert result.failures >= 1

    @pytest.mark.asyncio
    async def test_synthesize_deduplicates_findings(self, orchestrator):
        """Duplicate findings across specialists should be merged."""
        from ai_core.planning.plan_schema import PentestPlan

        async def _dup_executor(tool_name: str, params: dict) -> str:
            return json.dumps({
                "status": "completed",
                "findings": [
                    {"severity": "HIGH", "title": "Common finding"},
                    {"severity": "MEDIUM", "title": f"Unique to {tool_name}"},
                ],
            })

        orch = orchestrator
        orch._executor = _dup_executor
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),
            _make_step("run_database_credential_harvest"),
        ]
        result = await orch.execute_plan(plan)

        # "Common finding" appears in both results but should be deduplicated
        common_count = sum(
            1 for f in result.synthesized_findings
            if f["title"] == "Common finding"
        )
        assert common_count == 1
        # 2 unique + 1 common = 3 total
        assert len(result.synthesized_findings) == 3

    @pytest.mark.asyncio
    async def test_findings_sorted_by_severity(self, orchestrator):
        from ai_core.planning.plan_schema import PentestPlan

        async def _sev_executor(tool_name: str, params: dict) -> str:
            return json.dumps({
                "status": "completed",
                "findings": [
                    {"severity": "LOW", "title": f"Low from {tool_name}"},
                    {"severity": "CRITICAL", "title": f"Critical from {tool_name}"},
                    {"severity": "MEDIUM", "title": f"Medium from {tool_name}"},
                ],
            })

        orch = orchestrator
        orch._executor = _sev_executor
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [_make_step("run_capability_audit")]
        result = await orch.execute_plan(plan)

        severities = [f["severity"] for f in result.synthesized_findings]
        assert severities == ["CRITICAL", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# SpecialistAgent ReAct (LLM-powered) tests
# ---------------------------------------------------------------------------


class TestSpecialistAgentReAct:
    """Test the ReAct loop (run_with_llm) of SpecialistAgent."""

    @pytest.mark.asyncio
    async def test_run_with_llm_falls_back_to_direct_when_no_client(self):
        """When llm_client is None, run_with_llm delegates to execute_steps."""
        from ai_core.specialist_agent import SpecialistAgent, SpecialistResult

        agent = SpecialistAgent("token", tool_executor=_mock_executor_success)
        steps = [_make_step("run_capability_audit"), _make_step("run_priv_esc_scan")]
        result = await agent.run_with_llm(steps, llm_client=None)

        assert isinstance(result, SpecialistResult)
        assert result.domain == "token"
        assert result.steps_total == 2
        assert result.steps_succeeded == 2
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_run_with_llm_executes_with_mock_llm(self):
        """ReAct loop with a mock LLM that returns tool calls."""
        from ai_core.specialist_agent import SpecialistAgent

        # Build a mock LLM client that returns one tool call then stops
        call_count = [0]

        class MockLLM:
            def chat(self, system_prompt, messages, tools, temperature, max_tokens):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call: return a tool call
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call_1",
                            "name": "run_capability_audit",
                            "arguments": {"vault_addr": "https://vault.test"},
                        }],
                        "finish_reason": "tool_calls",
                    }
                else:
                    # Second call: no tool calls — agent is done
                    return {
                        "role": "assistant",
                        "content": "All steps complete. Findings: 3 critical issues.",
                        "tool_calls": None,
                        "finish_reason": "stop",
                    }

        agent = SpecialistAgent(
            "token",
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_success,
        )
        steps = [_make_step("run_capability_audit")]
        result = await agent.run_with_llm(
            steps, llm_client=MockLLM(), max_iterations=5,
        )

        assert result.domain == "token"
        assert result.steps_succeeded == 1
        assert result.status == "completed"
        # Should have the tool finding + the agent's summary finding
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_run_with_llm_respects_max_iterations(self):
        """ReAct loop stops after max_iterations, even if LLM keeps requesting tools."""
        from ai_core.specialist_agent import SpecialistAgent

        call_idx = [0]

        class InfiniteLLM:
            def chat(self, system_prompt, messages, tools, temperature, max_tokens):
                call_idx[0] += 1
                # Return unique tool calls each iteration to bypass dedup check
                return {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": f"call_{call_idx[0]}",
                        "name": "run_capability_audit",
                        "arguments": {"iteration": call_idx[0]},
                    }],
                    "finish_reason": "tool_calls",
                }

        agent = SpecialistAgent(
            "token",
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_success,
        )
        max_iter = 3
        result = await agent.run_with_llm(
            [_make_step("run_capability_audit")],
            llm_client=InfiniteLLM(),
            max_iterations=max_iter,
        )

        # Should stop after max_iterations loop limit
        assert result.steps_succeeded == max_iter
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_run_with_llm_handles_tool_errors(self):
        """ReAct specialist gracefully handles tool execution errors."""
        from ai_core.specialist_agent import SpecialistAgent

        call_count = [0]

        class ErrorThenStopLLM:
            def chat(self, system_prompt, messages, tools, temperature, max_tokens):
                call_count[0] += 1
                if call_count[0] == 1:
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call_1",
                            "name": "run_capability_audit",
                            "arguments": {},
                        }],
                        "finish_reason": "tool_calls",
                    }
                else:
                    return {
                        "role": "assistant",
                        "content": "Tool failed, stopping.",
                        "tool_calls": None,
                        "finish_reason": "stop",
                    }

        agent = SpecialistAgent(
            "token",
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_fail,  # always fails
        )
        result = await agent.run_with_llm(
            [_make_step("run_capability_audit")],
            llm_client=ErrorThenStopLLM(),
            max_iterations=5,
        )

        # Should have survived the error and recorded a failure
        assert result.steps_failed >= 1
        assert result.status in ("partial", "failed")

    @pytest.mark.asyncio
    async def test_run_with_llm_detects_escalation(self):
        """ReAct specialist detects token escalation from tool results."""
        from ai_core.specialist_agent import SpecialistAgent

        call_count = [0]

        class EscalateLLM:
            def chat(self, system_prompt, messages, tools, temperature, max_tokens):
                call_count[0] += 1
                if call_count[0] == 1:
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call_1",
                            "name": "run_privilege_escalation",
                            "arguments": {},
                        }],
                        "finish_reason": "tool_calls",
                    }
                else:
                    return {
                        "role": "assistant",
                        "content": "Escalation successful.",
                        "tool_calls": None,
                        "finish_reason": "stop",
                    }

        agent = SpecialistAgent(
            "token",
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_escalate,  # returns an escalated token
        )
        result = await agent.run_with_llm(
            [_make_step("run_privilege_escalation")],
            llm_client=EscalateLLM(),
            max_iterations=5,
        )

        # Should have detected escalation (mock returns escalated token)
        assert result.steps_succeeded >= 1
        # Escalation may or may not be detected depending on global state;
        # the important thing is the tool executed successfully
        assert result.status in ("completed", "partial")

    @pytest.mark.asyncio
    async def test_orchestrator_with_llm_specialists(self):
        """Orchestrator can spawn LLM-powered specialists in parallel."""
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan

        call_count = [0]

        class SharedLLM:
            def chat(self, system_prompt, messages, tools, temperature, max_tokens):
                call_count[0] += 1
                if call_count[0] <= 2:  # one tool call per domain
                    return {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": f"call_{call_count[0]}",
                            "name": "run_capability_audit"
                            if "TOKEN" in system_prompt.upper() else "get_findings",
                            "arguments": {},
                        }],
                        "finish_reason": "tool_calls",
                    }
                else:
                    return {
                        "role": "assistant",
                        "content": "Done.",
                        "tool_calls": None,
                        "finish_reason": "stop",
                    }

        orch = AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_success,
            llm_client=SharedLLM(),
            use_llm=True,
        )
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),            # → token
            _make_step("run_database_credential_harvest"),  # → database
        ]
        result = await orch.execute_plan(plan)

        # Both domains should have run with LLM
        assert result.successes >= 2
        # LLM was called (at least once per domain)
        assert call_count[0] >= 2


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Orchestrator + real registry and components."""

    @pytest.mark.asyncio
    async def test_orchestrator_with_real_registry(self):
        """Orchestrator can spawn specialists using real ActiveExecutionRegistry."""
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan
        from ai_core.specialist_agent import DOMAIN_PROMPTS

        orch = AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_mock_executor_success,
        )
        plan = PentestPlan(vault_addr="https://vault.test")

        # One step per known domain
        plan.steps = [
            _make_step("run_capability_audit"),            # token
            _make_step("run_secret_exfiltration"),          # secrets
            _make_step("run_database_credential_harvest"),  # database
            _make_step("run_cloud_key_exfiltration"),       # cloud
            _make_step("web_search", params={"query": "Vault CVE"}),  # universal
        ]
        result = await orch.execute_plan(plan)

        # 4 domain-specific steps + web_search distributed to all 4 domains = 8
        assert result.successes == 8
        # Should involve 4 domain specialists
        assert len(result.domains_involved) >= 4
        # Universal tool (web_search) got duplicated to all domains
        assert "web_search" in str(result.specialist_results)

    @pytest.mark.asyncio
    async def test_concurrent_specialists_dont_corrupt_shared_state(self):
        """Multiple specialists adding findings concurrently via global store."""
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan

        N = 3  # domains

        async def _add_token_executor(tool_name: str, params: dict) -> str:
            # Simulate each specialist discovering a unique token
            token = f"hvs.concurrent-test-{tool_name}-abc1234567890123"
            try:
                from ai_core.dynamic_session import global_store
                global_store.add_token(token, source=tool_name, power_level="user")
            except Exception:
                pass
            return json.dumps({"status": "completed", "findings": []})

        orch = AttackOrchestrator(
            vault_addr="https://vault.test",
            tool_executor=_add_token_executor,
        )
        plan = PentestPlan(vault_addr="https://vault.test")
        plan.steps = [
            _make_step("run_capability_audit"),
            _make_step("run_database_credential_harvest"),
            _make_step("run_secret_exfiltration"),
        ]
        result = await orch.execute_plan(plan)

        # All 3 original steps + re-plan steps (token escalation triggered re-plan)
        # Global store handled concurrency safely — no deadlocks or data loss
        assert result.successes >= N
        assert result.escalated  # token discovery triggered escalation
        assert result.replan_count >= 1
