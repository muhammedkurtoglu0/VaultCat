"""Tests for ai_core.agent — PentestAgent, PhaseTracker, guards."""

import json
from unittest.mock import AsyncMock

import pytest

from ai_core.agent import (
    AttackPhase,
    PentestAgent,
    PhaseTracker,
)
from tests.conftest import FAKE_VAULT_ADDR, FAKE_TOKEN


# ---------------------------------------------------------------------------
# PhaseTracker
# ---------------------------------------------------------------------------


class TestPhaseTracker:
    def test_initial_phase_is_recon(self):
        pt = PhaseTracker()
        assert pt.current_phase == AttackPhase.RECON

    def test_forward_transition_succeeds(self):
        pt = PhaseTracker()
        assert pt.transition_to(AttackPhase.AUDIT)
        assert pt.current_phase == AttackPhase.AUDIT

    def test_backward_transition_fails(self):
        pt = PhaseTracker()
        pt.transition_to(AttackPhase.AUDIT)
        assert not pt.transition_to(AttackPhase.RECON)  # can't go back

    def test_artifacts(self):
        pt = PhaseTracker()
        pt.record_artifact("token", "hvs.test")
        assert pt.get_artifact("token") == "hvs.test"
        assert pt.get_artifact("nonexistent") is None

    def test_summary(self):
        pt = PhaseTracker()
        summary = pt.summary()
        assert "recon" in summary
        assert "Completed" in summary


# ---------------------------------------------------------------------------
# PentestAgent — guards
# ---------------------------------------------------------------------------


class TestAgentGuards:
    @pytest.fixture
    def agent(self):
        return PentestAgent(
            vault_addr=FAKE_VAULT_ADDR,
            token=FAKE_TOKEN,
            provider="openai",
        )

    def test_guard_blocks_fake_token(self, agent):
        blocked = agent._guard_tool_call(
            "run_capability_audit",
            {"vault_addr": FAKE_VAULT_ADDR, "token": "your_token_here"},
        )
        assert blocked is not None
        assert "FAKE TOKEN" in blocked

    def test_guard_blocks_placeholder_token(self, agent: PentestAgent):
        blocked = agent._guard_tool_call(
            "run_capability_audit",
            {"vault_addr": FAKE_VAULT_ADDR, "token": "s.xxx"},
        )
        assert blocked is not None

    def test_guard_blocks_fake_ip(self, agent: PentestAgent):
        blocked = agent._guard_tool_call(
            "run_unauthenticated_recon",
            {"vault_addr": "http://192.168.1.100:8200"},
        )
        # Should inject real target when available
        assert blocked is None  # falls through to injection logic

    def test_guard_injects_real_target(self, agent: PentestAgent):
        blocked = agent._guard_tool_call(
            "run_unauthenticated_recon",
            {"vault_addr": "http://10.0.0.1:8200"},
        )
        assert blocked is None  # real target injected

    def test_guard_injects_real_token(self, agent: PentestAgent):
        blocked = agent._guard_tool_call(
            "run_capability_audit",
            {"vault_addr": FAKE_VAULT_ADDR, "token": "fake"},
        )
        # After blocking fake token, next call should inject real token
        blocked2 = agent._guard_tool_call(
            "run_capability_audit",
            {"vault_addr": FAKE_VAULT_ADDR},
        )
        assert blocked2 is None

    def test_guard_blocks_tool_without_target(self):
        agent = PentestAgent(provider="openai")  # no vault_addr set
        blocked = agent._guard_tool_call(
            "run_unauthenticated_recon",
            {},
        )
        assert blocked is not None
        assert "target" in blocked.lower()

    def test_guard_blocks_tool_without_token(self):
        agent = PentestAgent(vault_addr=FAKE_VAULT_ADDR, provider="openai")  # no token
        blocked = agent._guard_tool_call(
            "run_capability_audit",
            {"vault_addr": FAKE_VAULT_ADDR},
        )
        assert blocked is not None
        assert "token" in blocked.lower()

    def test_guard_blocks_duplicate_recon(self, agent: PentestAgent):
        # First call passes
        blocked1 = agent._guard_tool_call(
            "run_unauthenticated_recon",
            {},
        )
        assert blocked1 is None
        # Second call blocked
        blocked2 = agent._guard_tool_call(
            "run_unauthenticated_recon",
            {},
        )
        assert blocked2 is not None
        assert "ALREADY COMPLETED" in blocked2

    def test_guard_blocks_duplicate_get_findings(self, agent: PentestAgent):
        blocked1 = agent._guard_tool_call("get_findings", {})
        assert blocked1 is None
        blocked2 = agent._guard_tool_call("get_findings", {})
        assert blocked2 is not None
        assert "Already called" in blocked2


# ---------------------------------------------------------------------------
# PentestAgent — helpers
# ---------------------------------------------------------------------------


class TestAgentHelpers:
    @pytest.fixture
    def agent(self):
        return PentestAgent(
            vault_addr=FAKE_VAULT_ADDR,
            token=FAKE_TOKEN,
            provider="openai",
        )

    def test_summarize_result_with_findings(self, agent: PentestAgent):
        result = json.dumps({
            "status": "completed",
            "findings": [
                {"severity": "CRITICAL", "title": "Token can create tokens"},
                {"severity": "HIGH", "title": "HTTP used"},
            ],
        })
        summary = agent._summarize_result(result)
        assert "Status: completed" in summary
        assert "2 findings" in summary
        assert "KEY:" in summary

    def test_summarize_result_with_risk(self, agent: PentestAgent):
        result = json.dumps({
            "status": "completed",
            "risk_score": 85,
            "risk_grade": "B",
        })
        summary = agent._summarize_result(result)
        assert "Risk: 85/100 (B)" in summary

    def test_build_context_message(self, agent: PentestAgent):
        msg = agent._build_context_message("Test the vault")
        assert "Test the vault" in msg
        assert FAKE_VAULT_ADDR in msg

    def test_is_completion_marker_true(self):
        assert PentestAgent._is_completion_marker(
            "Task complete. Here is a summary of all findings from the "
            "penetration test. We discovered several critical vulnerabilities "
            "including exposed tokens and weak TLS configuration."
        )

    def test_is_completion_marker_false_short(self):
        assert not PentestAgent._is_completion_marker("task complete")


# ---------------------------------------------------------------------------
# PentestAgent — plan execution controls
# ---------------------------------------------------------------------------


class TestAgentPlanControls:
    @pytest.fixture
    def agent(self):
        return PentestAgent(provider="openai")

    def test_pause_resume(self, agent: PentestAgent):
        assert agent._paused_flag.is_set()
        agent.pause()
        assert not agent._paused_flag.is_set()
        # resume clears
        import asyncio
        asyncio.run(agent.resume())
        assert agent._paused_flag.is_set()

    def test_abort(self, agent: PentestAgent):
        agent.abort()
        assert agent._aborted_flag
        assert agent._paused_flag.is_set()  # unblocked so loop can see abort

    def test_max_turns(self, agent: PentestAgent):
        assert agent.MAX_TURNS == 50

    def test_max_plan_tool_calls(self, agent: PentestAgent):
        assert agent.MAX_PLAN_TOOL_CALLS == 15
