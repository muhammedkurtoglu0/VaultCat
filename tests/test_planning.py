"""Tests for ai_core.planning — planners, factory, schema."""

import json

import pytest

from ai_core.planning import (
    AnthropicPlanner,
    DeepSeekPlanner,
    OpenAIPlanner,
    PentestPlan,
    PlannedStep,
    PlanStatus,
    TokenAssessment,
    AttackPhase,
    create_planner,
)
from tests.conftest import FAKE_VAULT_ADDR, FAKE_TOKEN, sample_enum_data


# ---------------------------------------------------------------------------
# Plan schema
# ---------------------------------------------------------------------------


class TestPentestPlan:
    def test_default_state(self):
        plan = PentestPlan()
        assert plan.status == PlanStatus.DRAFT
        assert plan.total_steps == 0
        assert plan.next_step is None
        assert not plan.is_done

    def test_with_steps(self):
        plan = PentestPlan(vault_addr=FAKE_VAULT_ADDR, risk_level="high")
        plan.steps = [
            PlannedStep(tool="run_unauthenticated_recon", reason="First recon",
                        priority=1, phase=AttackPhase.RECON),
            PlannedStep(tool="run_capability_audit", reason="Audit token",
                        priority=2, phase=AttackPhase.AUDIT),
        ]
        assert plan.total_steps == 2
        assert plan.next_step.tool == "run_unauthenticated_recon"
        plan.current_step_index = 1
        assert plan.next_step.tool == "run_capability_audit"
        plan.current_step_index = 2
        assert plan.next_step is None

    def test_completed_and_failed_are_done(self):
        plan = PentestPlan()
        plan.status = PlanStatus.COMPLETED
        assert plan.is_done
        plan.status = PlanStatus.FAILED
        assert plan.is_done
        plan.status = PlanStatus.RUNNING
        assert not plan.is_done

    def test_to_dict_roundtrip(self):
        plan = PentestPlan(
            vault_addr=FAKE_VAULT_ADDR,
            risk_level="high",
            dynamic_policies=["db-admin", "vault-operator"],
            attack_narrative="Test narrative",
            token_assessment=TokenAssessment(
                power_level="admin",
                summary="Has broad access",
                accessible_paths=["sys/mounts", "secret/"],
                escalation_possible=True,
            ),
        )
        plan.steps = [
            PlannedStep(
                tool="run_unauthenticated_recon",
                reason="Recon first",
                params={"vault_addr": FAKE_VAULT_ADDR},
                priority=1,
                expected_impact="Find exposed endpoints",
                phase=AttackPhase.RECON,
                on_failure="skip",
            ),
        ]

        d = plan.to_dict()
        plan2 = PentestPlan.from_dict(d)

        assert plan2.vault_addr == plan.vault_addr
        assert plan2.risk_level == plan.risk_level
        assert plan2.dynamic_policies == plan.dynamic_policies
        assert plan2.total_steps == 1
        assert plan2.token_assessment.power_level == "admin"
        assert plan2.token_assessment.escalation_possible is True
        assert plan2.steps[0].on_failure == "skip"

    def test_id_is_generated(self):
        plan1 = PentestPlan()
        plan2 = PentestPlan()
        assert plan1.id != plan2.id
        assert len(plan1.id) == 8


class TestPlannedStep:
    def test_defaults(self):
        step = PlannedStep(tool="test_tool", reason="test")
        assert step.priority == 1
        assert step.on_failure == "abort"
        assert step.max_retries == 1
        assert step.params == {}
        assert step.phase == AttackPhase.AUDIT
        assert step.risk == "read_only"

    def test_custom(self):
        step = PlannedStep(
            tool="run_privilege_escalation",
            reason="Escalate",
            priority=3,
            risk="state_changing",
            on_failure="retry",
            max_retries=3,
            alternative_tool="run_capability_audit",
        )
        assert step.priority == 3
        assert step.risk == "state_changing"
        assert step.on_failure == "retry"
        assert step.max_retries == 3


# ---------------------------------------------------------------------------
# Planner factory
# ---------------------------------------------------------------------------


class TestPlannerFactory:
    def test_create_openai_planner(self):
        p = create_planner("openai")
        assert isinstance(p, OpenAIPlanner)
        assert p.provider_name == "openai"

    def test_create_deepseek_planner(self):
        p = create_planner("deepseek")
        assert isinstance(p, DeepSeekPlanner)
        assert p.provider_name == "deepseek"

    def test_create_anthropic_planner(self):
        p = create_planner("anthropic", api_key="sk-dummy")
        assert isinstance(p, AnthropicPlanner)
        assert p.provider_name == "anthropic"

    def test_create_ollama_planner_falls_back_to_openai(self):
        p = create_planner("ollama")
        assert isinstance(p, OpenAIPlanner)

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="No planner"):
            create_planner("unknown-provider")


# ---------------------------------------------------------------------------
# OpenAI planner (synthetic — no real API)
# ---------------------------------------------------------------------------


class TestOpenAIPlanner:
    def test_creates_fallback_plan_when_no_tool_calls(self, monkeypatch):
        """When LLM returns text-only, an empty plan is returned gracefully."""
        from tests.conftest import fake_openai_response

        def _post(url, **kwargs):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return fake_openai_response(content="I cannot generate a plan right now.")
            return R

        monkeypatch.setattr("requests.post", _post)
        monkeypatch.setattr("requests.get", lambda url, **kw: type("R", (), {"status_code": 200})())

        from ai_core.llm_engine import LLMClient
        client = LLMClient(provider="openai", api_key="sk-test")
        planner = OpenAIPlanner(client)

        enum = sample_enum_data()
        plan = planner.create_plan(FAKE_VAULT_ADDR, FAKE_TOKEN[:12] + "...", enum)
        assert isinstance(plan, PentestPlan)
        assert plan.total_steps == 0  # fallback empty plan

    def test_creates_plan_from_tool_call(self, monkeypatch):
        """When LLM returns a tool call with plan data, it's parsed correctly."""
        from tests.conftest import fake_openai_response

        plan_json = {
            "token_assessment": {
                "power_level": "privileged",
                "summary": "Token has sys/mounts and token create access",
                "accessible_paths": ["sys/mounts", "auth/token/create"],
                "escalation_possible": True,
            },
            "risk_level": "high",
            "dynamic_policies": ["db-admin", "app-reader"],
            "steps": [
                {
                    "tool": "run_privilege_escalation",
                    "reason": "Token can create tokens — attempt escalation",
                    "params": {"ttl": "30m"},
                    "priority": 1,
                    "expected_impact": "Get admin token",
                },
                {
                    "tool": "run_secret_exfiltration",
                    "reason": "Dump all KV secrets with elevated token",
                    "params": {"max_depth": 5},
                    "priority": 2,
                    "expected_impact": "Read all secrets",
                },
            ],
            "attack_narrative": "Token has powerful capabilities. Escalate then exfiltrate.",
        }

        def _post(url, **kwargs):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return fake_openai_response(
                        content=None,
                        tool_calls=[{
                            "name": "create_pentest_plan",
                            "arguments": plan_json,
                        }],
                    )
            return R

        monkeypatch.setattr("requests.post", _post)
        monkeypatch.setattr("requests.get", lambda url, **kw: type("R", (), {"status_code": 200})())

        from ai_core.llm_engine import LLMClient
        client = LLMClient(provider="openai", api_key="sk-test")
        planner = OpenAIPlanner(client)

        enum = sample_enum_data()
        plan = planner.create_plan(FAKE_VAULT_ADDR, FAKE_TOKEN[:12] + "...", enum)

        assert isinstance(plan, PentestPlan)
        assert plan.total_steps == 2
        assert plan.token_assessment.power_level == "privileged"
        assert plan.token_assessment.escalation_possible is True
        assert plan.risk_level == "high"
        assert "db-admin" in plan.dynamic_policies
        assert plan.steps[0].tool == "run_privilege_escalation"
        assert plan.steps[1].tool == "run_secret_exfiltration"
        assert plan.attack_narrative != ""


# ---------------------------------------------------------------------------
# Anthropic planner (graceful without API key)
# ---------------------------------------------------------------------------


class TestAnthropicPlanner:
    def test_returns_fallback_plan_without_api_key(self):
        """Without ANTHROPIC_API_KEY, returns a fallback plan (no crash)."""
        planner = AnthropicPlanner(api_key=None)
        plan = planner.create_plan(FAKE_VAULT_ADDR, "s.XXX...", sample_enum_data())
        assert isinstance(plan, PentestPlan)
        assert plan.total_steps == 0
        assert "ANTHROPIC_API_KEY" in plan.attack_narrative

    def test_warns_without_api_key(self):
        with pytest.warns(RuntimeWarning, match="ANTHROPIC_API_KEY"):
            AnthropicPlanner(api_key=None)


# ---------------------------------------------------------------------------
# TokenAssessment
# ---------------------------------------------------------------------------


class TestTokenAssessment:
    def test_defaults(self):
        ta = TokenAssessment(power_level="standard", summary="Basic token")
        assert ta.accessible_paths == []
        assert ta.escalation_possible is False

    def test_full(self):
        ta = TokenAssessment(
            power_level="root",
            summary="Root token — full access",
            accessible_paths=["*"],
            escalation_possible=False,
        )
        assert ta.power_level == "root"
        assert ta.accessible_paths == ["*"]
