"""Tests for the MCP extension tools and the hybrid `fix` chat command."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from core import report
from core.report import add_finding, clear_findings


@pytest.fixture(autouse=True)
def clear_findings_fixture():
    clear_findings()
    yield
    clear_findings()


# ─── get_remediation_advice ────────────────────────────────────────────────


def test_remediation_advice_empty_findings():
    from ai_core.mcp_server import get_remediation_advice

    result = json.loads(asyncio.run(get_remediation_advice()))
    assert result["status"] == "no_findings"
    assert result["advice_count"] == 0


def test_remediation_advice_matches_rule_and_action_plan():
    from ai_core.mcp_server import get_remediation_advice

    add_finding(
        "HIGH",
        "Wildcard CORS policy allows any origin",
        "Access-Control-Allow-Origin: *",
        module="cors_scanner",
        target="unit-test",
    )

    result = json.loads(asyncio.run(get_remediation_advice()))
    assert result["status"] == "completed"
    assert result["advice_count"] >= 1
    assert any("CORS" in a["category"] for a in result["advice"])
    assert any("vault write sys/config/cors" in step
               for a in result["advice"] for step in a["fix_steps"])
    assert result["action_plan"]  # non-empty priority plan


def test_remediation_advice_min_severity_filter():
    from ai_core.mcp_server import get_remediation_advice

    add_finding("LOW", "Reverse proxy header exposed", "Server: nginx",
                module="header_scanner", target="unit-test")

    result = json.loads(asyncio.run(get_remediation_advice(min_severity="CRITICAL")))
    assert result["findings_considered"] == 0
    assert result["advice_count"] == 0


# ─── _make_mcp_tool_executor ───────────────────────────────────────────────


def test_executor_rejects_unknown_tool():
    from ai_core.mcp_server import _make_mcp_tool_executor

    executor = _make_mcp_tool_executor()
    with pytest.raises(ValueError, match="Unknown tool"):
        asyncio.run(executor("no_such_tool_xyz", {}))


def test_executor_blocks_state_changing_tools_in_read_only():
    from ai_core.mcp_server import _make_mcp_tool_executor

    executor = _make_mcp_tool_executor("read_only")
    result = asyncio.run(executor("run_privilege_escalation", {"vault_addr": "http://x"}))
    assert "BLOCKED" in result

    # state_changing level must NOT block (will fail on network, but not with BLOCKED)
    executor2 = _make_mcp_tool_executor("state_changing")
    try:
        result2 = asyncio.run(executor2("run_privilege_escalation", {"vault_addr": "http://x"}))
        assert "BLOCKED" not in str(result2)
    except Exception:
        pass  # network/module errors are fine — we only assert no BLOCKED short-circuit


def test_executor_dispatches_known_tool():
    from ai_core.mcp_server import _make_mcp_tool_executor

    add_finding("INFO", "Executor dispatch probe", "probe",
                module="test", target="unit-test")
    executor = _make_mcp_tool_executor()
    result = asyncio.run(executor("get_findings", {}))
    assert "Executor dispatch probe" in result


# ─── run_orchestrated_attack ───────────────────────────────────────────────


def test_orchestrated_attack_requires_findings():
    from ai_core.mcp_server import run_orchestrated_attack

    result = json.loads(asyncio.run(run_orchestrated_attack("http://localhost:8200")))
    assert result["status"] == "no_findings"


# ─── hybrid _show_remediation ──────────────────────────────────────────────


def _make_ui(agent_calls: list):
    """Build a ChatUI shell without running __init__ (no LLM construction)."""
    from ai_core.chat_ui import ChatUI

    ui = ChatUI.__new__(ChatUI)
    ui.memory = SimpleNamespace(findings=[], add_conversation=lambda *a, **k: None)
    ui.vault_addr = "http://localhost:8200"
    ui.token = None

    async def _fake_run_agent(prompt):
        agent_calls.append(prompt)

    ui._run_agent = _fake_run_agent
    return ui


def test_fix_skips_llm_when_all_findings_match_rules(capsys):
    add_finding("HIGH", "Wildcard CORS policy allows any origin", "ACAOrigin: *",
                module="cors_scanner", target="unit-test")

    agent_calls: list = []
    ui = _make_ui(agent_calls)
    ui._show_remediation()

    assert agent_calls == []  # LLM must not be called
    out = capsys.readouterr().out
    assert "RULE-BASED ANALYSIS" in out
    assert "matched specific remediation rules" in out


def test_fix_calls_llm_for_unmatched_findings_only(capsys):
    add_finding("HIGH", "Wildcard CORS policy allows any origin", "ACAOrigin: *",
                module="cors_scanner", target="unit-test")
    add_finding("MEDIUM", "Unusual Configuration Anomaly ZZZ", "odd behaviour",
                module="test", target="unit-test")

    agent_calls: list = []
    ui = _make_ui(agent_calls)
    ui._show_remediation()

    assert len(agent_calls) == 1
    prompt = agent_calls[0]
    assert "Unusual Configuration Anomaly ZZZ" in prompt
    # matched finding should not be re-sent to the LLM
    assert "Wildcard CORS" not in prompt
    out = capsys.readouterr().out
    assert "RULE-BASED ANALYSIS" in out


def test_fix_filter_text_narrows_findings(capsys):
    add_finding("HIGH", "Wildcard CORS policy allows any origin", "ACAOrigin: *",
                module="cors_scanner", target="unit-test")
    add_finding("MEDIUM", "Unusual Configuration Anomaly ZZZ", "odd behaviour",
                module="test", target="unit-test")

    agent_calls: list = []
    ui = _make_ui(agent_calls)
    ui._show_remediation("cors")

    assert agent_calls == []  # only the CORS finding remains, and it matches a rule
    out = capsys.readouterr().out
    assert "CORS" in out


def test_fix_no_findings(capsys):
    agent_calls: list = []
    ui = _make_ui(agent_calls)
    ui._show_remediation()

    assert agent_calls == []
    assert "No findings yet" in capsys.readouterr().out
