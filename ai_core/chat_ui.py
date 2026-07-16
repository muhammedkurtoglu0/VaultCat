"""Interactive AI pentest chat — powered by the autonomous agent.

Connects the LLM agent to real MCP tool execution and provides a
terminal-based chat interface.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Optional

try:
    import readline  # noqa: F401
except ImportError:
    try:
        import pyreadline3 as readline  # noqa: F401
    except ImportError:
        pass

from ai_core.agent import PentestAgent
from ai_core.llm_engine import LLMClient, detect_provider
from ai_core.memory import Memory
from ai_core.tools import ALL_TOOLS


class ChatUI:
    """Terminal chat interface for the AI pentest agent."""

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self.provider = provider or detect_provider()
        self.model = model
        self.memory = Memory()
        self.agent = PentestAgent(
            vault_addr=vault_addr,
            token=token,
            provider=self.provider,
            model=model,
        )
        self.agent.set_tool_executor(self._execute_tool)
        self.running = True

        if vault_addr:
            self.memory.set_context("vault_addr", vault_addr)
        if token:
            self.memory.set_context("token", token)

    # ── public entry point ──────────────────────────────────────────────

    def start(self):
        """Main interactive loop."""
        print("\n" + "=" * 60)
        print("🛡️  VAULT AI PENTEST AGENT")
        print("=" * 60)
        print(f"\n🧠 Provider : {self.provider}")
        print(f"🤖 Model    : {self.agent.llm.model}")
        print(f"📍 Target   : {self.vault_addr or 'set target <url>'}")
        print(f"🔑 Token    : {self.token[:12] + '...' if self.token and len(self.token) > 12 else self.token or 'none'}")
        print(f"🔧 Tools    : {len(ALL_TOOLS)} available")
        print("\n💬 The agent decides WHAT to do, WHEN, and WHY.")
        print("💬 Just tell it your objective — it handles everything.")
        print("💬 'help', 'modules', 'findings', 'status', 'exit'")
        print("=" * 60 + "\n")

        while self.running:
            try:
                user_input = input("\n🔓 YOU: ").strip()
                if not user_input:
                    continue

                self.memory.add_conversation("user", user_input)

                cmd = user_input.lower()

                if cmd in ("exit", "quit", "q"):
                    print("\n👾 AGENT: Shutting down. Goodbye!")
                    break

                if cmd in ("help", "yardım", "?"):
                    self._show_help()
                    continue

                if cmd in ("modules", "modüller", "ls"):
                    self._show_tools()
                    continue

                if cmd == "findings":
                    self._show_findings()
                    continue

                if cmd == "status":
                    self._show_status()
                    continue

                if cmd.startswith("set "):
                    self._handle_set(user_input[4:])
                    continue

                # Run the agent for any other input
                asyncio.run(self._run_agent(user_input))

            except KeyboardInterrupt:
                print("\n\n👾 AGENT: Interrupted. Type 'exit' to quit.")
            except Exception as e:
                print(f"\n❌ ERROR: {e}")
                import traceback
                traceback.print_exc()

    # ── agent runner ────────────────────────────────────────────────────

    async def _run_agent(self, objective: str):
        """Stream agent output to the terminal."""
        print(f"\n{'─' * 50}")

        async for event in self._agent_stream(objective):
            etype = event.get("type", "")

            if etype == "status":
                print(event["message"])
            elif etype == "thinking":
                print(f"\n{event['message']}")
            elif etype == "tool_call":
                print(f"\n{event['message']}")
            elif etype == "tool_result":
                result = event["message"]
                # Truncate long results for display
                if len(result) > 300:
                    result = result[:300] + "..."
                print(f"   ↳ {result}")
            elif etype == "message":
                print(f"\n💬 AGENT: {event['message']}")
            elif etype == "complete":
                print(f"\n{event['message']}")
            elif etype == "error":
                print(f"\n❌ {event['message']}")
            elif etype == "warning":
                print(f"\n{event['message']}")

        print(f"{'─' * 50}")

    async def _agent_stream(self, objective: str):
        """Yield agent events, handling the async generator."""
        try:
            async for event in self._async_gen_wrapper(objective):
                yield event
        except Exception as e:
            yield {"type": "error", "message": str(e)}

    async def _async_gen_wrapper(self, objective: str):
        """Iterate the async agent.run() generator yielding events."""
        async for event in self.agent.run(objective):
            yield event
            await asyncio.sleep(0)

    # ── tool executor ───────────────────────────────────────────────────

    async def _execute_tool(self, tool_name: str, params: dict) -> str:
        """Execute a tool by calling the corresponding MCP function or module.

        This is the bridge between the agent's decisions and real code execution.
        """
        # Inject context
        if "vault_addr" not in params and self.vault_addr:
            params["vault_addr"] = self.vault_addr
        if "token" not in params and self.token:
            params["token"] = self.token

        try:
            # Import and call the actual MCP tool function
            result = await self._call_mcp_tool(tool_name, params)
            # Record execution
            self.memory.add_execution(tool_name, "success", {"params": params})
            return result
        except Exception as e:
            self.memory.add_execution(tool_name, "error", {"error": str(e)})
            return json.dumps({"status": "error", "message": str(e)},
                              ensure_ascii=False)

    async def _call_mcp_tool(self, tool_name: str, params: dict) -> str:
        """Route a tool call to the actual MCP tool implementation."""
        from ai_core.mcp_server import (
            get_findings,
            get_risk_score,
            list_active_modules,
            refresh_nvd_cache,
            run_active_module,
            run_auth_config_audit,
            run_capability_audit,
            run_cloud_key_exfiltration,
            run_database_credential_harvest,
            run_env_scan,
            run_hijack_scan,
            run_kv_enumeration,
            read_single_policy,
            run_raw_vault_request,
            run_policy_auditor,
            run_priv_esc_scan,
            run_privilege_escalation,
            run_secret_exfiltration,
            run_ttl_audit,
            run_unauthenticated_recon,
        )

        tool_map = {
            "run_unauthenticated_recon": run_unauthenticated_recon,
            "run_hijack_scan": run_hijack_scan,
            "run_env_scan": run_env_scan,
            "run_capability_audit": run_capability_audit,
            "run_priv_esc_scan": run_priv_esc_scan,
            "run_kv_enumeration": run_kv_enumeration,
            "run_ttl_audit": run_ttl_audit,
            "run_auth_config_audit": run_auth_config_audit,
            "read_single_policy": read_single_policy,
            "run_raw_vault_request": run_raw_vault_request,
            "run_policy_auditor": run_policy_auditor,
            "run_privilege_escalation": run_privilege_escalation,
            "run_secret_exfiltration": run_secret_exfiltration,
            "run_database_credential_harvest": run_database_credential_harvest,
            "run_cloud_key_exfiltration": run_cloud_key_exfiltration,
            "list_active_modules": list_active_modules,
            "run_active_module": run_active_module,
            "get_findings": get_findings,
            "get_risk_score": get_risk_score,
            "refresh_nvd_cache": refresh_nvd_cache,
        }

        handler = tool_map.get(tool_name)
        if not handler:
            return json.dumps({"status": "error",
                               "message": f"Unknown tool: {tool_name}"},
                              ensure_ascii=False)

        # Call with appropriate kwargs
        return await _invoke_mcp_handler(handler, params)

    # ── UI helpers ──────────────────────────────────────────────────────

    def _show_help(self):
        print(f"""
📖 COMMANDS:

    <anything>  → Tell the agent what to do (it decides HOW)
    modules     → List all 18 tools the agent can use
    findings    → Show accumulated pentest findings
    status      → Show current target, token, provider, model
    set target  → Set the Vault target URL
    set token   → Set a Vault token
    set model   → Change the LLM model
    set provider→ Change the LLM provider (ollama/openai/anthropic)
    exit        → Quit

📌 EXAMPLES:
    ▶ "Scan http://localhost:8200 and find every vulnerability"
    ▶ "I found this token hvs.abc123 — assess its power and escalate"
    ▶ "Do a full penetration test on this Vault instance"
    ▶ "Check if this version has any known CVEs"
    ▶ "After recon, automatically exploit whatever you find"

🧠 Provider: {self.provider}  Model: {self.agent.llm.model}  Tools: {len(ALL_TOOLS)}
""")

    def _show_tools(self):
        print(f"\n🔧 AVAILABLE TOOLS ({len(ALL_TOOLS)}):\n")
        phases = {
            "recon": "🔍 RECON (no auth needed)",
            "hijack": "🔑 HIJACK (local scan)",
            "audit": "📊 AUDIT (token required)",
            "active": "⚡ ACTIVE (state-changing)",
            "meta": "📋 META",
        }
        for phase, label in phases.items():
            tools = [t for t in ALL_TOOLS if t.phase == phase]
            if not tools:
                continue
            print(f"  {label}")
            for t in tools:
                icon = "🟢" if t.risk == "read_only" else "🟡" if t.risk == "state_changing" else "🔴"
                print(f"    {icon} {t.name}")
                print(f"       {t.description[:110]}...")
            print()

    def _show_findings(self):
        from core.report import findings as global_findings

        findings = self.memory.findings or global_findings
        if not findings:
            print("\n📭 No findings yet — try running some tools first.")
            return

        print(f"\n🔍 FINDINGS ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                      "LOW": "🔵", "INFO": "⚪", "PASS": "🟢"}.get(sev, "⚪")
            print(f"  {i}. {emoji} [{sev}] {f.get('title', '')}")
            desc = f.get("description", "")
            if desc:
                print(f"     {desc[:120]}")

    def _show_status(self):
        llm = self.agent.llm
        print(f"""
📊 STATUS:
  Provider : {llm.provider}
  Model    : {llm.model}
  Target   : {self.vault_addr or 'not set (use "set target <url>")'}
  Token    : {'present' if self.token else 'not set (use "set token <token>")'}
  Tools    : {len(ALL_TOOLS)} available
  Findings : {len(self.memory.findings)} in session memory
  LLM OK   : {'✅ connected' if llm.is_available() else '❌ check connection / API key'}
""")

    def _handle_set(self, command: str):
        parts = command.strip().split(" ", 1)
        if len(parts) != 2:
            print("❌ Usage: set <param> <value>")
            print("   set target http://vault:8200")
            print("   set token hvs.abc123...")
            print("   set model llama3.1:70b")
            print("   set provider openai")
            print("   set tls-verify off")
            return

        key, value = parts[0].strip(), parts[1].strip()

        if key == "target":
            self.vault_addr = value
            self.agent.vault_addr = value
            self.memory.set_context("vault_addr", value)
            # Auto-skip TLS for HTTPS targets (self-signed is common in pentests)
            if value.startswith("https://"):
                from core.tls_config import set_insecure_mode
                set_insecure_mode()
            print(f"✅ Target set: {value}")
        elif key == "token":
            self.token = value
            self.agent.token = value
            self.memory.set_context("token", value)
            print(f"✅ Token set: {value[:12] if len(value) > 12 else value}...")
        elif key == "model":
            self.agent.llm.model = value
            print(f"✅ Model set: {value}")
        elif key == "provider":
            self.agent.llm = LLMClient(provider=value, model=self.agent.llm.model)
            self.provider = value
            print(f"✅ Provider set: {value}")
        elif key == "tls-verify":
            if value.lower() in ("off", "false", "skip", "0", "no"):
                from core.tls_config import set_insecure_mode
                set_insecure_mode()
            elif value.lower() in ("on", "true", "verify", "1", "yes"):
                from core.tls_config import get_verify
                print("TLS verification is controlled by the --skip-tls-verify startup flag")
            else:
                print(f"Unknown tls-verify value: {value}. Use 'on' or 'off'.")
        else:
            print(f"❌ Unknown parameter: {key}")
            print("   Valid: target, token, model, provider")


async def _invoke_mcp_handler(handler, params: dict) -> str:
    """Invoke an MCP handler with the given params, filtering to valid kwargs."""
    import inspect

    sig = inspect.signature(handler)
    valid_keys = set(sig.parameters.keys())
    filtered = {k: v for k, v in params.items() if k in valid_keys}

    result = handler(**filtered)
    if inspect.isawaitable(result):
        result = await result
    return result if isinstance(result, str) else str(result)


# ── entry point (module-level) ──────────────────────────────────────────────


def start_chat_session(
    vault_addr: str | None = None,
    token: str | None = None,
    provider: str | None = None,
    model: str | None = None,
):
    """Launch the interactive AI pentest chat session."""
    chat = ChatUI(vault_addr=vault_addr, token=token, provider=provider, model=model)
    chat.start()


if __name__ == "__main__":
    start_chat_session()
