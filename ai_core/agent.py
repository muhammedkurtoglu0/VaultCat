"""Autonomous pentest agent with ReAct (Reasoning + Acting) loop.

The agent:
1. Understands the full pentest context (target, token, findings, tool results)
2. Plans multi-step attack chains autonomously
3. Decides which tool to use next based on findings, not keywords
4. Adapts when tools succeed or fail
5. Reports findings in natural language

Architecture:
    User Objective → Agent Loop (think → act → observe → repeat) → Report
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, AsyncIterator, Optional

from ai_core.llm_engine import LLMClient
from ai_core.memory import Memory
from ai_core.tools import ALL_TOOLS, ToolDef


# ---------------------------------------------------------------------------
# System prompt — teaches the LLM the pentest methodology
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert Vault penetration testing agent. You work alongside the user as a senior pentester would — conversational, direct, and practical.

## YOUR PERSONALITY
- Talk like a senior pentester chatting with a colleague. Use the user's language.
- When you discover findings, present them as TABLES (markdown format).
- After each finding, suggest the NEXT MOVE. Don't list 5 options — give ONE concrete next step.
- Be concise. No fluff. No disclaimers.
- Celebrate wins briefly (a checkmark, a "found it"), then move on.
- If something fails, explain why in one sentence and suggest the fix.
- Turkish users get Turkish responses. English users get English. Detect automatically.

## OUTPUT STYLE
After recon/scan results, format like this:
```
| Bulgu | Severity | Detay |
|-------|----------|-------|
| HTTP kullanımı | HIGH | Vault HTTPS yerine HTTP'te |
| Sürüm 1.15.6 | LOW | 3 CVE eşleşti |

**Sıradaki:** Token varsa capability audit yapalım. Yoksa token bulmamız lazım.
```

## CRITICAL RULES
- NO target → ask user to set one. Never guess IPs.
- NO token → suggest unauthenticated recon first.
- After each scan, ANALYZE results and suggest ONE next step.
- NEVER list numbered options like "we could do A, B, or C".
- NEVER output Chinese/Korean/Japanese unless asked.

## CRITICAL RULE — BEFORE ANY TOOL CALL

If NO target URL is configured, you CANNOT run recon or audit tools.
Instead, TELL THE USER in natural language:
"Please set a target first: set target http://VAULT_IP:8200"
Then STOP and wait for the user to provide it.

## YOUR CAPABILITIES
You have 18 specialized pentest tools. You decide which tool to use, when, and why — based on context and findings.

## METHODOLOGY

### Phase 1: RECONNAISSANCE (no credentials needed)
1. Run unauthenticated recon on the target — ALWAYS START HERE
2. If you have local access, scan for leaked credentials (env vars, files, git history)
3. Review findings in natural language — what did you discover?

### Phase 2: AUDIT (requires a token)
4. If a token was discovered or provided, audit its capabilities
5. Simulate privilege escalation paths (read-only, safe)
6. Enumerate KV paths, audit TTLs, auth configs, ACL policies

### Phase 3: EXPLOITATION (state-changing)
7. Attempt active privilege escalation if paths exist
8. Exfiltrate secrets with elevated token
9. Harvest database credentials and cloud IAM keys
10. Deploy persistence

### Phase 4: REPORTING
11. Use get_findings to review all findings
12. Assess overall risk score
13. Provide a structured summary of everything found

## COMMUNICATION RULES
- Respond in 2-4 sentences — be concise, like a senior pentester talking to a colleague
- NEVER list numbered options or suggestions — the user decides next steps
- NEVER say "we could do A, B, or C" — just report findings
- After tool results, explain what you found briefly and STOP
- If a target is unreachable, TELL THE USER clearly
- If the user's request is complete, provide a short summary and stop
- NEVER stay silent after a tool returns results

## RESPONSE FORMAT
Keep it minimal:
1. What the tool found (1-2 sentences)
2. If you MUST run another tool immediately, call it — otherwise STOP and wait"""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class PentestAgent:
    """Autonomous agent that plans and executes Vault pentest operations."""

    MAX_TURNS = 25  # safety limit

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self.llm = LLMClient(provider=provider, model=model)
        self.memory = Memory()
        self.tools = ALL_TOOLS
        self._tool_executor: Any = None  # set by chat_ui
        self._turn_count = 0

        if vault_addr:
            self.memory.set_context("vault_addr", vault_addr)
        if token:
            self.memory.set_context("token", token)

    # ── public API ──────────────────────────────────────────────────────

    def set_tool_executor(self, executor):
        """Bind the async function that actually runs tool calls."""
        self._tool_executor = executor

    async def run(self, objective: str):
        """Run the agent loop. Maintains conversation history across calls."""
        self._turn_count = 0
        self._get_findings_count = 0  # reset per run
        self.memory.add_conversation("user", objective)

        # Persistent conversation history
        if not hasattr(self, '_messages'):
            self._messages: list[dict] = []

        # Detect if context has changed significantly (target/token was just set)
        context_changed = False
        prev_target = getattr(self, '_last_target', None)
        prev_token = getattr(self, '_last_token', None)
        if prev_target != self.vault_addr or prev_token != self.token:
            context_changed = True
        self._last_target = self.vault_addr
        self._last_token = self.token

        if not self._messages or context_changed:
            # Fresh start or context changed — rebuild full context
            context_msg = self._build_context_message(objective)
            self._messages = [{"role": "user", "content": context_msg}]
        else:
            # Subsequent turns — inject context reminder + user message
            ctx = self._build_context_message("")
            self._messages.append({
                "role": "user",
                "content": (
                    f"[STATE UPDATE]\n{ctx}\n\n"
                    f"User says: {objective}"
                ),
            })

        messages = self._messages

        yield {"type": "status", "message": f"Provider: {self.llm.provider}:{self.llm.model}"}
        yield {"type": "status", "message": f"Target: {self.vault_addr or '(not set — use set target <url>)'}"}

        while self._turn_count < self.MAX_TURNS:
            self._turn_count += 1

            # Get LLM decision (offload sync HTTP to thread)
            llm_tools = [t.to_openai_function() for t in self.tools]
            yield {"type": "thinking", "message": f"Thinking... (step {self._turn_count})"}

            response = await asyncio.to_thread(
                self.llm.chat,
                system_prompt=SYSTEM_PROMPT,
                messages=messages,
                tools=llm_tools,
                temperature=0.1,
                max_tokens=2048,
            )

            if response["finish_reason"] == "error":
                yield {"type": "error", "message": f"LLM error: {response.get('raw', 'unknown')}"}
                break

            # If the LLM wants to call tools
            if response.get("tool_calls"):
                for tool_call in response["tool_calls"]:
                    name = tool_call["name"]
                    arguments = tool_call.get("arguments", {})

                    # ---- GUARD: validate + inject target/token -----------
                    blocked = self._guard_tool_call(name, arguments)
                    if blocked:
                        yield {"type": "warning", "message": blocked}
                        messages.append({
                            "role": "assistant",
                            "content": response.get("content") or "",
                        })
                        messages.append({
                            "role": "user",
                            "content": (
                                f"SYSTEM: Cannot run '{name}' — {blocked}. "
                                "Tell the user what's needed in natural language, "
                                "then wait for them to provide it."
                            ),
                        })
                        continue
                    # ----------------------------------------------------------

                    yield {
                        "type": "tool_call",
                        "message": f"{name}({json.dumps(arguments, ensure_ascii=False)})",
                        "tool": name,
                        "params": arguments,
                    }

                    # Execute the tool
                    tool_result = ""
                    if self._tool_executor:
                        try:
                            tool_result = await self._tool_executor(name, arguments)
                        except Exception as e:
                            tool_result = json.dumps({"status": "error", "message": str(e)})
                    else:
                        tool_result = json.dumps(
                            {"status": "error", "message": "no tool executor configured"}
                        )

                    result_preview = tool_result[:500]
                    yield {"type": "tool_result", "message": result_preview}

                    # Parse result for a quick summary
                    result_summary = self._summarize_result(tool_result)

                    # Add to conversation
                    messages.append({
                        "role": "assistant",
                        "content": response.get("content") or "",
                        "tool_calls": [{"name": name, "arguments": arguments}],
                    })
                    messages.append({
                        "role": "tool",
                        "content": tool_result[:2000],
                        "tool_call_id": name,
                    })
                    # Prompt LLM to analyze — BRIEFLY, no option lists
                    messages.append({
                        "role": "user",
                        "content": (
                            f"Tool '{name}' returned: {result_summary}\n\n"
                            "Report what you found in 2-3 sentences max. "
                            "Do NOT list options or suggestions — the user decides next steps. "
                            "If you need another tool immediately, call it. Otherwise just report and stop."
                        ),
                    })

                # Continue the loop — LLM sees tool results + analysis prompt
                continue

            # No tool calls — agent is speaking to us in natural language.
            # STOP here and wait for user input. The agent is conversational,
            # not an infinite autonomous loop.
            content = response.get("content", "")
            if content:
                yield {"type": "message", "message": content}
                messages.append({"role": "assistant", "content": content})
                self.memory.add_conversation("agent", content)

            # If agent says it's done, mark complete
            if self._is_completion_marker(content) and self._turn_count > 1:
                yield {"type": "complete", "message": "Agent completed the task."}

            # Always break after natural language response — wait for user
            break

        if self._turn_count >= self.MAX_TURNS:
            yield {"type": "warning", "message": "Max agent steps reached."}

    # ── guards ──────────────────────────────────────────────────────────

    def _guard_tool_call(self, name: str, arguments: dict) -> str | None:
        """Validate tool call. Block hallucinated/fake values."""
        # ---- detect FAKE token values (LLM hallucinations) ----
        arg_token = str(arguments.get("token", "")).strip().lower()
        fake_token_patterns = (
            "your_token", "your-token", "token_here", "insert_token",
            "s.xxx", "hvs.xxx", "token", "placeholder",
        )
        if arg_token and any(p in arg_token for p in fake_token_patterns):
            return (
                f"FAKE TOKEN '{arguments.get('token')}' — do NOT guess tokens. "
                "If no token is set, tell the user to provide one."
            )

        # ---- detect FAKE IPs (LLM hallucinations) ----
        arg_addr = str(arguments.get("vault_addr", "")).strip().rstrip("/")
        fake_ips = {
            "http://192.168.1.100:8200", "http://10.0.0.1:8200",
            "http://localhost:8200", "http://127.0.0.1:8200",
            "http://vault.example.com:8200", "http://VAULT_IP:8200",
        }
        if arg_addr in fake_ips:
            if self.vault_addr:
                arguments["vault_addr"] = self.vault_addr  # use real target
            else:
                return (
                    f"FAKE IP '{arg_addr}' — do NOT guess. "
                    "Ask the user to set a target with: set target http://IP:8200"
                )

        # ---- block tools without required context ----
        vault_tools = {
            "run_unauthenticated_recon", "run_capability_audit",
            "run_priv_esc_scan", "run_kv_enumeration", "run_ttl_audit",
            "run_auth_config_audit", "run_policy_auditor",
            "run_privilege_escalation", "run_secret_exfiltration",
            "run_database_credential_harvest", "run_cloud_key_exfiltration",
            "run_active_module",
        }
        if name in vault_tools and not self.vault_addr and not arguments.get("vault_addr"):
            return "No target. Ask: set target http://IP:8200"

        token_tools = {
            "run_capability_audit", "run_priv_esc_scan", "run_kv_enumeration",
            "run_ttl_audit", "run_auth_config_audit", "run_policy_auditor",
            "run_privilege_escalation",
        }
        if name in token_tools and not self.token and not arguments.get("token"):
            return "No token. Ask: set token hvs.ABC..."

        # ---- inject real target (override any hallucinated one) ----
        if self.vault_addr and name in vault_tools:
            arguments["vault_addr"] = self.vault_addr

        # ---- inject real token ----
        if self.token and name in token_tools:
            arguments["token"] = self.token

        # ---- prevent duplicate recon ----
        if name == "run_unauthenticated_recon":
            if getattr(self, '_recon_done', False):
                return (
                    "RECON ALREADY COMPLETED on this target. "
                    "DO NOT retry recon. Use get_findings ONCE, "
                    "then ANALYZE the results and respond to the user "
                    "with concrete exploitation suggestions based on findings."
                )
            self._recon_done = True

        # ---- prevent duplicate get_findings in same turn ----
        if name == "get_findings":
            count = getattr(self, '_get_findings_count', 0)
            if count >= 1:
                return (
                    "Already called get_findings this turn. "
                    "STOP calling tools and ANALYZE the results. "
                    "Respond to the user with specific, actionable findings."
                )
            self._get_findings_count = count + 1

        return None

    # ── helpers ─────────────────────────────────────────────────────────

    def _summarize_result(self, tool_result: str) -> str:
        """Extract a useful summary from a JSON tool result."""
        try:
            data = json.loads(tool_result)
            status = data.get("status", "unknown")
            parts = [f"Status: {status}"]

            # For get_findings — extract key findings titles
            findings = data.get("findings", [])
            if findings:
                sev_counts = {}
                titles = []
                for f in findings:
                    sev = f.get("severity", "?")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    titles.append(f"[{sev}] {f.get('title', '')}")
                parts.append(f"Total: {len(findings)} findings")
                parts.append(f"Breakdown: {sev_counts}")
                # Include HIGH/CRITICAL findings explicitly
                critical = [t for t in titles if "[CRITICAL]" in t or "[HIGH]" in t]
                if critical:
                    parts.append("KEY: " + " | ".join(critical[:5]))

            count = data.get("findings_count", data.get("total", ""))
            if count and not findings:
                parts.append(f"Count: {count}")

            msg = data.get("message", data.get("summary", ""))
            if msg:
                parts.append(str(msg)[:200])

            # Risk score
            score = data.get("risk_score")
            grade = data.get("risk_grade")
            if score is not None:
                parts.append(f"Risk: {score}/100 ({grade})")

            return " | ".join(parts)
        except (json.JSONDecodeError, TypeError):
            return tool_result[:300]

    # ── internal ────────────────────────────────────────────────────────

    def _build_context_message(self, objective: str) -> str:
        parts = []
        if objective:
            parts.append(f"USER OBJECTIVE: {objective}")
        if self.vault_addr:
            parts.append(f"Target Vault: {self.vault_addr}")
        if self.token:
            t = self.token[:12] + "..." if len(self.token) > 12 else self.token
            parts.append(f"Available token: {t}")
        elif not objective:
            parts.append("No token — use unauthenticated recon only.")

        # Include recent findings from global report
        try:
            from core.report import findings as global_findings
            if global_findings:
                parts.append(f"\nScan findings so far ({len(global_findings)} total):")
                for f in global_findings[-15:]:
                    sev = f.get("severity", "?")
                    title = f.get("title", "")
                    parts.append(f"  [{sev}] {title}")
        except ImportError:
            pass

        # Recent memory findings
        if self.memory.findings:
            parts.append(f"\nMemory findings ({len(self.memory.findings)}):")
            for f in self.memory.findings[-5:]:
                parts.append(f"  [{f.get('severity', '?')}] {f.get('title', '')}")

        return "\n".join(parts) if parts else "Continue the conversation."

    @staticmethod
    def _is_completion_marker(text: str) -> bool:
        """Detect if the LLM is signaling task completion."""
        if not text:
            return False
        markers = (
            "task complete", "summary", "görev tamam", "özet",
            "final report", "in conclusion", "no further",
            "exhausted", "penetration test complete",
        )
        lowered = text.lower()
        return any(m in lowered for m in markers) and len(text) > 100
