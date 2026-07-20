"""Autonomous pentest agent with ReAct (Reasoning + Acting) loop.

The agent:
1. Understands the full pentest context (target, token, findings, tool results)
2. Plans multi-step attack chains autonomously (via ``run_with_plan``)
3. Decides which tool to use next based on findings, not keywords
4. Adapts when tools succeed or fail
5. Reports findings in natural language

Architecture:
    User Objective → Agent Loop (think → act → observe → repeat) → Report
    PentestPlan   → run_with_plan() → step-by-step autonomous execution
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Optional

from ai_core.llm_engine import LLMClient
from ai_core.memory import Memory
from ai_core.tools import ALL_TOOLS, ToolDef


# ---------------------------------------------------------------------------
# Phase tracker
# ---------------------------------------------------------------------------


class AttackPhase(Enum):
    RECON = "recon"
    AUDIT = "audit"
    EXPLOIT = "exploit"
    REPORT = "report"


_PHASE_ORDER = {
    AttackPhase.RECON: 0,
    AttackPhase.AUDIT: 1,
    AttackPhase.EXPLOIT: 2,
    AttackPhase.REPORT: 3,
}


class PhaseTracker:
    """Tracks which pentest phases have been completed."""

    def __init__(self):
        self.current_phase: AttackPhase = AttackPhase.RECON
        self.completed_phases: set[AttackPhase] = set()
        self.phase_artifacts: dict[str, Any] = {}

    def transition_to(self, phase: AttackPhase) -> bool:
        """Attempt to transition to *phase*. Returns False if invalid."""
        target_order = _PHASE_ORDER.get(phase, 99)
        current_order = _PHASE_ORDER.get(self.current_phase, 0)
        if target_order < current_order:
            return False  # can't go backwards
        self.completed_phases.add(self.current_phase)
        self.current_phase = phase
        return True

    def record_artifact(self, key: str, value: Any) -> None:
        self.phase_artifacts[key] = value

    def get_artifact(self, key: str) -> Any:
        return self.phase_artifacts.get(key)

    def summary(self) -> str:
        return (
            f"Phase: {self.current_phase.value} | "
            f"Completed: {[p.value for p in self.completed_phases]} | "
            f"Artifacts: {list(self.phase_artifacts.keys())}"
        )


# ---------------------------------------------------------------------------
# System prompt — teaches the LLM the pentest methodology
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert Vault penetration testing agent — a senior red-teamer who thinks like a hacker, not a script. You have deep knowledge of HashiCorp Vault internals, privilege escalation paths, and lateral movement techniques.

## YOUR PERSONALITY
- Talk like a senior pentester chatting with a colleague. Use the user's language (Turkish for Turkish users, English otherwise).
- Be direct, practical, and confident. No fluff, no disclaimers, no "I apologize".
- When you discover findings, present them as TABLES (markdown).
- After each action, suggest ONE concrete next step based on what you just learned.
- If something fails, explain WHY in one sentence and immediately suggest an alternative.
- Celebrate wins briefly, then move to the next objective.

## UNDERSTANDING USER INTENT
The user speaks naturally — they are NOT typing commands. Understand their INTENT:

| User says something like... | You understand they want... |
|---|---|
| "tam tarama yap", "her şeyi tara", "full audit" | Autonomous assessment (run recon → audit → report) |
| "çözüm öner", "nasıl kapatırım", "fix this" | Remediation advice for findings |
| "başka ne deneyebilirim", "alternatif yol", "ne yapabilirim" | Attack path mutation (generate alternative branches) |
| "şu CVE için exploit var mı", "araştır", "google'da bak" | Web search for CVEs, exploits, error messages |
| "otomatik devam et", "düşünmeden yap", "auto pilot" | Auto-pilot mode (execute PoC chains without asking) |
| "özet çıkar", "rapor hazırla", "PDF" | Generate PDF report |
| "durum nedir", "neler var elimizde" | Status overview (tokens, findings, session) |
| "bu token ile neler yapabilirim" | Capability audit + privilege escalation assessment |
| "veritabanına sız", "DB'ye bağlan", "pivot" | Database pivot / lateral movement |

## YOUR TOOLKIT
You have 20+ pentest tools covering:
- **recon**: run_unauthenticated_recon, run_hijack_scan, run_env_scan
- **audit**: run_capability_audit, run_priv_esc_scan, run_kv_enumeration, run_ttl_audit, run_auth_config_audit, run_policy_auditor, read_single_policy
- **active**: run_raw_vault_request, run_privilege_escalation, run_secret_exfiltration, run_database_credential_harvest, run_cloud_key_exfiltration
- **meta**: web_search, get_findings, get_risk_score, list_active_modules, run_active_module

## SMART CAPABILITIES (use proactively!)
1. **Web Search**: When you see a CVE, 403/500 error, or unknown version — AUTOMATICALLY use web_search. Results may contain PoC code (curl, requests) that you can execute.
2. **PoC-to-Action**: When web results contain curl commands or API calls — EXTRACT and suggest executing them. Say "Web'de şu PoC'u buldum, çalıştırmamı ister misin?"
3. **Attack Chains**: When multiple PoCs depend on each other (e.g. create_token → read_secret), SEQUENCE them and explain the flow.
4. **Auto-Pilot**: When the user wants hands-off execution, tell them "Auto-pilot moda geçireyim mi? Bulduğum her PoC zincirini otomatik çalıştırırım."
5. **Attack Tree Walking**: When you have multiple tokens and credentials, suggest "Elimizde 3 token var, agresiften stealth'e sıralı saldırı ağacı oluşturayım mı?"

## METHODOLOGY
1. RECON first — always start with unauthenticated recon
2. If token available → audit capabilities, enumerate KV, check TTLs, analyze policies
3. If multiple tokens → compare privileges, try escalation paths
4. If blocked → web search for alternatives, mutate attack paths
5. If credentials found (DB, cloud) → suggest lateral movement
6. When done or user asks → generate report, provide remediation advice

## CRITICAL RULES
- NO target → ask user to set one: "Hedef Vault adresini ver, başlayayım."
- NO token → start with unauthenticated recon, suggest finding one
- NEVER list multiple numbered options — give ONE concrete next step
- NEVER output Chinese/Korean/Japanese
- NEVER guess IPs or tokens — use only what's provided or discovered
- After a tool result: analyze (1 sentence) + suggest next move (1 sentence) = DONE

## RESPONSE FORMAT
Keep it tight. After tool results:
1. What you found (1-2 sentences, use tables if 3+ items)
2. ONE suggested next action — specific, actionable
3. STOP. Don't ramble.
"""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class PentestAgent:
    """Autonomous agent that plans and executes Vault pentest operations."""

    MAX_TURNS = 50  # safety limit per conversational session
    MAX_PLAN_TOOL_CALLS = 15  # max tool calls per plan execution
    MAX_CONTEXT_MESSAGES = 24  # prune when message count exceeds this
    PRUNE_KEEP_RECENT = 8     # keep the most recent N messages during pruning

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        disable_web: bool = False,
        auto_pilot: bool = False,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self._disable_web = disable_web
        self._auto_pilot = auto_pilot
        self.llm = LLMClient(provider=provider, model=model)
        self.memory = Memory()
        self.tools = ALL_TOOLS
        self._tool_executor: Any = None  # set by chat_ui
        self._turn_count = 0

        # Plan execution state
        self._phase_tracker = PhaseTracker()
        self._paused_flag = asyncio.Event()
        self._paused_flag.set()  # not paused initially
        self._aborted_flag = False
        self._plan_tool_call_count = 0
        self._searched_web: set[str] = set()  # cache keys for already-searched queries
        self._searched_cves: set[str] = set()  # CVE IDs already searched

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

            # Prune old tool results before context window overflows
            before = len(messages)
            messages = self._messages = self._prune_context(messages)
            if len(messages) < before:
                yield {"type": "status", "message": f"Context pruned: {before} → {len(messages)} messages"}

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

                    # ── Auto-trigger web search on CVE / error / version ──
                    if self._should_search_web(tool_result):
                        yield {"type": "status", "message": "  [*] Auto-triggering web search..."}
                        try:
                            from ai_core.web_search import search_web_sync
                            from ai_core.poc_parser import parse_web_results
                            from ai_core.poc_sequencer import PoCSequencer

                            search_query = self._build_web_search_query(name, tool_result)
                            web_results = search_web_sync(search_query, max_results=3)
                            if web_results:
                                yield {"type": "status", "message": f"  [*] Web results: {len(web_results)} found"}

                                # ── 1. Parse raw PoC actions ─────────
                                poc_actions = parse_web_results(
                                    web_results, vault_addr=self.vault_addr or ""
                                )

                                # ── 2. Sequence into attack chains ────
                                poc_text = ""
                                chains = []
                                if poc_actions:
                                    sequencer = PoCSequencer()
                                    chains = sequencer.build_chains(poc_actions)
                                    yield {"type": "status", "message": f"  [!] {len(poc_actions)} PoC(s) → {len(chains)} attack chain(s)"}

                                    poc_parts = []
                                    for chain in chains:
                                        poc_parts.append(chain.to_agent_prompt(self.vault_addr or ""))
                                    poc_text = "\n".join(poc_parts)

                                    # ── 3. Auto-pilot: execute full chains ──
                                    if getattr(self, '_auto_pilot', False):
                                        for chain in chains:
                                            if chain.total_confidence == "low":
                                                continue
                                            yield {"type": "status", "message": f"  [>>] Auto-pilot chain: {chain.description}"}
                                            chain_results = []
                                            for step in chain.steps:
                                                poc_params = step.action.to_tool_params(self.vault_addr or "")
                                                yield {"type": "status", "message": f"       Step {step.step_index}: {step.action.method} {step.action.path}"}
                                                try:
                                                    poc_result = await self._tool_executor("run_raw_vault_request", poc_params)
                                                    chain_results.append({
                                                        "step": step.step_index,
                                                        "path": step.action.path,
                                                        "result": str(poc_result)[:500],
                                                    })
                                                    yield {"type": "tool_result", "message": str(poc_result)[:200]}
                                                except Exception as poc_exc:
                                                    yield {"type": "warning", "message": f"Chain step failed: {poc_exc}"}
                                                    break  # stop chain on failure

                                            # Feed chain results back to agent
                                            if chain_results:
                                                messages.append({
                                                    "role": "tool",
                                                    "content": json.dumps({
                                                        "chain_executed": chain.description,
                                                        "steps": chain_results,
                                                    }, ensure_ascii=False)[:2000],
                                                    "tool_call_id": f"call_chain_{hash(chain.chain_id) & 0x7FFFFFFF:08x}",
                                                })

                                # Build web+POC+chains content for the agent
                                chain_summary = [
                                    {"id": c.chain_id, "steps": len(c.steps),
                                     "description": c.description,
                                     "confidence": c.total_confidence}
                                    for c in chains
                                ] if chains else []

                                web_content = json.dumps({
                                    "query": search_query,
                                    "results": web_results,
                                    "poc_actions_count": len(poc_actions) if poc_actions else 0,
                                    "chains": chain_summary,
                                }, ensure_ascii=False)[:2000]

                                messages.append({
                                    "role": "tool",
                                    "content": web_content,
                                    "tool_call_id": f"call_web_{hash(search_query) & 0x7FFFFFFF:08x}",
                                })

                                # Add sequenced chain prompt for the agent
                                if poc_text:
                                    action = "Execute ALL steps without asking" if getattr(self, '_auto_pilot', False) else "Recommend which chains to execute"
                                    messages.append({
                                        "role": "user",
                                        "content": (
                                            f"{poc_text}\n\n"
                                            f"{action}. For multi-step chains, explain the "
                                            f"dependency flow (step 1 generates token → step 2 uses it)."
                                        ),
                                    })

                                # Mark as searched
                                self._searched_web.add(self._search_cache_key(name, tool_result))
                                for cve_match in __import__('re').finditer(
                                    r'CVE-\d{4}-\d{4,}', str(tool_result), __import__('re').IGNORECASE
                                ):
                                    self._searched_cves.add(cve_match.group(0).upper())
                        except Exception as exc:
                            yield {"type": "warning", "message": f"Web search failed: {exc}"}

                    # Parse result for a quick summary
                    result_summary = self._summarize_result(tool_result)

                    # Generate a unique tool call ID for API compliance
                    import uuid
                    call_id = f"call_{uuid.uuid4().hex[:12]}"

                    # Add to conversation — OpenAI/DeepSeek API format
                    messages.append({
                        "role": "assistant",
                        "content": response.get("content") or "",
                        "tool_calls": [{
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(arguments)},
                        }],
                    })
                    messages.append({
                        "role": "tool",
                        "content": tool_result[:2000],
                        "tool_call_id": call_id,
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
            "read_single_policy",
            "run_raw_vault_request",
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
            "read_single_policy", "run_privilege_escalation",
        }
        if name in token_tools and not self.token and not arguments.get("token"):
            return "No token. Ask: set token hvs.ABC..."

        # ---- inject real target (override any hallucinated one) ----
        if self.vault_addr and name in vault_tools:
            arguments["vault_addr"] = self.vault_addr

        # ---- inject best available token (global store > explicit) ----
        best_token = None
        try:
            from ai_core.dynamic_session import global_store
            best_token = global_store.get_best_token_value()
        except ImportError:
            pass
        if not best_token:
            best_token = self.token

        if best_token and name in token_tools:
            arguments["token"] = best_token
            # Update agent's own token view if escalated
            if best_token != self.token:
                self.token = best_token

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

        # ---- prevent infinite loops: same tool + same args > 3x ----
        call_tracker = getattr(self, '_call_tracker', None)
        if call_tracker is None:
            call_tracker = {}
            self._call_tracker = call_tracker
        call_key = f"{name}:{_hash_args(arguments)}"
        call_count = call_tracker.get(call_key, 0) + 1
        call_tracker[call_key] = call_count
        if call_count > 3:
            return (
                f"CALL LIMIT: '{name}' with the same arguments has been called "
                f"{call_count} times. STOP looping. Analyze previous results "
                f"and either escalate differently or report findings to user."
            )

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

    # ── web search auto-trigger ──────────────────────────────────────────

    @staticmethod
    def _search_cache_key(tool_name: str, result: str) -> str:
        """Stable key to prevent searching the same result twice."""
        import hashlib
        raw = f"{tool_name}|{str(result)[:200]}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _should_search_web(self, observation: str) -> bool:
        """Return True if the observation warrants a web search.

        Triggers on:
        - CVE IDs (e.g. CVE-2024-2048) not yet searched
        - HTTP 403/500/permission denied errors not yet searched
        - Vault version strings without existing exploit info
        """
        if getattr(self, '_disable_web', False):
            return False
        if not observation:
            return False

        # Don't search for our own web search results (prevent loop)
        if '"query"' in observation and '"results"' in observation:
            return False

        obs_lower = observation.lower()

        # Check: contains a CVE ID?
        cve_match = __import__('re').search(r'CVE-\d{4}-\d{4,}', observation, __import__('re').IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
            if cve_id not in self._searched_cves:
                return True

        # Check: HTTP error codes that might benefit from web search
        if any(err in obs_lower for err in ("403", "500", "permission denied", "access denied")):
            err_key = self._search_cache_key("error", observation[:200])
            if err_key not in self._searched_web:
                return True

        # Check: version string found, possibly need exploit info
        if "version:" in obs_lower or "vault version" in obs_lower:
            ver_key = self._search_cache_key("version", observation[:200])
            if ver_key not in self._searched_web:
                return True

        return False

    def _build_web_search_query(self, tool_name: str, result: str) -> str:
        """Build a targeted web search query from the observation context."""
        import re

        # Extract CVE ID
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', result, re.IGNORECASE)
        if cve_match:
            return f"HashiCorp Vault {cve_match.group(0)} exploit"

        # Error-based query
        if "permission denied" in result.lower():
            return f"HashiCorp Vault permission denied fix {tool_name}"

        # Version-based query
        ver_match = re.search(r'(?:version|vault)[:\s]+(\d+\.\d+\.\d+)', result, re.IGNORECASE)
        if ver_match:
            return f"HashiCorp Vault {ver_match.group(1)} vulnerabilities exploits"

        # Generic fallback
        return f"HashiCorp Vault {tool_name} error"

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

    # ── context pruning ──────────────────────────────────────────────────

    def _prune_context(self, messages: list[dict]) -> list[dict]:
        """Trim old tool results when the message list grows too large.

        Strategy: when the message count exceeds ``MAX_CONTEXT_MESSAGES``,
        locate the oldest *tool-call block* (assistant + tool + user follow-up),
        replace it with a short summary injected into the preceding user
        message, and remove the block.  The ``PRUNE_KEEP_RECENT`` most recent
        messages are always left untouched.
        """
        if len(messages) <= self.MAX_CONTEXT_MESSAGES:
            return messages

        # Find the boundary: everything before this index is eligible for pruning
        prune_boundary = max(0, len(messages) - self.PRUNE_KEEP_RECENT)

        # Locate the oldest tool-call block within the prune-eligible range.
        # A block is: assistant(with tool_calls) → tool → user(follow-up)
        block_start: int | None = None
        for i in range(prune_boundary - 2):
            if (
                messages[i].get("role") == "assistant"
                and messages[i].get("tool_calls")
                and i + 1 < len(messages)
                and messages[i + 1].get("role") == "tool"
            ):
                block_start = i
                break

        if block_start is None:
            return messages  # nothing to prune safely

        # Determine block end: after the tool result, there is often a user
        # follow-up message; include it if present.
        block_end = block_start + 2  # assistant + tool
        if block_end < len(messages) and messages[block_end].get("role") == "user":
            block_end += 1

        # Build a one-line summary from the tool call block
        tool_name = "unknown"
        for tc in messages[block_start].get("tool_calls", []):
            fn = tc.get("function", {}) if "function" in tc else tc
            tool_name = fn.get("name", tool_name)
        tool_content = messages[block_start + 1].get("content", "")[:150]
        summary = (
            f"[CONTEXT PRUNE] Earlier tool '{tool_name}' result summarized: "
            f"{tool_content[:120]}..."
        )

        # Inject summary into the message just before the block
        prev_msg = messages[block_start - 1] if block_start > 0 else None
        if prev_msg and prev_msg.get("role") == "user":
            prev_msg["content"] = (
                prev_msg.get("content", "")[:500] + "\n\n" + summary
            )
        else:
            # No good anchor — just insert a system note
            messages.insert(block_start, {
                "role": "user",
                "content": f"SYSTEM NOTE: {summary}",
            })
            block_end += 1  # shift because we inserted

        # Remove the pruned block
        del messages[block_start : block_end]

        # Recurse if still over limit (shouldn't normally happen)
        if len(messages) > self.MAX_CONTEXT_MESSAGES:
            return self._prune_context(messages)

        return messages

    # ── multi-step plan execution ────────────────────────────────────────

    def pause(self) -> None:
        """Pause plan execution after the current step finishes."""
        self._paused_flag.clear()

    async def resume(self) -> None:
        """Resume a paused plan."""
        self._paused_flag.set()

    def abort(self) -> None:
        """Abort plan execution immediately."""
        self._aborted_flag = True
        self._paused_flag.set()  # unblock any wait so the loop can see _aborted_flag

    async def run_with_plan(self, plan: Any) -> AsyncIterator[dict]:
        """Execute a full ``PentestPlan`` autonomously.

        Yields events:
            {"type": "phase_start"|"phase_end", "phase": str}
            {"type": "step_start"|"step_end", "step": dict, "index": int, "total": int}
            {"type": "tool_call"|"tool_result", ...}
            {"type": "plan_complete", "plan": dict, "status": str}
        """
        from ai_core.planning.plan_schema import PentestPlan, PlanStatus

        self._phase_tracker = PhaseTracker()
        self._plan_tool_call_count = 0
        self._aborted_flag = False
        self._paused_flag.set()  # not paused

        plan.status = PlanStatus.RUNNING
        self.memory.active_plan = plan

        yield {"type": "status", "message": f"Executing plan '{plan.id}' — {plan.total_steps} steps"}
        yield {"type": "status", "message": plan.attack_narrative or "Starting attack plan..."}

        last_phase: AttackPhase | None = None

        for i, step in enumerate(plan.steps):
            # Check abort
            if self._aborted_flag:
                plan.status = PlanStatus.FAILED
                yield {"type": "plan_complete", "plan": plan.to_dict(), "status": "aborted"}
                return

            # Check pause — block until resumed
            await self._paused_flag.wait()

            # Check plan tool call limit
            self._plan_tool_call_count += 1
            if self._plan_tool_call_count > self.MAX_PLAN_TOOL_CALLS:
                yield {
                    "type": "warning",
                    "message": f"Plan exceeded max tool calls ({self.MAX_PLAN_TOOL_CALLS})",
                }
                plan.status = PlanStatus.FAILED
                yield {"type": "plan_complete", "plan": plan.to_dict(), "status": "limit_exceeded"}
                return

            plan.current_step_index = i

            # Phase transition tracking
            step_phase = AttackPhase(step.phase.value) if hasattr(step.phase, 'value') else AttackPhase.AUDIT
            if step_phase != last_phase:
                if last_phase:
                    yield {"type": "phase_end", "phase": last_phase.value}
                self._phase_tracker.transition_to(step_phase)
                yield {"type": "phase_start", "phase": step_phase.value}
                last_phase = step_phase

            yield {
                "type": "step_start",
                "step": {"tool": step.tool, "reason": step.reason, "priority": step.priority},
                "index": i,
                "total": plan.total_steps,
            }

            # --- tool call ---
            params_preview = dict(step.params) if step.params else {}
            if self.vault_addr and "vault_addr" not in params_preview:
                params_preview["vault_addr"] = self.vault_addr
            if self.token and "token" not in params_preview:
                params_preview["token"] = self.token
            yield {
                "type": "tool_call",
                "message": f"{step.tool}({json.dumps(params_preview, ensure_ascii=False)})",
                "tool": step.tool,
                "params": params_preview,
            }

            result = await self._execute_planned_step(step, plan)

            # --- tool result ---
            yield {"type": "tool_result", "message": result.get("raw", result.get("message", ""))}

            if result["status"] == "success":
                yield {"type": "step_end", "status": "success", "result": result}
            else:
                outcome = self._handle_step_failure(step, result)
                if outcome == "abort":
                    plan.status = PlanStatus.FAILED
                    yield {"type": "plan_complete", "plan": plan.to_dict(), "status": "failed"}
                    return
                if outcome == "skip":
                    yield {"type": "step_end", "status": "skipped", "reason": result.get("message")}
                    continue
                if outcome == "retry" and step.max_retries > 0:
                    step.max_retries -= 1
                    yield {"type": "step_end", "status": "retrying", "retries_left": step.max_retries}
                    # Re-attempt the same step
                    yield {
                        "type": "tool_call",
                        "message": f"{step.tool}(retry)",
                        "tool": step.tool,
                        "params": params_preview,
                    }
                    result2 = await self._execute_planned_step(step, plan)
                    yield {"type": "tool_result", "message": result2.get("raw", result2.get("message", ""))}
                    if result2["status"] != "success":
                        yield {"type": "step_end", "status": "failed", "result": result2}
                        if step.on_failure == "abort":
                            plan.status = PlanStatus.FAILED
                            yield {"type": "plan_complete", "plan": plan.to_dict(), "status": "failed"}
                            return
                    else:
                        yield {"type": "step_end", "status": "success", "result": result2}
                else:
                    yield {"type": "step_end", "status": "failed", "result": result}

        if last_phase:
            yield {"type": "phase_end", "phase": last_phase.value}

        plan.status = PlanStatus.COMPLETED
        self.memory.archive_plan(plan)
        yield {"type": "plan_complete", "plan": plan.to_dict(), "status": "completed"}

    async def _execute_planned_step(self, step: Any, plan: Any) -> dict:
        """Execute a single PlannedStep and return the result dict."""
        params = dict(step.params) if step.params else {}
        if self.vault_addr and "vault_addr" not in params:
            params["vault_addr"] = self.vault_addr
        if self.token and "token" not in params:
            params["token"] = self.token

        tool_result = ""
        if self._tool_executor:
            try:
                tool_result = await self._tool_executor(step.tool, params)
            except Exception as exc:
                tool_result = json.dumps({"status": "error", "message": str(exc)})
        else:
            tool_result = json.dumps({"status": "error", "message": "no tool executor configured"})

        try:
            data = json.loads(tool_result)
            status = data.get("status", "error")
            return {"status": status, "message": data.get("message", ""),
                    "data": data, "raw": tool_result[:500]}
        except json.JSONDecodeError:
            return {"status": "unknown", "message": tool_result[:300],
                    "data": {}, "raw": tool_result[:300]}

    def _handle_step_failure(self, step: Any, result: dict) -> str:
        """Decide what to do after a step failure.

        Returns one of: "abort" | "skip" | "retry" | "continue"
        """
        on_failure = getattr(step, "on_failure", "abort") or "abort"
        return on_failure


def _hash_args(args: dict) -> str:
    """Stable hash of tool arguments for duplicate-call detection."""
    if not args:
        return "noargs"
    raw = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return str(hash(raw))
