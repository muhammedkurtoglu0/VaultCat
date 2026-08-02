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
import re
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
- Be conversational. If the user greets you or chats casually, just reply — don't jump into scanning.
- Be direct, practical, and confident. No fluff, no disclaimers, no "I apologize".
- When you discover findings, present them as TABLES (markdown).
- If something fails, explain why and suggest an alternative.
- When you have findings, present them clearly. When you're done, say so.

## UNDERSTANDING USER INTENT
The user speaks naturally — understand what they want, not what keywords they used.
They might ask for a scan, a fix, an explanation, or just chat. Figure it out from context.

## YOUR TOOLKIT
You have 20+ pentest tools covering:
- **recon**: run_unauthenticated_recon, run_hijack_scan, run_env_scan
- **audit**: run_capability_audit, run_priv_esc_scan, run_kv_enumeration, run_ttl_audit, run_auth_config_audit, run_policy_auditor, read_single_policy
- **active**: run_raw_vault_request, run_privilege_escalation, run_secret_exfiltration, run_database_credential_harvest, run_cloud_key_exfiltration
- **meta**: web_search, get_findings, get_risk_score, list_active_modules, run_active_module

## SMART CAPABILITIES
- **Web Search**: Auto-trigger on CVEs, errors, unknown versions, or unrecognized credentials.
- **PoC Execution**: When web results contain curl/API calls, extract and offer to execute them.
- **Attack Chains**: When PoCs depend on each other, sequence them automatically.

## ATTACK CHAINS (execute automatically — don't just suggest!)
When you discover credentials, DON'T stop at listing them. Follow the chain:

**KV secret → DB credentials → Database Pivot → Reverse Shell:**
1. Find DB credentials (KV, env scan, database_credential_harvest)
2. IMMEDIATELY call `run_database_pivot` with {host, port, user, password, db_name}
3. If connected + SUPERUSER → IMMEDIATELY call `run_reverse_shell` with same params
4. Start with recon commands: whoami, id, uname -a, ls /, env
5. Then escalate: read /etc/shadow, find SSH keys, check cloud metadata

**Token → Privilege Escalation → Root → Full Dump:**
1. Audit token capabilities
2. If sudo on sys/policies/acl/* → run_privilege_escalation (autonomous takeover)
3. With root token → run_secret_exfiltration, run_database_credential_harvest

**AppRole → Token → Audit:**
1. role_id + secret_id → POST auth/approle/login → get token
2. Then capability audit + KV enumeration

## METHODOLOGY
1. RECON first — always start with unauthenticated recon
2. If token available → audit capabilities, enumerate KV, check TTLs, analyze policies
3. If DB credentials found → **IMMEDIATELY chain: run_database_pivot → run_reverse_shell**
4. If multiple tokens → compare privileges, try escalation paths
5. If blocked → web search for alternatives, mutate attack paths
6. **WHEN UNKNOWN DATA FOUND → WEB SEARCH**: If you see a token/key/secret you don't recognize, call `web_search` to identify it. Example queries:
   - "sk_live_ token prefix what platform how to exploit pentest"
   - "ghp_ token what is it GitHub API exploit"
   - "eyJ JWT token exploitation pentest"
   This is how the pentest escapes Vault and pivots to GitHub, AWS, Stripe, databases, etc.
7. When done or user asks → generate report, provide remediation advice

## CREDENTIAL TYPE RECOGNITION
When a user gives you a string, FIRST identify its type by FORMAT before trying to use it:

### Vault-native formats
| Format | Type | What to do |
|---|---|---|
| `hvs.xxx...` (starts with hvs.) | Vault token | Use as token for API calls; try lookup-self first |
| `s.xxx...` (starts with s.) | Legacy Vault token | Same as hvs. token |
| 64 hex chars `[0-9a-f]{64}` | **Unseal key / Shamir share** | Check seal status; use with unseal or generate-root |
| UUID `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | AppRole role_id | Pair with secret_id for approle login |
| Long base64 string (no hvs. prefix) | AppRole secret_id | Pair with role_id for approle login |

### External platform credentials (pivot opportunities!)
When you discover a credential that does NOT match Vault formats, it may unlock other platforms:

| Format | Likely Platform | How to verify & exploit |
|---|---|---|
| `ghp_xxx...` (36+ chars) | **GitHub personal access token** | `curl -H "Authorization: token <token>" https://api.github.com/user` |
| `github_pat_xxx...` | **GitHub fine-grained token** | Same as above; check `X-OAuth-Scopes` header |
| `gho_xxx...` | **GitHub OAuth token** | Used by GitHub Apps/OAuth — check user + repos |
| `ghs_xxx...` | **GitHub installation token** | Temp token from GitHub App — check org access |
| `sk_live_xxx...` / `sk_test_xxx...` | **Stripe secret key** | `curl https://api.stripe.com/v1/charges -u <key>:` |
| `eyJ...` (3-part base64url) | **JWT / JWS token** | Decode at jwt.io; check `alg`, `sub`, `exp`, `scope` |
| `AIza...` (39 chars) | **Google API key** | Check which APIs are enabled: `curl "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<key>"` |
| `AKIA...` (20 chars) | **AWS Access Key ID** | Pair with Secret Access Key; `aws sts get-caller-identity` |
| `-----BEGIN ... PRIVATE KEY-----` | **SSH/TLS private key** | Check if it matches known hosts; try `ssh -i <key>` |
| `postgresql://user:pass@host/db` | **DB connection string** | Direct database access — use `run_database_pivot` |

### UNKNOWN credential → WEB SEARCH!
If you see a credential format you don't recognize:
1. **IMMEDIATELY call `web_search`** with a query like: "<prefix> token format what is it how to exploit"
2. Example: you find `sk-ant-api03-xxx...` → search "sk-ant-api03 token format what is it" → discover it's Anthropic API key
3. **NEVER just say "bilinmeyen bir token buldum"** — research it first, then tell the user what it is AND how to exploit it
4. This is how we escape Vault and pivot to other platforms

**UNSEAL KEY (64 hex chars = Shamir secret share):**
- These are NOT tokens — they CANNOT be used for API authentication
- First: check `sys/seal-status` (unauthenticated). If sealed → unseal with `sys/unseal` (use run_active_module: vault_seal.unseal_vault)
- If already unsealed: use `sys/generate-root/attempt` + `sys/generate-root/update` + `decode_generate_root_otp` to derive a ROOT TOKEN
- The unseal key proves physical access/insider knowledge — it's a CRITICAL finding
- NEVER try to use a hex string (64 chars) as a Vault token, username, or password — it won't work

## CRITICAL RULES
- NO target → ask user to set one.
- NO token → start with unauthenticated recon, suggest finding one.
- User gives you a string → identify its format first, then act (see credential tables above).
- **UNKNOWN CREDENTIAL → WEB SEARCH**: If you find a credential format you don't recognize, research it via `web_search` — don't just say "bilinmeyen token". Pivot to other platforms (GitHub, AWS, Stripe, etc.).
- System auto-injects the best available token. Only pass token explicitly when you need a SPECIFIC one.
- **Hijack scan requires user approval**: NEVER run `run_hijack_scan` without asking FIRST. Never scan system-wide paths like `/`, `C:/`, `C:/Users`.
- NEVER guess IPs or tokens — use only what's provided or discovered.

## TOKEN PARADOX (READ THIS)
If the user provides a ROOT or admin token, the capability audit WILL report
"CRITICAL: token has sudo/root on *". This is EXPECTED — it's not a vulnerability,
it's the nature of the credential the user gave you. When this happens:
1. ACKNOWLEDGE it: "This assessment used a root/admin token, so wildcard sudo
   findings are expected — they reflect the token's legitimate privilege, not a
   discovered vulnerability."
2. SUGGEST re-testing with a restricted token: "For a realistic pentest, re-run
   with a low-privilege token (e.g. read-only) to discover actual privilege
   escalation paths."
3. REPORT what a LOW-privilege attacker could do differently: "With a restricted
   token, the attack surface would be..."
4. ALWAYS execute exploit modules (run_privilege_escalation, run_secret_exfiltration,
   run_database_credential_harvest) after capability audit — don't just observe,
   exploit where the audit finds high-value paths.
## HANDLING RESTRICTED TOKENS (everything returns 403)
**CRITICAL: This section ONLY applies when you HAVE a token.**
If you have NO token, skip this entire section — you are doing unauthenticated recon.
DO NOT brute-force paths without a token — every request will 403 and it's a waste.

If capability audit fails (permission denied) AND lookup-self returns 403
AND you actually have a token:
1. This is a RESTRICTED token — it has VERY specific, narrow permissions
2. **Step 1: Try `run_kv_enumeration` with kv_path="secret/"** — many restricted tokens are KV-only readers
3. **Step 2: Try `run_raw_vault_request(POST, auth/token/create)`** — some tokens are "token factory" tokens that can only create child tokens. Body: `{"policies": ["default"], "ttl": "1h", "display_name": "escalated"}`
4. **Step 3: Try `run_raw_vault_request(GET, database/creds/app-admin)`** — some tokens are DB credential readers
5. If all three fail → report: "This token is highly restricted. No accessible paths found."
   DO NOT brute-force more paths — 3 is enough. Move on.

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
    MAX_CONTEXT_MESSAGES = 100  # prune when message count exceeds this
    PRUNE_KEEP_RECENT = 24     # keep the most recent N messages during pruning
    MIN_TURNS_TO_KEEP = 3      # never prune the last N complete turns
    TOOL_RESULT_MAX_CHARS = 800  # truncate tool results to this many chars

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
        self._session_queries: set[str] = set()  # normalized queries searched this session

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

        if context_changed:
            # Reset per-target guards so the new target gets a clean slate.
            # Without this, _recon_done=True from a previous target would block
            # recon on the new target, and stale _call_tracker entries would
            # prematurely trigger CALL LIMIT errors.
            self._recon_done = False
            self._call_tracker = {}
            self._ua_probe_count = 0  # reset unauthenticated probe counter
            self._searched_web.clear()
            self._searched_cves.clear()
            self._session_queries.clear()
            self._get_findings_count = 0
            self._plan_tool_call_count = 0
            self._phase_tracker = PhaseTracker()

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
                # ── Collect all tool results first, then append ONE assistant
                #     message with ALL tool_calls + ALL tool results together.
                #     This keeps the message list compliant with
                #     OpenAI/DeepSeek API format even after context pruning.
                import uuid
                _collected: list[dict] = []  # {name, arguments, result, enrichment_notes, call_id}
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

                                            # Feed chain results back to agent as user context
                                            if chain_results:
                                                messages.append({
                                                    "role": "user",
                                                    "content": json.dumps({
                                                        "chain_executed": chain.description,
                                                        "steps": chain_results,
                                                    }, ensure_ascii=False)[:2000],
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
                                    "role": "user",
                                    "content": f"[Web search: {search_query}] {web_content[:1500]}",
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

                    # ── web_search context enrichment ─────────────────
                    # When the LLM explicitly calls web_search, inject
                    # supplementary context notes (repeat-detection,
                    # version-mismatch warnings).  The LLM's query and
                    # parameters are NEVER modified — only informational
                    # user messages are appended.
                    enrichment_notes: list[str] = []
                    if name == "web_search":
                        query = str(arguments.get("query", "")).strip()
                        if query:
                            repeat_note = self._note_repeat_query(query)
                            if repeat_note:
                                enrichment_notes.append(repeat_note)

                            version_note = self._note_version_mismatch(query)
                            if version_note:
                                enrichment_notes.append(version_note)

                    # Parse result for a quick summary
                    result_summary = self._summarize_result(tool_result)

                    call_id = f"call_{uuid.uuid4().hex[:12]}"
                    _collected.append({
                        "name": name,
                        "arguments": arguments,
                        "result": tool_result,
                        "result_summary": result_summary,
                        "enrichment_notes": enrichment_notes,
                        "call_id": call_id,
                    })

                # ── If all tool calls were blocked, prompt and continue ──
                if not _collected:
                    messages.append({
                        "role": "user",
                        "content": (
                            "SYSTEM: All requested tools were blocked. "
                            "Tell the user what's needed in natural language."
                        ),
                    })
                    continue

                # ── Append ONE assistant message with ALL tool_calls ──
                messages.append({
                    "role": "assistant",
                    "content": response.get("content") or "",
                    "tool_calls": [
                        {
                            "id": rec["call_id"],
                            "type": "function",
                            "function": {
                                "name": rec["name"],
                                "arguments": json.dumps(rec["arguments"]),
                            },
                        }
                        for rec in _collected
                    ],
                })

                # ── Append ALL tool results (summarized) ───────────────
                for rec in _collected:
                    messages.append({
                        "role": "tool",
                        "content": self._summarize_tool_result_for_context(
                            rec["result"], rec["name"]
                        ),
                        "tool_call_id": rec["call_id"],
                    })

                # ── Append enrichment notes ────────────────────────────
                for rec in _collected:
                    for note in rec["enrichment_notes"]:
                        messages.append({"role": "user", "content": note})

                # ── Single analysis prompt ─────────────────────────────
                summaries = "; ".join(
                    f"{r['name']}: {r['result_summary']}" for r in _collected
                )
                messages.append({
                    "role": "user",
                    "content": (
                        f"Tools returned: {summaries}\n\n"
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
            # Normalize: strip path/query from vault_addr (user may paste UI URLs)
            addr = self.vault_addr
            if "://" in addr:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(addr)
                addr = urlunparse((p.scheme, p.netloc, "", "", "", ""))
            arguments["vault_addr"] = addr

        # ---- inject best available token (global store > agent default) ----
        # CRITICAL: respect the LLM's explicit token choice.
        # If the LLM passed a real-looking token (hvs./s. prefix, not truncated),
        # it was explicitly chosen by the user or the agent — use it as-is.
        # Only inject the global-store best token when the LLM didn't specify one
        # or used a placeholder.
        llm_token = arguments.get("token", "")
        llm_has_real_token = (
            isinstance(llm_token, str)
            and len(llm_token) >= 24
            and (llm_token.startswith("hvs.") or llm_token.startswith("hvb.") or llm_token.startswith("s."))
        )

        best_token = None
        if not llm_has_real_token:
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

        # ---- prevent unauthenticated brute-force: max 8 raw requests without auth ----
        if name == "run_raw_vault_request":
            # Check if ANY token is available: via set-token, chat-provided, or global store
            has_any_token = bool(
                self.token
                or (isinstance(arguments.get("token"), str)
                    and len(str(arguments.get("token"))) >= 24
                    and (str(arguments.get("token")).startswith("hvs.")
                         or str(arguments.get("token")).startswith("s.")))
            )
            if not has_any_token:
                try:
                    from ai_core.dynamic_session import global_store
                    if global_store.get_best_token_value():
                        has_any_token = True
                except ImportError:
                    pass

            if not has_any_token:
                ua_probe_count = getattr(self, '_ua_probe_count', 0)
                ua_probe_count += 1
                self._ua_probe_count = ua_probe_count
                if ua_probe_count > 8:
                    return (
                        f"UNATHENTICATED PROBE LIMIT: {ua_probe_count} raw requests without "
                        f"a token. Most Vault endpoints return 403 without auth. "
                        f"STOP probing. Report findings from recon scanners only "
                        f"and suggest the user provide a token."
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
            parts.append(f"Available token: {self.token}")
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
        - HTTP 5xx server errors not yet searched
        - Vault version strings without existing exploit info
        - External platform credentials/keys not matching Vault formats
          (GitHub tokens, Stripe keys, JWTs, generic API keys, etc.)
          → enables pivoting from Vault to other platforms

        Deliberately does NOT trigger on 403 / permission denied: during
        unauthenticated testing a 403 is Vault's *expected* answer, and
        searching for it produced noise queries like
        "HashiCorp Vault permission denied fix run_raw_vault_request".
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

        # Check: server-side errors (5xx) that might indicate a known bug/CVE
        if '"http_status": 5' in obs_lower or "http 5" in obs_lower or " 500 " in obs_lower:
            err_key = self._search_cache_key("error", observation[:200])
            if err_key not in self._searched_web:
                return True

        # Check: version string found, possibly need exploit info
        if "version:" in obs_lower or "vault version" in obs_lower:
            ver_key = self._search_cache_key("version", observation[:200])
            if ver_key not in self._searched_web:
                return True

        # ── External platform credential detection ──────────────────────
        # When the tool discovers a secret/token/key that doesn't match
        # Vault-native formats (hvs., s., UUID, 64-char hex), it's likely
        # a credential for an external platform.  Auto-search so the agent
        # can tell the user what it is and how to pivot.
        cred_type = self._detect_external_credential(observation)
        if cred_type:
            cred_key = self._search_cache_key("credential", cred_type + observation[:200])
            if cred_key not in self._searched_web:
                return True

        return False

    # ── external credential detection ────────────────────────────────────

    # Patterns for platform-specific credentials that, when discovered inside
    # Vault, indicate a pivot opportunity.  Grouped by platform so the search
    # query can be targeted.
    _EXTERNAL_CREDENTIAL_PATTERNS: list[tuple[str, str, re.Pattern]] = [
        # GitHub  (https://docs.github.com/en/authentication)
        # Real tokens are 36+ chars body, but we accept 8+ to catch
        # truncated samples / placeholders in tool output.
        ("GitHub", "personal access token", re.compile(r'\bghp_[A-Za-z0-9]{8,}\b')),
        ("GitHub", "fine-grained token", re.compile(r'\bgithub_pat_[A-Za-z0-9_]{8,}\b')),
        ("GitHub", "OAuth / app token", re.compile(r'\bgho_[A-Za-z0-9]{8,}\b')),
        ("GitHub", "installation token", re.compile(r'\bghs_[A-Za-z0-9]{8,}\b')),
        ("GitHub", "refresh token", re.compile(r'\bghr_[A-Za-z0-9]{8,}\b')),

        # Stripe
        ("Stripe", "secret key", re.compile(r'\b(?:sk_live|sk_test)_[A-Za-z0-9]{8,}\b')),
        ("Stripe", "publishable key", re.compile(r'\bpk_(?:live|test)_[A-Za-z0-9]{8,}\b')),

        # AI/LLM API keys (commonly stored in Vault alongside app secrets)
        ("Anthropic", "API key", re.compile(r'\bsk-ant-(?:api|admin|user)[0-9]{2,3}-[A-Za-z0-9_-]{20,}\b')),
        ("OpenAI", "API key", re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b')),
        ("HuggingFace", "API key", re.compile(r'\bhf_[A-Za-z0-9]{20,}\b')),

        # JWT / JWS (eyJ... base64url header.payload.signature)
        ("JWT", "JSON Web Token", re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b')),

        # AWS (access key IDs — 20-char uppercase alphanumeric starting with AKIA/ASIA)
        ("AWS", "access key ID", re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
        ("AWS", "secret access key", re.compile(r'\baws_(?:secret_access_key|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{20,})["\']?', re.IGNORECASE)),

        # Google
        ("Google", "API key", re.compile(r'\bAIza[0-9A-Za-z_-]{20,}\b')),

        # Slack
        ("Slack", "webhook URL", re.compile(
            r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+',
            re.IGNORECASE)),

        # Generic API key / token assignments
        ("API key", "generic key assignment", re.compile(
            r'\b(?:api_key|apikey|api_token|auth_token|access_token|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{8,})["\']?',
            re.IGNORECASE)),

        # SSH private keys
        ("SSH", "private key", re.compile(
            r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
            re.IGNORECASE)),

        # Database connection strings
        ("Database", "connection string", re.compile(
            r'(?:postgres(?:ql)?|mysql|mssql|oracle|mongodb)://[A-Za-z0-9._-]+:[^\s@]+@[^\s/]+',
            re.IGNORECASE)),
        ("Database", "JDBC URL", re.compile(r'jdbc:(?:postgresql|mysql|sqlserver|oracle)://[^\s]+', re.IGNORECASE)),
    ]

    @classmethod
    def _detect_external_credential(cls, observation: str) -> str | None:
        """Return the platform name if *observation* contains an
        external-platform credential that the agent should research.

        Vault-native formats (hvs., s., UUID, 64-char hex, approle paths)
        are deliberately excluded — those are already handled by the
        agent's credential recognition table.
        """
        # Skip if the observation is dominated by Vault-native tokens
        # (avoid false positives when the tool returns a Vault response
        #  that happens to contain a base64 blob).
        vault_native_markers = ['"auth"', '"client_token"', '"policies"',
                                 '"lease_duration"', 'approle/login']
        native_score = sum(1 for m in vault_native_markers if m in observation)
        if native_score >= 3:
            return None

        for platform, kind, pattern in cls._EXTERNAL_CREDENTIAL_PATTERNS:
            if pattern.search(observation):
                return platform

        return None

    # ── search query builder ────────────────────────────────────────────

    def _build_web_search_query(self, tool_name: str, result: str) -> str:
        """Build a targeted web search query from the observation context."""
        import re

        # ── Credential identification (new — pivot to other platforms) ──
        cred_type = self._detect_external_credential(result)
        if cred_type:
            # Extract a sample of the matched text for context
            sample = ""
            for platform, kind, pattern in self._EXTERNAL_CREDENTIAL_PATTERNS:
                m = pattern.search(result)
                if m and platform == cred_type:
                    sample = m.group(0)
                    break
            # Build a targeted query: what is this, how to exploit it
            if sample:
                # Use a short prefix so we don't leak the full secret to
                # the search engine, but keep enough to identify the type.
                prefix = sample[:12] if len(sample) > 12 else sample[:6]
                return f"{cred_type} token starting with {prefix} what is it how to exploit pentest"
            return f"{cred_type} credential found in Vault how to exploit pentest pivot"

        # Extract CVE ID
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', result, re.IGNORECASE)
        if cve_match:
            return f"HashiCorp Vault {cve_match.group(0)} exploit"

        # Version-based query
        ver_match = re.search(r'(?:version|vault)[:\s]+(\d+\.\d+\.\d+)', result, re.IGNORECASE)
        if ver_match:
            return f"HashiCorp Vault {ver_match.group(1)} vulnerabilities exploits"

        # Generic fallback
        return f"HashiCorp Vault {tool_name} error"

    # ── web_search context enrichment ─────────────────────────────────────

    @staticmethod
    def _normalize_query(query: str) -> str:
        """Normalize a query for dedup: lowercase, trim, collapse whitespace."""
        return " ".join(query.strip().lower().split())

    def _note_repeat_query(self, query: str) -> str | None:
        """Return a context note if *query* was already searched this session.

        The query is **never** blocked or modified — this only produces an
        informational note so the LLM can avoid re-analyzing stale results.
        """
        norm = self._normalize_query(query)
        if norm in self._session_queries:
            return (
                f"[WEB_SEARCH NOTE] This query was already searched earlier in "
                f"this session: \"{query}\". The results may be returning from "
                f"the 24-hour cache. If the previous search was adequate, "
                f"reference those findings instead of re-analyzing."
            )
        # Track for future calls
        self._session_queries.add(norm)
        return None

    def _note_version_mismatch(self, query: str) -> str | None:
        """Return a version-mismatch note if *query* references a Vault version
        different from what was previously discovered in this session.

        The LLM's query is **never** changed — this is purely an informational
        note for the LLM to consider.
        """
        import re

        # Extract version from query (e.g. "1.15.3" or "v1.18.0")
        m = re.search(r'\bv?(\d+\.\d+\.\d+)\b', query)
        if not m:
            return None
        query_version = m.group(1)

        # Collect known versions from memory findings and global report
        known_versions: set[str] = set()

        # 1. Memory findings
        for f in self.memory.findings:
            title = f.get("title", "")
            desc = f.get("description", "")
            for v in re.findall(r'\b\d+\.\d+\.\d+\b', f"{title} {desc}"):
                known_versions.add(v)

        # 2. Global report findings
        try:
            from core.report import findings as global_findings
            for f in global_findings:
                title = f.get("title", "")
                desc = f.get("description", "")
                for v in re.findall(r'\b\d+\.\d+\.\d+\b', f"{title} {desc}"):
                    known_versions.add(v)
        except ImportError:
            pass

        # 3. Memory context
        for key in ("vault_version", "version", "detected_version"):
            ctx_val = self.memory.get_context(key)
            if ctx_val:
                for v in re.findall(r'\b\d+\.\d+\.\d+\b', str(ctx_val)):
                    known_versions.add(v)

        # Check for mismatch
        for kv in known_versions:
            if kv != query_version:
                return (
                    f"[WEB_SEARCH NOTE] The LLM's query references Vault version "
                    f"{query_version}, but this session previously detected version "
                    f"{kv}. There may be a version mismatch — verify the correct "
                    f"target version before acting on search results."
                )

        return None

    # ── completion marker ─────────────────────────────────────────────────

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

    # ── tool result summarization ─────────────────────────────────────────

    @staticmethod
    def _summarize_tool_result_for_context(result: str, tool_name: str) -> str:
        """Compress a tool result so it doesn't blow up the context window.

        Full JSON blobs (5K-15K chars) from get_findings, recon scans etc.
        are truncated to the most relevant fields.  This lets the agent
        run 20-30 steps without hitting token limits.
        """
        max_chars = PentestAgent.TOOL_RESULT_MAX_CHARS
        if len(result) <= max_chars:
            return result

        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            # Not JSON — just truncate
            return result[:max_chars] + "\n[...truncated]"

        if not isinstance(data, dict):
            return result[:max_chars]

        # ── Per-tool compression rules ────────────────────────────────
        if tool_name == "get_findings":
            # Keep severity counts + top 5 critical/high titles
            findings = data.get("findings", [])
            sev_counts: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "?")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            critical_high = [
                f"[{f.get('severity','?')}] {f.get('title','')[:80]}"
                for f in findings
                if f.get("severity") in ("CRITICAL", "HIGH")
            ][:5]
            compact = {
                "total": data.get("total", len(findings)),
                "summary": sev_counts,
                "top_findings": critical_high,
            }
            return json.dumps(compact, ensure_ascii=False)

        if tool_name in ("run_unauthenticated_recon", "run_capability_audit",
                         "run_kv_enumeration", "run_priv_esc_scan"):
            # Keep status + findings count + first finding summary
            findings = data.get("findings", [])
            compact = {
                "status": data.get("status", "?"),
                "findings_count": data.get("findings_count", len(findings)),
                "key_titles": [f.get("title", "")[:100] for f in findings[:3]],
            }
            return json.dumps(compact, ensure_ascii=False)

        # Generic: keep status + message, drop raw evidence
        compact = {
            k: v for k, v in data.items()
            if k in ("status", "message", "findings_count", "total",
                      "risk_score", "risk_grade", "threat_count")
        }
        if not compact:
            return result[:max_chars]
        return json.dumps(compact, ensure_ascii=False)

    # ── context pruning ──────────────────────────────────────────────────

    def _prune_context(self, messages: list[dict]) -> list[dict]:
        """Trim old completed turns when the message list grows too large.

        A "turn" is: user_msg → assistant(with tool_calls) → tool×(N) → user(follow-up)

        Only COMPLETE turns are pruned — never the current in-progress turn.
        The ``MIN_TURNS_TO_KEEP`` most recent turns are always preserved.
        After pruning, the message list is validated: if any tool message is
        orphaned (no preceding assistant with matching tool_calls), the prune
        is rolled back to avoid 400 API errors.
        """
        if len(messages) <= self.MAX_CONTEXT_MESSAGES:
            return messages

        # ── 1. Identify complete turns ──────────────────────────────────
        # A turn starts at a user message that precedes an assistant with
        # tool_calls, and ends after all tool results + the next user msg.
        turns: list[tuple[int, int]] = []  # (start_idx, end_idx_exclusive)
        i = 0
        while i < len(messages):
            # Look for: user → assistant(with tool_calls)
            if (
                messages[i].get("role") == "user"
                and i + 1 < len(messages)
                and messages[i + 1].get("role") == "assistant"
                and messages[i + 1].get("tool_calls")
            ):
                turn_start = i
                i += 1  # skip user, now at assistant
                # Skip all tool results
                i += 1  # skip assistant
                while i < len(messages) and messages[i].get("role") == "tool":
                    i += 1
                # Optionally skip one user follow-up
                if i < len(messages) and messages[i].get("role") == "user":
                    i += 1
                turns.append((turn_start, i))
            else:
                i += 1

        if len(turns) <= self.MIN_TURNS_TO_KEEP:
            return messages  # not enough turns to safely prune

        # ── 2. Remove oldest turn (but never the most recent N) ─────────
        prune_turn = turns[0]  # oldest
        protected_start = turns[-self.MIN_TURNS_TO_KEEP][0]
        if prune_turn[0] >= protected_start:
            return messages  # oldest turn is within protected range

        turn_start, turn_end = prune_turn

        # Build summary
        tc_names = []
        for tc in messages[turn_start + 1].get("tool_calls", []):
            fn = tc.get("function", {}) if "function" in tc else tc
            tc_names.append(fn.get("name", "?"))
        summary = f"[PRUNED] Earlier tools: {', '.join(tc_names[:4])}"

        # Inject summary into the user message at turn_start
        msg = messages[turn_start]
        msg["content"] = summary + " | " + msg.get("content", "")[:300]

        # Remove the assistant + tool results + follow-up (keep the user msg)
        del messages[turn_start + 1 : turn_end]

        # ── 3. Safety check: no orphaned tool messages ──────────────────
        for _j, _m in enumerate(messages):
            if _m.get("role") != "tool":
                continue
            # Scan backwards for a matching assistant
            _found = False
            for _k in range(_j - 1, -1, -1):
                _prev = messages[_k]
                if _prev.get("role") == "assistant" and _prev.get("tool_calls"):
                    for _tc in _prev["tool_calls"]:
                        if _tc.get("id") == _m.get("tool_call_id"):
                            _found = True
                            break
                    break
                elif _prev.get("role") == "assistant":
                    break  # assistant without tool_calls — stop looking
            if not _found:
                # Safety net failed — this shouldn't happen with turn-based
                # pruning, but if it does, don't prune this session.
                return messages  # bail out, keep original list

        # ── 4. Recurse if still over limit ──────────────────────────────
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
