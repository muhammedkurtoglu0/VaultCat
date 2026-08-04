# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Getting Started (for humans too!)

**Quick setup:**
```bash
git clone https://github.com/muhammedkurtoglu0/vaultcat.git
cd vaultcat
uv sync                                          # deterministic build via uv.lock
```

**Run a scan (no token — unauthenticated recon only):**
```bash
uv run python main.py --target https://localhost:8200
```

**Run authenticated scan + capability audit:**
```bash
uv run python main.py --target https://localhost:8200 --token YOUR_TOKEN --capability-audit
```

**Start the lab (Docker):**
```bash
cd vaultcat-lab
docker compose up -d              # Vault 1.15.3 + PostgreSQL 16 + Pentest Tool
./scripts/setup-lab.sh            # Init, unseal, seed secrets, create tokens
source lab-tokens.env             # Load ROOT_TOKEN, LOW_PRIV_TOKEN, etc.
cd ..
uv run python main.py --target https://localhost:8200 --skip-tls-verify --token $ROOT_TOKEN
```

**Interactive AI agent:**
```bash
uv run python main.py chat --target https://localhost:8200 --token $ROOT_TOKEN --skip-tls-verify
```

**Run tests:**
```bash
uv run pytest                                          # all unit tests (fast)
uv run pytest -m "not integration"                     # skip lab-dependent tests
uv run pytest -m "integration" -v                      # only integration tests (lab required)
```

## Commands (Windows PowerShell)

**Install:**
```powershell
uv sync
```

**Run all tests:**
```powershell
uv run pytest
```

**Run a single test file:**
```powershell
uv run pytest tests/test_scanners.py
```

**Run a single test by name:**
```powershell
uv run pytest tests/test_scanners.py -k test_hijack_analyzer_correlates_approle_pair_and_token_chain
```

On this Windows host, do not execute `.venv\Scripts\pytest.exe` directly. Windows Code Integrity blocks the generated
console-script executable; always invoke pytest through `uv run pytest`.

**Run all tests (legacy venv):**
```powershell
.\.venv\Scripts\python.exe -m pytest
```

**Run a single test file:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_scanners.py
```

**Run a single test by name:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_scanners.py -k test_hijack_analyzer_correlates_approle_pair_and_token_chain
```

On this Windows host, do not execute `.venv\Scripts\pytest.exe` directly. Windows Code Integrity blocks the generated
console-script executable; always invoke pytest through the signed Python interpreter with
`.\.venv\Scripts\python.exe -m pytest ...`.

Do not create a Task/subagent just to run tests in this repository. Run the pytest command directly in the current
session with the Bash tool so the result is visible to the operator.

**Run the CLI:**
```bash
python main.py --target http://localhost:8200
python main.py hijack --path ./test-artifacts
python main.py chat   # starts local Ollama agent
python main.py mcp    # starts MCP server on 127.0.0.1:8000
```

## Architecture

`main.py` is a backward-compatible shim that delegates to the Typer CLI in `vault_cli.py` (5 commands: `scan`, `hijack`, `chat`, `cleanup`, `mcp`). It orchestrates all modules and calls `print_report()` / `export_*_report()` at the end of every run.

### `core/`
- `client.py` — `VaultClient`: thin `requests` wrapper that adds the `X-Vault-Token` header. Used only for authenticated legacy checks; most scanners make their own requests.
- `report.py` — global `findings` list (module-level state). All findings flow through `add_finding(severity, title, description, ...)`. The `recommendation` field is accepted but **intentionally not stored or printed** (stripped at ingestion). Severity filter is set once via `set_report_min_severity()`.
- `risk_score.py` — converts the findings list to a 0–100 score + letter grade.

### `reconnaissance/`
Unauthenticated scanners for external recon. Each file exports one public `scan_*` function. They share a `ReconContext` instance that caches HTTP responses by `(method, path)` to avoid redundant requests to the same endpoint.

`http_utils.safe_request()` is the shared HTTP helper used across all recon scanners.

### `scanners/`
Authenticated and local assessment helpers (token analysis, capability audit, KV enumeration, TTL governance, policy analysis, auth config audit, privilege escalation, environment scan). These use `hvac` for Vault API calls or direct `requests`.

### `credential_hijacking/`
The file/git scanning pipeline:
1. `patterns.py` — compiled `PATTERNS` dict (pattern name → regex) and `FINDING_METADATA` dict (pattern name → severity/title/description). This is the single source of truth for what the scanner detects.
2. `file_secret_scanner.py` — walks a directory tree and optionally git history; calls `_scan_text()` per file; calls `add_finding()` immediately for individual pattern hits. `_is_material_value()` distinguishes real credential values from placeholders (`${VAR}`, `{{ template }}`). `mask_value()` intentionally returns raw values (surfaced for authorized assessment).
3. `hijack_analyzer.py` — `analyze_hijack_findings(matches)` takes the raw match list and performs per-file correlation (e.g. role_id + secret_id in same file → HIGH) and cross-file chain detection (e.g. vault_addr + approle pair across the whole scope → HIGH).
4. `validators.py` — opt-in token and AppRole validation against a live Vault, only when `--validate-token` / `--validate-approle` is passed.
5. `db_validator.py` — opt-in database secrets engine metadata check via `--validate-db`.
6. `impact_analyzer.py` — blast-radius analysis for validated credentials.

### `active_execution/`
Plugin-style system for state-changing assessment modules:
- `registry.py` — `BaseExecutionModule` (abstract: `can_run()` / `execute()`), `ActiveExecutionRegistry`, `RiskLevel` enum (`read_only` → `state_changing` → `destructive`), `risk_level_allowed()`.
- `engine.py` — `ActiveExecutionEngine.execute_plan(steps, context)` iterates a step list, checks `can_run`, calls `execute`, and prints results.
- `context.py` — `ExecutionContext` carries `vault_addr`, `token`, `namespace`, and accumulates `findings`.
- `modules/` — concrete module implementations (`PrivilegeEscalationModule`, `SecretExfiltrationModule`).

### `ai_core/`
- `mcp_server.py` — FastMCP server (`127.0.0.1:8000`, supports `streamable-http`/`stdio`/`sse` transports) exposing 52 MCP tools: recon scanners, audit scanners, active execution modules (`run_privilege_escalation`, `run_secret_exfiltration`, …), session management (`get_session_status`, `reset_session`, `create_attack_plan`, `execute_attack_plan`), agentic orchestration (`run_orchestrated_attack`, `run_auto_pentest` — both driven by `_make_mcp_tool_executor`, which hard-blocks state-changing tools when `max_risk=read_only`), remediation (`get_remediation_advice`, backed by `core/remediation_engine.py`), and meta tools (`get_findings`, `get_risk_score`, `list_active_modules`, `run_active_module`). Maintains a `PentestSession` per session ID via `ai_core.session.SessionManager`.
- `agent.py` — `PentestAgent`: ReAct-loop conversational agent with hallucination guards (fake token/IP detection, duplicate-call prevention). Also supports `run_with_plan()` for autonomous multi-step plan execution with pause/resume/abort controls, phase tracking (`PhaseTracker`), and conditional step failure handling.
- `llm_engine.py` — `LLMClient`: multi-provider (Ollama/OpenAI/Anthropic/DeepSeek) with unified `chat()` interface, native tool calling, ReAct fallback for Ollama, retry with exponential backoff (`RetryableError`/`FatalError`), circuit breaker (`CircuitBreaker`), and `health()` status.
- `session.py` — `PentestSession` dataclass (targets, token history, active plan, phase tracking) + thread-safe `SessionManager` with TTL cleanup and export/import.
- `planning/` — Provider-agnostic plan generation: `BasePlanner` → `OpenAIPlanner` (JSON mode), `DeepSeekPlanner` (thin subclass), `AnthropicPlanner` (extended thinking). `PlannerFactory` picks by provider name. Produces typed `PentestPlan` with `PlannedStep` (conditional execution: `on_failure`, `max_retries`, `alternative_tool`).
- `chat_ui.py` — interactive terminal chat (`ChatUI`) connecting `PentestAgent` to MCP tool execution.
- `tools.py` — 18 `ToolDef` dataclasses (OpenAI/Anthropic function-calling format) in `ALL_TOOLS`.
- `memory.py` — conversation history, findings, captured credentials, plan storage (`active_plan`, `plan_history`).

## Key Conventions

**All findings go through `core.report.add_finding()`** — never print findings directly from scanners. The `recommendation` argument is accepted for call-site documentation purposes but is not stored or exported.

**The `material` flag on matches** — `_is_material_value()` marks a match as `material: False` when the captured value looks like a placeholder or template variable. The `hijack_analyzer` uses this flag to suppress correlation findings for non-concrete values.

**Findings deduplication** — `add_finding()` silently drops exact duplicates keyed on `(severity, title, module, target, evidence)`.

**Test isolation** — the `clear_findings` autouse fixture in `tests/test_scanners.py` resets `report.findings` before and after every test. When writing new scanner tests, monkeypatch the `safe_request` function or the relevant `requests` call rather than hitting the network.

**Pattern additions** — add new regex to `credential_hijacking/patterns.py` (`PATTERNS` + `FINDING_METADATA`). The scanner picks them up automatically. Add correlation logic to `hijack_analyzer.py` if the new pattern participates in multi-pattern chains.
