# Architecture

## High-Level Flow

```
                         ┌─────────────────────────────┐
                         │        ChatUI / Agent        │
                         │  (natural language, ReAct)   │
                         └─────────────┬───────────────┘
                                       │
               ┌───────────────────────┼───────────────────────┐
               ▼                       ▼                       ▼
     ┌─────────────────┐   ┌───────────────────┐   ┌──────────────────┐
     │   auto_mode.py  │   │  tree_walker.py   │   │ mutation_engine  │
     │ (orchestrator)  │   │ (branch executor) │   │   (LLM planner)  │
     └────────┬────────┘   └────────┬──────────┘   └────────┬─────────┘
              │                     │                        │
              └─────────────────────┼────────────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
                  ┌──────────┐        ┌───────────────┐
                  │ web_search│        │ poc_parser +  │
                  │ (DDG 24h │        │ poc_sequencer │
                  │  cache)  │        │ (curl→action) │
                  └────┬─────┘        └───────┬───────┘
                       │                      │
                       └──────────┬───────────┘
                                  ▼
                         ┌─────────────────┐
                         │ dynamic_session │  ← global singleton
                         │  (token store,  │     all modules read/write
                         │   auto-escalate)│
                         └────────┬────────┘
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                  ┌──────────┐     ┌──────────────┐
                  │ pivot    │     │ stealth_http │
                  │ engine   │     │ (opt-in,     │
                  │ (DB→OS)  │     │  --stealth)  │
                  └──────────┘     └──────────────┘
```

## Auto Mode Flow

1. **Recon** — direct tool calls (no LLM overhead)
2. **Build Attack Tree** — `MutationEngine` seeds branches from findings + tokens
3. **Walk Tree** — `TreeWalker` executes branches in risk order (Aggressive → Balanced → Stealth)
4. **On Failure** → `MutationEngine` asks LLM for new branches (dynamic)
5. **On Escalation** → regenerate tree with elevated privileges, walk deeper (recursive)
6. **Agent Summary** → LLM reviews all findings, provides structured report
7. **PDF Export** → `export_pdf_report()`

## Component Roles

| Component | Role |
|-----------|------|
| `auto_mode.py` | Orchestrator — drives the full autonomous flow |
| `tree_walker.py` | Executor — walks branches in risk order, tracks failures (max 2/branch) |
| `mutation_engine.py` | Planner — asks LLM for dynamic attack paths (2-6 branches) |

## Package Layout

```text
main.py                 CLI entry point (Typer, 5 commands)
vault_cli.py            Typer app definition
core/                   Reporting, risk scoring, TLS config, Vault client
reconnaissance/         Unauthenticated recon scanners (14 modules)
scanners/               Authenticated assessment helpers (10 modules)
credential_hijacking/   File/git scanning, correlation, validation (7 modules)
active_execution/       State-changing assessment modules (30 modules)
  modules/
    cloud/              AWS/Azure/GCP exploitation
    database/           Database credential harvest + exploitation
    general/            CVE scanner, agent sidecar, unauthenticated attacks
    persistence/        Backdoors + audit manipulation
    pivot/              Cross-service lateral movement
    seal/               Seal/unseal manipulation + key exfiltration
    secrets/            KV dump, PKI, Transit, Raft storage
    token/              Privilege escalation, token/policy exploits, K8s/JWT/AppRole
ai_core/                LLM agent, MCP server, chat UI, planning, session (20+ files)
vaultcat-lab/      Docker-based pentest lab (Vault 1.15.3 + PostgreSQL 16)
tests/                  23 test files, 600+ tests
```

## Key Design Decisions

- **All findings go through `core.report.add_finding()`** — never printed directly from scanners
- **Global `ReconContext`** caches HTTP responses by `(method, path)` to avoid redundant requests
- **`DynamicCredentialStore`** global singleton — all discovered tokens auto-escalate
- **Risk gating** at multiple layers: CLI flags, engine defaults, MCP tool defaults
- **`mask_value()` intentionally returns raw values** — surfaced for authorized assessment
