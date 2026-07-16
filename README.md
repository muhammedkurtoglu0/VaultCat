# Vault Hijacking Risk Assessment Tool

Python-based reconnaissance and credential exposure assessment tool for authorized HashiCorp Vault security testing.

The default workflow assumes an external tester starts with only a target URL:

- No Vault token
- No credentials
- No shell access
- No SSH access
- No Docker access
- No Kubernetes access

The tool focuses on safe attack surface mapping, fingerprinting, unauthenticated misconfiguration checks, and optional authenticated assessment when a token is explicitly provided.

The current development direction prioritizes Vault credential hijacking risk assessment:

- Find Vault tokens, AppRole Role IDs, AppRole Secret IDs, Vault addresses, and Vault auth flow references in reachable artifacts.
- Correlate AppRole Role ID + Secret ID exposure.
- Correlate AWS IAM Vault auth references with AWS credential or role material.
- Detect AppRole and AWS IAM integration clues in source code, README files, Terraform, CI/CD workflows, logs, archives, and git history.
- Detect Vault Database Secrets Engine clues, including dynamic database credential paths, role definitions, TTLs, creation statements, and leaked static DB plugin credentials.
- Treat placeholders, environment-variable references, and generated code variables as context instead of concrete exposed credentials.
- Validate discovered material only when explicitly requested and authorized.
- Avoid secret read, write, delete, brute force, or destructive actions.

## Ethics and Authorization

Use this tool only on systems you own or have explicit permission to assess. It does not perform brute force, password cracking, destructive exploitation, or data modification by default.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Project Layout

```text
active_execution/      State-changing assessment modules (PrivEsc, exfil, harvest, seal/unseal)
ai_core/               LLM agent, MCP server, chat UI, planning, session management
core/                  Reporting, risk scoring, TLS config, and Vault client helpers
credential_hijacking/  Artifact scanning, correlation, validation, and impact analysis
reconnaissance/        Safe unauthenticated Vault recon scanners
scanners/              Authenticated assessment helpers (policy, capability, KV, TTL, etc.)
test-artifacts/        Synthetic local fixtures for smoke testing
vault-pentest-lab/     Docker-based Vault pentest lab (Vault 1.15.3 + PostgreSQL 16)
  ├── vault-target/     Vault config, TLS cert/key, ACL policies
  ├── lab-artifacts/    Sample files for hijack scanner testing
  ├── scripts/          Automated lab setup (init, unseal, seeds, policies, tokens)
  └── docker-compose.yml
main.py                CLI entrypoint
```

## Unauthenticated External Recon

```bash
python main.py --target http://localhost:8200
```

This runs safe checks for:

- Vault health endpoint exposure
- Vault fingerprint signals
- Vault UI exposure
- HTTP security headers
- A small curated list of known unauthenticated Vault endpoints

Async health, seal, and leader metadata collection:

```bash
python main.py --target http://localhost:8200 --vault-recon
```

`--vault-recon` queries `/v1/sys/health`, `/v1/sys/seal-status`, and `/v1/sys/leader` without a token and returns sealed state, cluster metadata, version, and leader metadata for authorized vulnerability management and version tracking.

When a Vault version is observed, the recon workflow also compares it against a bundled offline CVE table (8 static CVEs covering Vault 1.12–1.19) and, when network is available, also queries the **NVD API 2.0** for live CVE data. Results are cached locally for 24 hours. Use `--nvd-refresh` to force-refresh, or set `NVD_API_KEY` env var to raise the rate limit.

To run targeted authenticated checks without repeating the default unauthenticated recon output, add `--skip-recon`:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --validate-token --skip-recon
python main.py --target http://localhost:8200 --token YOUR_TOKEN --capability-audit --skip-recon
```

## Authenticated Assessment

Authenticated checks only run when a token is supplied.

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN
```

Legacy authenticated address usage is also supported:

```bash
python main.py --addr http://localhost:8200 --token YOUR_TOKEN
```

Optional secret path and policy checks:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --secret-path secret/data/myapp --policy default
```

Over-privileged token blast-radius audit:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --capability-audit
python main.py --target http://localhost:8200 --token YOUR_TOKEN --capability-audit --capability-path "sys/*" --capability-path "auth/*" --capability-path "database/roles/*" --capability-path "database/config/*"
```

`--capability-audit` uses Vault's `sys/capabilities-self` endpoint to report whether the supplied token has `sudo` or write-like capabilities on the audited paths. It also flags least-privilege violations when those capabilities appear on critical paths such as `sys/*`, `auth/*`, identity paths, or database role/config paths. It does not read secrets, generate dynamic credentials, update roles, or modify Vault state.

Privilege escalation simulation:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --priv-esc-audit
python main.py --target http://localhost:8200 --token YOUR_TOKEN --priv-esc-audit --token-policy app-policy
```

`--priv-esc-audit` uses `sys/capabilities-self` to safely simulate whether the active token can update its ACL policy path or create new tokens through `auth/token/create`. It does not modify policies or create tokens.

External auth configuration audit:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --auth-config-audit
```

`--auth-config-audit` reads Kubernetes, AWS, and LDAP auth method configuration metadata when authorized. It checks for broad Kubernetes service account bindings, wildcard AWS IAM principal bindings, and observable LDAP lockout/rate-limit settings. It does not attempt logins or modify auth configuration.

TTL governance audit:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --ttl-audit
python main.py --target http://localhost:8200 --token YOUR_TOKEN --ttl-audit --max-mount-ttl-seconds 2592000 --max-pki-cert-ttl-seconds 7776000
```

`--ttl-audit` reads secrets engine mount metadata from `sys/mounts` and checks `max_lease_ttl` against policy thresholds. For PKI mounts, it lists roles and reviews `ttl` and `max_ttl` values to identify weak certificate lifecycle controls. It does not generate certificates or read secret values.

KV path enumeration for authorized inventory:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --kv-enum --kv-path secret/ --kv-version 2
python main.py --target http://localhost:8200 --token YOUR_TOKEN --kv-enum --kv-path kv/app --kv-max-depth 5 --kv-concurrency 3
python main.py --target http://localhost:8200 --token YOUR_TOKEN --kv-enum --kv-path secret/ --kv-no-read
```

`--kv-enum` recursively lists accessible KV directories and secret paths. By default it reads only leaf metadata or key names to confirm readability and build an access map; it does not print or export secret values. Use `--kv-no-read` for list-only enumeration.

## Local Token Discovery

Local discovery is for post-exploitation or local assessment scenarios, not default external recon:

```bash
python main.py --env-scan
```

## Current Modules

**Reconnaissance (unauthenticated):**
- `reconnaissance/health_scanner.py` — Vault health endpoint
- `reconnaissance/fingerprint_scanner.py` — Vault fingerprint detection
- `reconnaissance/ui_scanner.py` — UI exposure checks
- `reconnaissance/header_scanner.py` — Security header analysis
- `reconnaissance/endpoint_scanner.py` — Curated endpoint probing
- `reconnaissance/vault_recon.py` — Async health/seal/leader metadata
- `reconnaissance/version_cve_matcher.py` — Version → CVE matching
- `reconnaissance/auth_surface_scanner.py` — Auth method surface mapping
- `reconnaissance/cors_scanner.py` — CORS misconfiguration detection
- `reconnaissance/tls_scanner.py` — TLS/HTTPS configuration

**Scanners (authenticated):**
- `scanners/capability_scanner.py` — Token capability audit (sys/capabilities-self)
- `scanners/privilege_escalation_scanner.py` — Privilege escalation risk simulation
- `scanners/policy_auditor.py` — ACL policy enumeration + HCL analysis (with fallback)
- `scanners/policy_scanner.py` — HCL policy rule analyzer
- `scanners/auth_config_scanner.py` — Kubernetes/AWS/LDAP auth config audit
- `scanners/ttl_scanner.py` — Mount and PKI TTL governance
- `scanners/kv_enumerator.py` — Async KV path enumeration
- `scanners/token_scanner.py` — Token validity and metadata
- `scanners/secret_scanner.py` — Secret path checks
- `scanners/env_scanner.py` — Local environment Vault variable scan

**Credential Hijacking:**
- `credential_hijacking/file_secret_scanner.py` — File/git credential discovery
- `credential_hijacking/hijack_analyzer.py` — Cross-file correlation + chain detection
- `credential_hijacking/validators.py` — Opt-in token/AppRole validation
- `credential_hijacking/db_validator.py` — Database secrets engine validation
- `credential_hijacking/impact_analyzer.py` — Blast-radius analysis

**Active Execution (state-changing):**
- `active_execution/modules/privilege_escalation.py` — Token abuse + autonomous takeover
- `active_execution/modules/secret_exfiltration.py` — KV/transit/PKI secret dump
- `active_execution/modules/database_credential_harvest.py` — Dynamic DB credential harvest
- `active_execution/modules/cloud_key_exfiltration.py` — Cloud provider key dump
- `active_execution/modules/vault_seal_manipulation.py` — Seal/Unseal (DoS + recovery)
- `active_execution/modules/audit_backdoor.py` — Audit device disable
- `active_execution/modules/token_exploit.py` — Token creation/renewal/lookup
- `active_execution/modules/policy_exploit.py` — Policy manipulation
- `active_execution/modules/persistence.py` — Auth backdoor persistence

**AI Core:**
- `ai_core/agent.py` — ReAct-loop autonomous pentest agent
- `ai_core/chat_ui.py` — Interactive terminal chat
- `ai_core/mcp_server.py` — FastMCP server (25 tools, streamable HTTP)
- `ai_core/llm_engine.py` — Multi-provider LLM client (Ollama/OpenAI/Anthropic/DeepSeek)
- `ai_core/planning/` — Provider-agnostic attack plan generation
- `ai_core/session.py` — Thread-safe session management with TTL

## Vault Hijacking Risk Assessment

```bash
python main.py --hijack-path ./test-artifacts
python main.py hijack --path ./test-artifacts
```

Export reports:

```bash
python main.py --hijack-path ./test-artifacts --json hijack-report.json --markdown hijack-report.md
```

Opt-in validation, only in authorized environments:

```bash
python main.py --hijack-path ./test-artifacts --validate-token --target http://localhost:8207
python main.py --hijack-path ./test-artifacts --validate-approle --target http://localhost:8207
```

Direct AppRole validation and blast-radius analysis:

```bash
python main.py --target http://localhost:8200 --validate-approle --role-id ROLE_ID --secret-id SECRET_ID
python main.py --target http://localhost:8200 --validate-approle --role-id ROLE_ID --secret-id SECRET_ID --capability-path "database/roles/*" --capability-path "database/config/*" --capability-path "sys/*"
```

This performs an AppRole login with the supplied pair, analyzes the returned client token TTL, policy hints, renewability, and then uses `sys/capabilities-self` to identify audited paths where the token has `sudo` or write-like capabilities. It does not read secrets, generate database credentials, update database roles, or modify Vault state.

Production triage examples:

```bash
python main.py hijack --path C:\path\to\repo --no-git-history --min-severity HIGH --json repo-high.json
python main.py hijack --path C:\path\to\repo --exclude-dir vendor --exclude-dir build --max-file-size-mb 2 --json repo-triage.json
```

Authorized Vault Database Secrets Engine metadata validation:

```bash
python main.py --hijack-path C:\path\to\repo --validate-db --target https://vault.example.com --token YOUR_AUTHORIZED_TOKEN
```

`--validate-db` checks only Vault metadata and hardening signals such as visible database mounts, listable roles, role TTLs, visible creation statements, and broad privilege patterns. It does not read `database/creds/<role>`, does not generate dynamic database users, and does not modify Vault or the database.

## Active Execution

Active execution modules are intended for controlled, authorized lab or red-team use after passive and read-only checks have established a clear path. They are not part of the default recon workflow.

### Risk Levels

| Level | Description | Examples |
|-------|-------------|----------|
| `read_only` | No state changes | seal_status |
| `state_changing` | Creates resources, modifies config | token creation, secret exfil, DB harvest, seal/unseal |
| `destructive` | Destroys or disables | audit disable, policy deletion |

### Usage

Read-only active modules can be selected with:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --active-auto
```

State-changing modules require both an explicit risk level and confirmation:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --active-auto --active-max-risk state_changing --confirm-active
```

Run a single module:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --module vault_seal.seal_vault --confirm-active
python main.py --target http://localhost:8200 --module vault_seal.unseal_vault --confirm-active
```

### Available Modules

| Module ID | Risk | Description |
|-----------|------|-------------|
| `privilege_escalation.token_abuse` | state_changing | Auto-detect wildcard sudo paths, create backdoor policies, generate root-equivalent tokens |
| `secret_exfiltration.kv_dump` | state_changing | Enumerate + dump all KV secrets, Transit keys, PKI certs |
| `database_credential_harvest.dynamic_creds` | state_changing | Generate dynamic DB users from all accessible roles |
| `cloud_key_exfiltration.key_dump` | state_changing | Locate + exfiltrate cloud provider keys |
| `vault_seal.seal_status` | read_only | Check whether Vault is sealed |
| `vault_seal.seal_vault` | state_changing | Seal Vault (DoS — all tokens invalid, all engines stop) |
| `vault_seal.unseal_vault` | state_changing | Unseal Vault with Shamir key (recovery) |
| `audit_backdoor.disable` | destructive | Disable all audit devices to hide activity |
| `token_exploit.creation` | state_changing | Create, renew, lookup, orphan tokens |
| `policy_exploit.modification` | state_changing | List, read, clone, escalate policies |
| `persistence.backdoor` | state_changing | Deploy persistent auth backdoor |

## Vault Pentest Lab

A Docker-based lab for safe, local testing of all tool features:

```bash
cd vault-pentest-lab
docker compose up -d
./scripts/setup-lab.sh
source lab-tokens.env

# Run pentest against the lab
python ../main.py scan --target $VAULT_ADDR --skip-tls-verify
python ../main.py hijack ./lab-artifacts --target $VAULT_ADDR --skip-tls-verify
python ../main.py chat --target $VAULT_ADDR --skip-tls-verify --provider deepseek
```

**Lab components:**
- Vault 1.15.3 (intentionally old — CVE coverage)
- PostgreSQL 16 (database secrets engine backend)
- 6 custom ACL policies (admin, read-only, wildcard-sudo-user, app-admin, db-reader, weak-policy)
- 5 test tokens + AppRole credentials
- AppRole, Userpass auth methods
- KV v2, Database, Transit, PKI secrets engines
- Lab artifacts for hijack scanner testing (logs, configs, terraform, CI files)
- Self-signed TLS, CORS wildcard, missing security headers

For a detailed walkthrough of all test scenarios, see [vault-pentest-lab/README.md](vault-pentest-lab/README.md).

## AI-Powered Pentesting

The `ai_core/` module provides an LLM-driven agent that plans and executes pentest operations autonomously. It supports multiple providers and exposes an MCP server for tool integration.

### Chat Agent

```bash
python main.py chat
python main.py chat --target https://localhost:8200 --skip-tls-verify --provider deepseek
python main.py chat --provider deepseek --model deepseek-chat
python main.py chat --provider openai --model gpt-4o-mini
python main.py chat --provider anthropic --model claude-sonnet-5
```

The agent understands natural language (Turkish or English), decides which tool to use based on what it discovers, adapts when tools succeed or fail, and reports findings in table format. It follows a 4-phase methodology: Recon → Audit → Exploit → Report.

In-chat commands:
```
set target https://localhost:8200
set token hvs.abc123...
saldır                    # Run autonomous pentest
bloklamayı kaldır         # Re-run blocked module with max_risk=destructive
```

Supported providers:

| Provider | Env Var | Default Model |
|----------|---------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Ollama (local) | `OLLAMA_HOST` | (auto-detect) |

Provider auto-detection order: Anthropic → DeepSeek → OpenAI → Ollama. If no API key is set, Ollama is the default fallback.

### MCP Server

```bash
python main.py mcp
```

Starts a FastMCP server on `127.0.0.1:8000` exposing 25 MCP tools: recon scanners, audit scanners, active execution modules (privilege escalation, secret exfiltration, DB harvest, cloud key dump, seal/unseal), raw Vault API access, single policy read, session management, and findings/risk-score reporting. Compatible with any MCP client (Claude Desktop, VS Code, etc.).

### LLM Engine

The `LLMClient` provides a unified `chat()` interface across all providers with:
- Native tool/function calling (OpenAI/Anthropic/DeepSeek), ReAct fallback (Ollama)
- Retry with exponential backoff on transient errors (429, 5xx)
- Circuit breaker — fast-fails after 3 consecutive failures, auto-recovers after 30s
- Error classification: `RetryableError` (transient), `FatalError` (auth/client), `LLMTimeoutError`

### AI Planning

`ai_core/planning/` provides provider-agnostic attack plan generation. The planner analyzes token capabilities, enumeration data, and findings, then produces a typed `PentestPlan` with prioritized steps, conditional execution (`on_failure`, `max_retries`, `alternative_tool`), and dynamic policy inference from observed data.

```python
from ai_core.planning import create_planner

planner = create_planner("deepseek")
plan = planner.create_plan(
    vault_addr="http://localhost:8200",
    token_hint="hvs.abc123...",
    enum_data={"capabilities": ..., "findings": ...},
)
# plan.steps  → list of PlannedStep (tool, reason, phase, risk, params)
# plan.token_assessment → TokenAssessment (power_level, escalation_possible)
```

### Session Management

`ai_core/session.py` provides `PentestSession` (targets, token history, active plan, phase tracking) and thread-safe `SessionManager` with TTL-based cleanup and export/import. The MCP server uses it to isolate state between concurrent sessions.

The hijack scanner currently looks for:

- Vault tokens and response-wrapped tokens: `hvs.*`, `hvc.*`, wrapped-token examples, `VAULT_TOKEN`, `vault_token`
- AppRole material: `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `role_id`, `secret_id`, `roleId`, `secretId`
- AppRole flow clues: `auth/approle/login`, role-id retrieval paths, Secret ID generation paths, CLI AppRole login examples
- Vault addresses and namespaces: `VAULT_ADDR`, `vault_addr`, `:8200`, `VAULT_NAMESPACE`
- AWS IAM Vault auth clues: `auth/aws/login`, `auth/aws/role/*`, AWS credential environment variables, role ARNs, bound IAM principal ARNs, `X-Vault-AWS-IAM-Server-ID`
- Vault Database Secrets Engine clues: `database/config/*`, `database/roles/*`, `database/creds/*`, database plugins, connection URLs, `creation_statements`, `revocation_statements`, `default_ttl`, `max_ttl`
- Static DB credential clues: `DB_USERNAME`, `DB_PASSWORD`, `DATABASE_PASS`, `db_password`, `pg_password`, `mysql_password`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, `PGUSER`, `PGPASSWORD`
- Vault Agent clues: `auto_auth` and file token sinks

Noise and scope controls:

- `--min-severity HIGH` shows and exports only HIGH/CRITICAL findings.
- `--no-git-history` skips git history scanning for faster first-pass triage.
- `--exclude-dir NAME` excludes additional directory names; it can be repeated.
- `--max-file-size-mb N` changes the maximum scanned file size.
- Default excluded directories include `.git`, `.terraform`, `node_modules`, virtualenvs, and common cache directories.

Public lab smoke tests used during development:

```bash
git clone --depth 1 https://github.com/hashicorp/vault-examples.git public-labs/vault-examples
git clone --depth 1 https://github.com/hashicorp/vault-action.git public-labs/vault-action
git clone --depth 1 https://github.com/ned1313/vault-tfc-approle.git public-labs/vault-tfc-approle

python main.py hijack --path public-labs/vault-examples --json public-vault-examples-report.json --markdown public-vault-examples-report.md
python main.py hijack --path public-labs/vault-action --json public-vault-action-report.json --markdown public-vault-action-report.md
python main.py hijack --path public-labs/vault-tfc-approle --json public-vault-tfc-approle-report.json --markdown public-vault-tfc-approle-report.md
```
