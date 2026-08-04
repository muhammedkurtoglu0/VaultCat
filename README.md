# Vault Pentest Tool

[![Test](https://github.com/muhammedkurtoglu0/vault-pentest-tool/actions/workflows/test.yml/badge.svg)](https://github.com/muhammedkurtoglu0/vault-pentest-tool/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python-based offensive security tool for authorized HashiCorp Vault penetration testing. Covers the full attack lifecycle — recon, hijack, escalate, exfiltrate, pivot, and persist — across three operational modes:

### 1. External Reconnaissance (Zero-Knowledge)
Start with **only a target URL** — no credentials, no access:
- Unauthenticated Vault fingerprinting, health/version/seal status discovery
- TLS certificate analysis, HTTP security header audit, CORS misconfiguration detection
- Auth method surface mapping (9 auth types via unauthenticated endpoint)
- NVD CVE matching against discovered version (11 bundled + 36+ live)
- Deployment fingerprinting (reverse proxy, dev-mode indicators)

### 2. Authenticated Assessment (Token-Based)
Once a Vault token is obtained (discovered, provided, or escalated):
- Token capability audit (`sys/capabilities-self`) with auto-probe
- ACL policy enumeration and HCL analysis with wildcard/sudo detection
- KV secret path enumeration with blind brute-force fallback
- Auth method security audit (Kubernetes, AWS, LDAP, JWT, OIDC)
- TTL governance audit (mounts + PKI roles)
- Privilege escalation simulation (read-only)
- **Active exploitation**: token creation, secret exfiltration, database credential harvesting, cloud key dumping, PKI certificate issuance, Transit encrypt/decrypt, seal/unseal manipulation, and more

### 3. Local / Post-Exploitation (Shell Access)
When you have **filesystem or shell access** to a host:
- File system scanning for Vault tokens, AppRole pairs, AWS keys, DB passwords (56 regex patterns)
- Git history scanning for committed credentials
- Vault Agent / Sidecar config discovery and sink token extraction
- AppRole credential file reading (`role_id_file_path`, `secret_id_file_path`)
- Environment variable scanning (`VAULT_TOKEN`, `VAULT_ADDR`)
- Raft storage analysis (raft.db SQLite parsing, snapshot download, WAL inspection)
- Cross-file credential correlation and chain detection
- Kubernetes service account token discovery (`/var/run/secrets/kubernetes.io/serviceaccount/`)

---

**All state-changing and destructive operations are gated** behind explicit `--confirm-active` and `--active-max-risk` flags. Read-only scanning runs freely. The tool does not perform brute-force or password cracking.

## Ethics and Authorization

Use this tool only on systems you own or have explicit permission to assess. Read-only modules run freely; state-changing and destructive operations require the `--confirm-active` flag (enforced at runtime). It does not perform brute force or password cracking.

## Install

**Quick (recommended — uses uv for deterministic builds):**

```bash
git clone https://github.com/muhammedkurtoglu0/vault-pentest-tool.git
cd vault-pentest-tool
uv sync
```

**Manual (pip):**

```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# or: .\.venv\Scripts\Activate.ps1  (Windows PowerShell)
pip install -e .
```

**Lab + tool together (Docker):**

```bash
cd vault-pentest-lab
docker compose up -d           # Vault 1.15.3 + PostgreSQL 16 + Pentest Tool
docker compose logs -f vault-pentest
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

- Vault health endpoint exposure (version, sealed/initialized status, cluster metadata)
- Vault fingerprint signals (confirms target is HashiCorp Vault)
- Vault UI exposure (`/ui/`, login page reachability)
- HTTP security headers (HSTS, X-Content-Type-Options, CSP, etc.)
- CORS misconfiguration detection (wildcard origin + credentials)
- TLS/HTTPS configuration (certificate expiry, self-signed, HTTP→HTTPS redirect)
- Auth method surface mapping (9 auth method types via unauthenticated endpoint)
- Deployment indicators (reverse proxy headers, dev-mode)
- A curated list of known unauthenticated Vault endpoints (`/v1/sys/health`, `/v1/sys/seal-status`, `/v1/sys/internal/ui/mounts`)

Async health, seal, and leader metadata collection:

```bash
python main.py --target http://localhost:8200 --vault-recon
```

`--vault-recon` queries `/v1/sys/health`, `/v1/sys/seal-status`, and `/v1/sys/leader` without a token and returns sealed state, cluster metadata, version, and leader metadata for authorized vulnerability management and version tracking.

When a Vault version is observed, the recon workflow also compares it against a bundled offline CVE table (11 static CVEs covering Vault 1.12–1.19) and, when network is available, also queries the **NVD API 2.0** for live CVE data (36+ CVEs). Results are cached locally for 24 hours. Use `--nvd-refresh` to force-refresh, or set `NVD_API_KEY` env var to raise the rate limit.

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

`--auth-config-audit` reads Kubernetes, AWS, LDAP, JWT, and OIDC auth method configuration metadata when authorized. It checks for broad Kubernetes service account bindings, wildcard AWS IAM principal bindings, observable LDAP lockout/rate-limit settings, OIDC discovery URLs, JWT bound issuers, bound claims, and audience validation gaps. It does not attempt logins or modify auth configuration.

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
- `reconnaissance/version_cve_matcher.py` — Version → CVE matching (11 bundled + NVD)
- `reconnaissance/version_risk_scanner.py` — Version risk scoring (honeypot detection)
- `reconnaissance/auth_surface_scanner.py` — Auth method surface mapping (9 types)
- `reconnaissance/cors_scanner.py` — CORS misconfiguration detection
- `reconnaissance/tls_scanner.py` — TLS/HTTPS configuration + certificate analysis
- `reconnaissance/deployment_scanner.py` — Reverse proxy + dev-mode detection
- `reconnaissance/nvd_client.py` — NVD API 2.0 client (24h disk cache)
- `reconnaissance/stealth_http.py` — Stealth HTTP with adaptive backoff + jitter

**Scanners (authenticated):**
- `scanners/capability_scanner.py` — Token capability audit (sys/capabilities-self) + auto-probe
- `scanners/privilege_escalation_scanner.py` — Privilege escalation risk simulation
- `scanners/policy_auditor.py` — ACL policy enumeration + HCL analysis (with fallback)
- `scanners/policy_scanner.py` — HCL policy rule analyzer
- `scanners/auth_config_scanner.py` — Kubernetes/AWS/LDAP/JWT/OIDC auth config audit
- `scanners/ttl_scanner.py` — Mount and PKI TTL governance
- `scanners/kv_enumerator.py` — Async KV path enumeration + blind brute-force fallback
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
- `active_execution/modules/secret_exfiltration.py` — KV/transit/PKI/SSH secret dump
- `active_execution/modules/database_credential_harvest.py` — Dynamic DB credential harvest
- `active_execution/modules/cloud_key_exfiltration.py` — Cloud provider key dump
- `active_execution/modules/vault_seal_manipulation.py` — Seal/Unseal (DoS + recovery)
- `active_execution/modules/audit_backdoor.py` — Audit device disable + log injection + audit-hash
- `active_execution/modules/token_exploit.py` — Token creation/renewal/lookup
- `active_execution/modules/policy_exploit.py` — Policy manipulation (clone, escalate)
- `active_execution/modules/persistence.py` — Auth backdoor persistence (AppRole)
- `active_execution/modules/multi_persistence.py` — Multi-method backdoor (AppRole + K8s + LDAP)
- `active_execution/modules/database_pivot.py` — DB pivot: connect + enumerate + extract
- `active_execution/modules/database_exploit.py` — DB exploit: DML/DDL on harvested creds
- `active_execution/modules/cloud_pivot.py` — Cloud pivot: AWS/Azure/GCP enumeration
- `active_execution/modules/cloud_exploit.py` — Cloud exploit: IAM user/EC2/S3 creation
- `active_execution/modules/raft_storage_exploit.py` — Raft: snapshot download, raft.db parsing
- `active_execution/modules/cve_scanner.py` — Active CVE exploitation (12 CVEs)
- `active_execution/modules/unauthenticated_attack.py` — Token-less attack surface scan
- `active_execution/modules/pivot_engine.py` — Full cross-service pivot: Vault→DB→OS shell
- `active_execution/modules/payload_module.py` — Reverse shell via PostgreSQL COPY FROM PROGRAM
- `active_execution/modules/unseal_key_exfiltration.py` — Shamir unseal key discovery
- **Tier 1 (v1.1):**
- `active_execution/modules/transit_engine_exploit.py` — Transit: key audit, encrypt/decrypt PoC, datakey, HMAC, rotate
- `active_execution/modules/agent_sidecar_attack.py` — Agent: HCL discovery, sink token theft, AppRole file reading
- `active_execution/modules/pki_engine_exploit.py` — PKI: CA/CRL download, 9-flag role audit, cert issuance PoC
- `active_execution/modules/kubernetes_auth_exploit.py` — K8s: JWT decode, config audit, role binding, login, CVE-2023-46835
- **Tier 2 (v1.2):**
- `active_execution/modules/jwt_oidc_exploit.py` — JWT/OIDC: discovery doc fetch, JWKS parse, algorithm confusion, bound_claims audit
- `active_execution/modules/approle_exploit.py` — AppRole: config audit, bind_secret_id bypass, CIDR bypass, login

**AI Core:**
- `ai_core/agent.py` — ReAct-loop autonomous pentest agent
- `ai_core/chat_ui.py` — Interactive terminal chat
- `ai_core/gui_app.py` — CustomTkinter desktop GUI
- `ai_core/mcp_server.py` — FastMCP server (43 tools, streamable HTTP)
- `ai_core/llm_engine.py` — Multi-provider LLM client (Ollama/OpenAI/Anthropic/DeepSeek/Kimi/Cursor)
- `ai_core/planning/` — Provider-agnostic attack plan generation
- `ai_core/session.py` — Thread-safe session management with TTL
- `ai_core/orchestrator.py` — Parallel domain-based attack orchestrator
- `ai_core/specialist_agent.py` — Domain-specialist agents (8 domains)
- `ai_core/tree_walker.py` — Attack tree branch executor
- `ai_core/mutation_engine.py` — LLM-driven dynamic attack path generation
- `ai_core/tool_executor.py` — MCP tool execution bridge

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

### Auto-Pilot Safety

When `--auto-pilot` is enabled, the AI agent auto-executes PoC chains from web search results:
- Only **high** and **medium** confidence chains are executed
- Only `read_only` and `state_changing` steps run automatically
- **Destructive** chains are always skipped — reported but never auto-executed

### Available Modules

29 modules registered in `active_execution/registry.py`. Each carries an explicit risk level enforced at runtime:

| Module ID | Risk | Parameters | Description |
|-----------|------|------------|-------------|
| `privilege_escalation.token_abuse` | `state_changing` | `policies`, `ttl`, `backdoor_policy_name` | Auto-detect wildcard sudo, create backdoor policies, generate root tokens |
| `secret_exfiltration.kv_dump` | `read_only` | `max_depth`, `namespace` | Enumerate + dump all KV secrets, Transit keys, PKI certs, SSH roles |
| `database_credential_harvest.dynamic_creds` | `state_changing` | `timeout`, `verify_tls`, `namespace` | Generate dynamic DB users from all accessible roles |
| `cloud_key_exfiltration.key_dump` | `state_changing` | `provider` (aws/azure/gcp), `region` | Locate + exfiltrate cloud provider IAM keys |
| `vault_seal.seal_status` | `read_only` | (none) | Check whether Vault is sealed |
| `vault_seal.seal_vault` | `state_changing` | (none) | Seal Vault (DoS — all tokens invalid, all engines stop) |
| `vault_seal.unseal_vault` | `state_changing` | `unseal_key` | Unseal Vault with Shamir key (recovery) |
| `audit_backdoor.disable` | `destructive` | (none) | Disable audit devices + log injection + audit-hash HMAC test |
| `token_exploit.creation` | `state_changing` | `policies`, `ttl`, `display_name`, `num_uses` | Create, renew, lookup, orphan tokens |
| `policy_exploit.modification` | `state_changing` | `policy_name`, `policy_body` | List, read, clone, escalate policies |
| `persistence.backdoor` | `destructive` | `backdoor_user`, `backdoor_pass`, `backdoor_policy` | Deploy persistent auth backdoor (AppRole) |
| `multi_persistence.backdoor` | `destructive` | `methods` (approle,k8s,ldap) | Deploy multiple concurrent backdoors |
| `pivot_engine.cross_service` | `destructive` | `db_type`, `db_host`, `db_port`, `db_name` | Cross-service pivot: Vault → DB → OS shell |
| `database_pivot.exploit` | `destructive` | `host`, `port`, `username`, `password`, `db_name` | Direct database exploitation via harvested credentials |
| `database_exploit.exploit` | `destructive` | `sql_query`, `db_type` | Database engine exploitation (DML/DDL on harvested creds) |
| `cloud_pivot.exploit` | `destructive` | `provider` (aws/azure/gcp), `region`, `access_key`, `secret_key` | Cloud infrastructure pivot → enumerate resources |
| `cloud_exploit.exploit` | `destructive` | `provider`, `access_key`, `secret_key`, `resource_type` | Cloud provider exploitation (IAM, EC2, S3) |
| `raft_storage.exploit` | `destructive` | `snapshot_path`, `raft_db_path` | Raft: snapshot download + raft.db SQLite parsing + WAL |
| `unseal_key.exfiltration` | `destructive` | `search_paths` (default: /vault, /tmp, /etc) | Exfiltrate Shamir unseal key material |
| `payload_module.reverse_shell` | `destructive` | `lhost`, `lport` (default 4444), `payload_type` (bash/python/nc) | Reverse shell ON target via PostgreSQL COPY FROM PROGRAM |
| `cve_scanner.scan` | `state_changing` | `target_cves` | Active CVE exploitation against 12 known Vault CVEs |
| `unauthenticated.attack` | `read_only` | (none) | Unauthenticated attack surface scanning |
| **Tier 1:** | | | |
| `transit_engine_exploit.operations` | `state_changing` | `key_name`, `plaintext` | Transit: key audit, encrypt/decrypt PoC, datakey, HMAC, rotate |
| `agent_sidecar_attack.scan` | `read_only` | `config_paths` | Agent: HCL discovery, sink token theft, AppRole file reading |
| `pki_engine_exploit.operations` | `state_changing` | `role_name`, `common_name`, `ttl` | PKI: CA/CRL download, 9-flag role audit, cert issuance PoC |
| `kubernetes_auth_exploit.login` | `state_changing` | `jwt_token`, `role_name`, `mount_path` | K8s: JWT decode, auth config audit, SA token login, CVE-2023-46835 |
| **Tier 2:** | | | |
| `jwt_oidc_exploit.audit` | `state_changing` | `mount_path`, `role_name` | JWT/OIDC: discovery doc + JWKS fetch, algorithm confusion, bound_claims audit |
| `approle_exploit.bypass` | `state_changing` | `role_id`, `secret_id`, `mount_path` | AppRole: config audit, bind_secret_id bypass, CIDR bypass (X-Forwarded-For), login |
| `raft_storage.exploit` (rewritten) | `destructive` | `snapshot_path`, `raft_db_path` | Snapshot download + raft.db SQLite parsing + WAL analysis |

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
- Vault 1.15.3 (intentionally old — CVE coverage for 12 CVEs)
- PostgreSQL 16 (database secrets engine backend)
- 6 custom ACL policies (admin, read-only, wildcard-sudo-user, app-admin, db-reader, weak-policy)
- 5 test tokens + AppRole credentials (my-role with secret_id_num_uses=10)
- AppRole + Userpass auth methods
- KV v2, Database, Transit (key: my-key), PKI secrets engines
- Lab artifacts for hijack scanner testing (logs, configs, terraform, CI files)
- Self-signed TLS, CORS wildcard, missing security headers

For a detailed walkthrough of all test scenarios, see [vault-pentest-lab/README.md](vault-pentest-lab/README.md).

## AI-Powered Pentesting

The `ai_core/` module provides an LLM-driven agent that plans and executes pentest operations autonomously.

### Quick Start

```bash
# Interactive chat (terminal)
python main.py chat --target https://vault:8200 --token hvs.xxx

# Desktop GUI (CustomTkinter)
python main.py chat --ui desktop --target https://vault:8200 --token hvs.xxx

# Fully autonomous (non-interactive, cron-compatible)
python main.py chat --auto --target https://vault:8200 --token hvs.xxx --pdf-report report.pdf

# Auto with stealth evasion
python main.py chat --auto --stealth --target https://vault:8200

# Auto-pilot: auto-execute web PoC chains
python main.py chat --auto-pilot --target https://vault:8200
```

### In-Chat Commands

Natural language works — the agent understands intent. These commands are shortcuts:

| Command | Action |
|---------|--------|
| `auto` / `otomatik` | Run fully autonomous pentest → tree walker → PDF report |
| `orchestrate` / `smart` | Run parallel domain-specialist orchestrated attack |
| `pilot` / `auto-pilot` | Toggle auto-execution of web PoC chains |
| `walk` / `yuru` | Walk the attack tree (risk-ordered branches) |
| `mutate` / `branch` | Ask LLM for alternative attack paths |
| `fix` / `cozum` | Get remediation advice for all findings |
| `stealth` / `gizli` | Toggle stealth HTTP (jitter + backoff) |
| `modules` / `ls` | List all available tools and active modules |
| `findings` | Show accumulated pentest findings |
| `status` | Show session: tokens, escalations, power levels |
| `set target/token` | Configure target URL and Vault token |
| `exit` | Quit |

### Architecture — How Everything Fits Together

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
             │    ┌────────────────┘                        │
             │    │  auto_mode calls TreeWalker to walk     │
             │    │  branches. On failure, MutationEngine   │
             │    │  generates new branches via LLM.        │
             │    │  On escalation, tree is regenerated.    │
             │    └─────────────────────────────────────────┘
             │
    ┌────────┴──────────┐
    │                   │
    ▼                   ▼
┌──────────┐    ┌───────────────┐
│ web_search│    │ poc_parser +  │
│ (DDG 24h │    │ poc_sequencer │
│  cache)  │    │ (curl→action) │
└────┬─────┘    └───────┬───────┘
     │                  │
     └──────┬───────────┘
            ▼
   ┌─────────────────┐
   │ dynamic_session │  ← global singleton
   │  (token store,  │     all modules read/write
   │   auto-escalate)│
   └────────┬────────┘
            │
   ┌────────┴────────┐
   ▼                 ▼
┌──────────┐  ┌──────────────┐
│ pivot    │  │ stealth_http │
│ engine   │  │ (opt-in,     │
│ (DB→OS)  │  │  --stealth)  │
└──────────┘  └──────────────┘
```

**Flow when `auto` is triggered:**

1. **Recon** — direct tool calls (no LLM overhead)
2. **Build Attack Tree** — `MutationEngine` seeds branches from findings + tokens
3. **Walk Tree** — `TreeWalker` executes branches in risk order (Aggressive → Balanced → Stealth)
4. **On Failure** → `MutationEngine` asks LLM for new branches (dynamic, no hardcoded limit)
5. **On Escalation** → regenerate tree with elevated privileges, walk deeper (recursive)
6. **Agent Summary** → LLM reviews all findings, provides structured report
7. **PDF Export** → `export_pdf_report()`

### Auto Mode vs Tree Walker vs Mutation Engine

| Component | Role | Calls |
|-----------|------|-------|
| `auto_mode.py` | **Orchestrator** — drives the full autonomous flow | TreeWalker, MutationEngine, PentestAgent |
| `tree_walker.py` | **Executor** — walks branches in risk order, tracks failures (max 2/branch), recursive escalation | tool_executor (MCP tools) |
| `mutation_engine.py` | **Planner** — asks LLM for dynamic attack paths (2-6 branches), context-aware fallbacks when offline | LLM (optional), web intel |

`auto_mode` is the entry point. It owns the flow. `TreeWalker` does the walking. `MutationEngine` provides new ideas when things fail.

### Supported Providers

| Provider | Env Var | Default Model |
|----------|---------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-v4-pro` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Kimi | `KIMI_API_KEY` | (auto-detect) |
| Cursor | `CURSOR_API_KEY` | (auto-detect) |
| Ollama (local) | `OLLAMA_HOST` | (auto-detect) |

### MCP Server

```bash
python main.py mcp
```

Starts a FastMCP server on `127.0.0.1:8000` exposing 43 MCP tools: recon, audit, active execution, raw Vault API, web search, session management, findings/risk-score, remediation advice, attack planning, auto-pentest, transit/PKI/K8s/JWT/OIDC/AppRole/Agent exploitation, and more.

### LLM Engine

`LLMClient` unified `chat()` across all providers with native tool calling, retry + exponential backoff, circuit breaker.

### Web Search & PoC-to-Action

The agent uses `web_search` as a regular tool — the LLM decides when to search based on context, not regex patterns. Results are parsed for executable PoC code (curl, requests, vault CLI) and converted into `run_raw_vault_request` calls.

**Default: DuckDuckGo** — free, no API key, works out of the box.  
**Optional: Tavily** — 1000 queries/month free. Set `TAVILY_API_KEY` in `.env` (copy from `.env.example`). If Tavily fails or key is missing, DuckDuckGo is used as fallback.

**Domain reliability scoring** — results are scored/sorted by domain trust. Official sources (`developer.hashicorp.com`, `nvd.nist.gov`, `github.com/hashicorp`, `cve.mitre.org`, `github.com/advisories`) get priority; random blogs rank lower but are never filtered out. Pass `prefer_domains` to customize.

**Full-page fetch** (`fetch_top_n`) — optionally fetch and extract the full text (up to 5000 chars) of the top N results. Uses trafilatura (preferred) with BeautifulSoup fallback for HTML cleaning. Enables PoC parser to find exploit code buried deep in pages beyond the snippet.

**Context enrichment** — before executing a `web_search` call, the agent injects context notes: repeat-query detection (session-level dedup) and version-mismatch warnings (when the query references a Vault version different from what was previously discovered). The LLM's query is **never modified or blocked** — only supplementary information is added.

| Component | File | Role |
|-----------|------|------|
| Search engine | `ai_core/web_search.py` | DuckDuckGo (default) + Tavily (opt-in), 24h MD5 cache, domain scoring, full-page fetch |
| PoC parser | `ai_core/poc_parser.py` | Extracts curl/requests/vault CLI from text + full_text → `PoCAction` |
| PoC sequencer | `ai_core/poc_sequencer.py` | Chains actions: producer→consumer, dependency detection |

**Flow:** LLM calls web_search → domain scoring + optional full-page fetch → parse PoCs → sequence into chains → offer to execute (or auto-execute in `--auto-pilot` mode).

```bash
# Disable web search (privacy / air-gapped)
python main.py chat --disable-web --target https://vault:8200
```

### Stealth HTTP (`--stealth`)

**OFF by default** — requests are fast and direct. Enable with `--stealth` for real targets:

| Feature | Effect |
|---------|--------|
| 429 backoff | Exponential: 10s→20s→40s→80s, concurrency halved |
| 403 backoff | Moderate: 5s→10s→20s (WAF evasion) |
| Random jitter | 1-5s between requests (human cadence) |
| Concurrency limit | Starts at 3, drops to 1 on 429 |
| Adaptive polling | Fast Vault→2s poll, slow Vault→30s poll |

```bash
python main.py chat --stealth --target https://prod-vault:8200
# In chat: >> stealth    (toggle ON/OFF)
```

### Dynamic Session & Auto-Escalation

`ai_core/dynamic_session.py` — global singleton tracking all discovered tokens and credentials. Every module (scanners, active execution, agent) reads/writes to it. When a higher-privilege token is discovered, all subsequent tool calls automatically use it.

```python
from ai_core.dynamic_session import global_store
global_store.add_token("hvs.xxx", source="priv_esc", power_level="root")
best = global_store.get_best_token()  # always the highest-power token
```

### Pivot Engine (`--pivot`)

`active_execution/modules/pivot_engine.py` — cross-service lateral movement. Takes DB credentials harvested from Vault, connects directly to PostgreSQL, checks SUPERUSER privileges, and attempts OS command execution via `COPY FROM PROGRAM`.

```
Vault → Database Credentials → PostgreSQL Connection → SUPERUSER Check → OS Shell
```

```bash
python main.py scan --target https://vault:8200 --token root --pivot --confirm-active
```

The hijack scanner currently looks for:

- Vault tokens and response-wrapped tokens: `hvs.*`, `hvc.*`, wrapped-token examples, `VAULT_TOKEN`, `vault_token`
- AppRole material: `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `role_id`, `secret_id`, `roleId`, `secretId`
- AppRole flow clues: `auth/approle/login`, role-id retrieval paths, Secret ID generation paths, CLI AppRole login examples
- Vault addresses and namespaces: `VAULT_ADDR`, `vault_addr`, `:8200`, `VAULT_NAMESPACE`
- AWS IAM Vault auth clues: `auth/aws/login`, `auth/aws/role/*`, AWS credential environment variables, role ARNs, bound IAM principal ARNs, `X-Vault-AWS-IAM-Server-ID`
- Vault Database Secrets Engine clues: `database/config/*`, `database/roles/*`, `database/creds/*`, database plugins, connection URLs, `creation_statements`, `revocation_statements`, `default_ttl`, `max_ttl`
- Static DB credential clues: `DB_USERNAME`, `DB_PASSWORD`, `DATABASE_PASS`, `db_password`, `pg_password`, `mysql_password`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, `PGUSER`, `PGPASSWORD`
- Vault Agent clues: `auto_auth`, file token sinks, `role_id_file_path`, `secret_id_file_path`, `exit_after_auth`, template destinations, HCL config blocks with Vault addresses

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
