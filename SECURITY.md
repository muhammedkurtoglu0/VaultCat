# Security Policy

This project is a **Vault penetration testing toolkit** for authorized security testing and internal risk assessment.

**Do not use it against systems without explicit written permission.**

## Risk-Level System

Every active module declares a risk level. The tool enforces this at runtime — you cannot
accidentally run destructive operations:

| Level | Description | CLI Guard |
|---|---|---|
| `read_only` | No state changes, reads metadata only | Runs without confirmation |
| `state_changing` | Creates resources, modifies config, generates credentials | Requires `--confirm-active` |
| `destructive` | Destroys, disables, deploys backdoors, OS command execution | Requires `--confirm-active` |

## Supported Use

- **Authorized Vault reconnaissance** — unauthenticated endpoint probing, TLS/header/CORS checks, auth surface mapping, version-to-CVE matching
- **Authenticated assessment** — token capability audit, policy analysis, TTL governance, KV enumeration (metadata-only), auth config audit, privilege escalation simulation (read-only `sys/capabilities-self`)
- **Credential exposure assessment** — file/git scanning for tokens, AppRole pairs, DB credentials, cloud keys; cross-file correlation and chain detection
- **Metadata-only validation** — opt-in `--validate-token`, `--validate-approle`, `--validate-db` flags that only check Vault metadata (never read secrets)
- **Active execution (authorized labs only)** — controlled token creation, secret exfiltration, DB credential harvest, cloud key dump, persistence deployment, and pivot engine cross-service lateral movement; all gated by `--active-max-risk` + `--confirm-active`
- **AI-powered autonomous pentesting** — LLM-driven agent with ReAct loop, attack tree walking, auto-pilot PoC execution; web search with 24h cache for CVE research

## Out of Scope

- Brute force, password cracking, or credential stuffing
- Unauthorized access — every operation requires a valid token or explicit user confirmation
- Network-level DoS beyond Vault seal/unseal (which is part of authorized resilience testing)

## Guardrails

The tool has multiple layers of protection against accidental misuse:

1. **Risk-level gating** — `read_only` modules run freely; `state_changing` and `destructive` modules refuse to execute without the `--confirm-active` CLI flag (or `confirm_active=True` in API calls)

2. **Auto-pilot safety** — `--auto-pilot` mode auto-executes PoC chains from web search results, but **only** `read_only` and `state_changing` chains; destructive chains are skipped unless explicitly confirmed

3. **Seal/unseal guard** — `vault_seal.seal_vault` requires a Shamir unseal key for recovery; the tool warns before executing and never seals without confirmation

4. **Pivot engine guard** — `pivot_engine.cross_service` attempts OS command execution via PostgreSQL `COPY FROM PROGRAM`; this is `destructive` risk level and requires both `--pivot` and `--confirm-active`

5. **Session isolation** — the MCP server (`main.py mcp`) maintains per-session token stores and TTL cleanup; tokens from one session never leak to another

## Active Execution Modules

All modules are in `active_execution/modules/`. Listed here with their exact `module_id` and declared risk level:

| Module ID | Risk | Description |
|---|---|---|
| `privilege_escalation.token_abuse` | `state_changing` | Auto-detect wildcard sudo paths, create backdoor policies, generate root-equivalent tokens |
| `secret_exfiltration.kv_dump` | `read_only` | Enumerate + dump all KV secrets, Transit keys, PKI certs |
| `database_credential_harvest.dynamic_creds` | `state_changing` | Generate dynamic DB users from all accessible roles |
| `cloud_key_exfiltration.key_dump` | `state_changing` | Locate + exfiltrate cloud provider keys (AWS/Azure/GCP) |
| `vault_seal.seal_status` | `read_only` | Check whether Vault is sealed |
| `vault_seal.seal_vault` | `state_changing` | Seal Vault (DoS — all tokens invalid, all engines stop) |
| `vault_seal.unseal_vault` | `state_changing` | Unseal Vault with Shamir key (recovery) |
| `audit_backdoor.disable` | `destructive` | Disable all audit devices to hide activity |
| `token_exploit.creation` | `state_changing` | Create, renew, lookup, orphan tokens |
| `policy_exploit.modification` | `state_changing` | List, read, clone, escalate policies |
| `persistence.backdoor` | `destructive` | Deploy persistent auth backdoor (AppRole/userpass) |
| `multi_persistence.backdoor` | `destructive` | Deploy multiple concurrent backdoors across auth methods |
| `pivot_engine.cross_service` | `destructive` | Cross-service pivot: Vault→DB→OS shell (PostgreSQL `COPY FROM PROGRAM`) |
| `database_pivot.exploit` | `destructive` | Direct database exploitation via harvested credentials |
| `database_exploit.exploit` | `destructive` | Database engine exploitation (privilege escalation within DB) |
| `cloud_pivot.exploit` | `destructive` | Cloud infrastructure pivot via exfiltrated IAM keys |
| `cloud_exploit.exploit` | `destructive` | Cloud provider exploitation (IAM privilege escalation) |
| `raft_storage.exploit` | `destructive` | Raft storage manipulation (snapshot extraction, tampering) |
| `unseal_key.exfiltration` | `destructive` | Exfiltrate Shamir unseal key material from Vault internals |
| `payload_module.reverse_shell` | `destructive` | Deploy reverse shell payload via compromised Vault access |
| `cve_scanner.scan` | `state_changing` | Active CVE exploitation attempts against known Vault CVEs |
| `unauthenticated.attack` | `read_only` | Unauthenticated attack surface scanning (no credentials needed) |

## Auto-Pilot Mode (`--auto-pilot`)

When enabled, the AI agent automatically executes PoC chains extracted from web search
results. Safety rules:

- **Only** chains with `high` or `medium` confidence are executed
- **Only** `read_only` and `state_changing` steps run automatically
- **Destructive** chains are always skipped — the agent reports them but waits for explicit confirmation
- Every auto-executed step is logged with its result in the conversation history

## Reporting Issues

If you find a bug that could expose secrets, bypass risk-level gating, or perform
unintended writes, treat it as sensitive and report it privately to the project owner.

**Please include:**
- Affected module ID and risk level
- Steps to reproduce (target config, token privileges, CLI flags)
- Whether the bug bypassed `--confirm-active` or risk-level checks
