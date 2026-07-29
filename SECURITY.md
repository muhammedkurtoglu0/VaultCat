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
- **Active execution (authorized labs only)** — controlled token creation, secret exfiltration, DB credential harvest, cloud key dump, Transit encrypt/decrypt PoC, PKI certificate issuance, K8s/JWT/OIDC auth exploitation, AppRole bypass, persistence deployment, and pivot engine cross-service lateral movement; all gated by `--active-max-risk` + `--confirm-active`
- **Raft storage assessment** — snapshot download via API (contains all Vault state), raft.db SQLite parsing, WAL analysis, peers.json reading (requires filesystem access or high-privilege token)
- **Vault Agent / Sidecar assessment** — local HCL config discovery, sink token extraction, AppRole credential file reading (requires filesystem access)
- **AI-powered autonomous pentesting** — LLM-driven agent with ReAct loop, attack tree walking, parallel domain orchestrator, auto-pilot PoC execution; web search with 24h cache for CVE research; 43 MCP tools exposed via FastMCP server

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

All modules are in `active_execution/modules/`. Listed here with their exact `module_id` and declared risk level (29 total):

| Module ID | Risk | Description |
|---|---|---|
| `privilege_escalation.token_abuse` | `state_changing` | Auto-detect wildcard sudo paths, create backdoor policies, generate root-equivalent tokens |
| `secret_exfiltration.kv_dump` | `read_only` | Enumerate + dump all KV secrets, Transit keys, PKI certs, SSH roles |
| `database_credential_harvest.dynamic_creds` | `state_changing` | Generate dynamic DB users from all accessible roles |
| `cloud_key_exfiltration.key_dump` | `state_changing` | Locate + exfiltrate cloud provider keys (AWS/Azure/GCP) |
| `vault_seal.seal_status` | `read_only` | Check whether Vault is sealed |
| `vault_seal.seal_vault` | `state_changing` | Seal Vault (DoS — all tokens invalid, all engines stop) |
| `vault_seal.unseal_vault` | `state_changing` | Unseal Vault with Shamir key (recovery) |
| `audit_backdoor.disable` | `destructive` | Disable audit devices + log injection + audit-hash HMAC test |
| `token_exploit.creation` | `state_changing` | Create, renew, lookup, orphan tokens |
| `policy_exploit.modification` | `state_changing` | List, read, clone, escalate policies |
| `persistence.backdoor` | `destructive` | Deploy persistent auth backdoor (AppRole) |
| `multi_persistence.backdoor` | `destructive` | Deploy multiple concurrent backdoors (AppRole+K8s+LDAP) |
| `pivot_engine.cross_service` | `destructive` | Cross-service pivot: Vault→DB→OS shell (PostgreSQL COPY FROM PROGRAM) |
| `database_pivot.exploit` | `destructive` | Direct database exploitation via harvested credentials |
| `database_exploit.exploit` | `destructive` | Database engine exploitation (privilege escalation within DB) |
| `cloud_pivot.exploit` | `destructive` | Cloud infrastructure pivot via exfiltrated IAM keys |
| `cloud_exploit.exploit` | `destructive` | Cloud provider exploitation (IAM privilege escalation) |
| `raft_storage.exploit` | `destructive` | Raft: snapshot download (API) + raft.db SQLite parsing (filesystem) |
| `unseal_key.exfiltration` | `destructive` | Exfiltrate Shamir unseal key material from Vault internals |
| `payload_module.reverse_shell` | `destructive` | Reverse shell ON target via PostgreSQL COPY FROM PROGRAM |
| `cve_scanner.scan` | `state_changing` | Active CVE exploitation against 12 known Vault CVEs |
| `unauthenticated.attack` | `read_only` | Unauthenticated attack surface scanning (no credentials needed) |
| **Tier 1 (v1.1):** | | |
| `transit_engine_exploit.operations` | `state_changing` | Transit: key metadata, exportable detection, encrypt/decrypt PoC, datakey, HMAC, rotate |
| `agent_sidecar_attack.scan` | `read_only` | Agent: HCL discovery, sink token theft, AppRole file reading, env scan |
| `pki_engine_exploit.operations` | `state_changing` | PKI: CA/CRL download, 9-flag role audit, cert issuance PoC |
| `kubernetes_auth_exploit.login` | `state_changing` | K8s: JWT decode, auth config audit, SA token login, CVE-2023-46835 |
| **Tier 2 (v1.2):** | | |
| `jwt_oidc_exploit.audit` | `state_changing` | JWT/OIDC: discovery doc + JWKS fetch, algorithm confusion, bound_claims audit |
| `approle_exploit.bypass` | `state_changing` | AppRole: config audit, bind_secret_id bypass, CIDR bypass (X-Forwarded-For) |

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
