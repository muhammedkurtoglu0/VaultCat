# CLI Flags Reference

All flags for the 5 commands: `scan`, `hijack`, `chat`, `cleanup`, `mcp`.

## Global

`python main.py <flags>` is automatically rewritten to `python main.py scan <flags>`.

## `scan` — Full Pentest Assessment

```
vaultcat scan [OPTIONS]
```

### Target & Auth

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | `str` | — | Target Vault URL (`http://localhost:8200`) |
| `--addr` | `str` | — | Legacy alias for `--target` |
| `--token` | `str` | — | Vault token for authenticated checks |
| `--namespace` | `str` | — | Vault namespace |
| `--skip-tls-verify` | `bool` | `False` | Disable TLS certificate verification |

### Recon

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--skip-recon` | `bool` | `False` | Skip default unauthenticated recon |
| `--vault-recon` | `bool` | `False` | Run async health/seal/leader recon |
| `--nvd-refresh` | `bool` | `False` | Force-refresh NVD CVE cache |
| `--env-scan` | `bool` | `False` | Scan local environment for Vault variables |

### Authenticated Audit

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--capability-audit` | `bool` | `False` | Audit token capabilities (`sys/capabilities-self`) |
| `--capability-path` | `list[str]` | — | Path for capability audit (repeatable) |
| `--priv-esc-audit` | `bool` | `False` | Simulate privilege escalation risk |
| `--token-policy` | `list[str]` | — | Policy name for priv-esc audit (repeatable) |
| `--auth-config-audit` | `bool` | `False` | Audit Kubernetes/AWS/LDAP/JWT/OIDC auth config |
| `--ttl-audit` | `bool` | `False` | Audit TTL governance (mounts + PKI) |
| `--max-mount-ttl-seconds` | `int` | `2592000` | Max mount TTL threshold (30 days) |
| `--max-pki-cert-ttl-seconds` | `int` | `7776000` | Max PKI cert TTL threshold (90 days) |

### KV Enumeration

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--kv-enum` | `bool` | `False` | Enumerate KV secret paths |
| `--kv-path` | `str` | — | KV start path |
| `--kv-version` | `int` | — | KV engine version (1 or 2) |
| `--kv-max-depth` | `int` | `10` | Max recursion depth |
| `--kv-concurrency` | `int` | `5` | Max concurrent KV operations |
| `--kv-no-read` | `bool` | `False` | Only list paths, don't read metadata |
| `--kv-blind` | `bool` | `False` | Brute-force common secret names on 403 |

### Policy & Secret

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--secret-path` | `str` | `secret/data/myapp` | Secret path to test |
| `--policy` | `str` | — | Policy name to analyze |

### Validation (opt-in)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--validate-token` | `bool` | `False` | Validate discovered tokens against live Vault |
| `--validate-approle` | `bool` | `False` | Validate discovered AppRole pairs |
| `--role-id` | `str` | — | Role ID for AppRole validation |
| `--secret-id` | `str` | — | Secret ID for AppRole validation |
| `--approle-mount` | `str` | `approle` | AppRole auth mount path |
| `--validate-db` | `bool` | `False` | Validate DB secrets engine metadata |

### Active Execution

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--active-auto` | `bool` | `False` | Run default-enabled active execution modules |
| `--active-max-risk` | `str` | `read_only` | Max risk: `read_only`, `state_changing`, `destructive` |
| `--confirm-active` | `bool` | `False` | **Required** for state-changing or destructive modules |
| `--active-policy` | `list[str]` | — | Policy for active token creation (repeatable) |
| `--active-ttl` | `str` | `30m` | TTL for active token creation |
| `--active-exfil-max-depth` | `int` | `5` | Max KV depth for active exfiltration |
| `--module` | `str` | — | Run a single specific module by ID |

### Pivot & Persistence

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pivot` | `bool` | `False` | Enable cross-service pivot (DB → OS → infra) |
| `--db-pivot` | `bool` | `False` | Enable database pivot module |
| `--cloud-pivot` | `bool` | `False` | Enable cloud pivot module |
| `--persistence` | `bool` | `False` | Enable persistence module |

### Hijack (inline with scan)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--hijack-path` | `str` | — | Scan a path for leaked Vault credentials |
| `--no-git-history` | `bool` | `False` | Skip git history scanning |
| `--exclude-dir` | `list[str]` | — | Exclude directory (repeatable) |
| `--max-file-size-mb` | `int` | `5` | Max file size for hijack scan |
| `--workers` | `int` | `0` | Parallel scanner workers (0=auto) |

### AI Analysis

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ai-provider` | `str` | — | LLM provider for AI analysis after scan |
| `--ai-model` | `str` | — | LLM model name (auto-detected if not set) |

### Output

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--min-severity` | `str` | — | Minimum severity to show/export |
| `--json` | `str` | — | Export findings to JSON file |
| `--markdown` | `str` | — | Export findings to Markdown file |
| `--pdf-report` | `str` | — | Export findings to PDF with remediation |

---

## `hijack` — Credential Hijacking Scan

```
vaultcat hijack <PATH> [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `path` (positional) | `str` | **required** | Path to scan for Vault credentials |
| `--target` | `str` | — | Vault address for validation |
| `--token` | `str` | — | Vault token for validation |
| `--validate-token` | `bool` | `False` | Validate discovered tokens |
| `--validate-approle` | `bool` | `False` | Validate discovered AppRole pairs |
| `--validate-db` | `bool` | `False` | Validate DB secrets engine metadata |
| `--role-id` | `str` | — | Role ID for AppRole validation |
| `--secret-id` | `str` | — | Secret ID for AppRole validation |
| `--capability-path` | `list[str]` | — | Paths for capability audit (repeatable) |
| `--no-git-history` | `bool` | `False` | Skip git history scanning |
| `--exclude-dir` | `list[str]` | — | Exclude directory (repeatable) |
| `--max-file-size-mb` | `int` | `5` | Max file size to scan (MB) |
| `--workers` | `int` | `0` | Parallel scanner workers (0=auto) |
| `--min-severity` | `str` | — | Minimum severity to show/export |
| `--json` | `str` | — | Export findings to JSON |
| `--markdown` | `str` | — | Export findings to Markdown |

---

## `chat` — AI-Powered Pentest Agent

```
vaultcat chat [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | `str` | — | Vault address |
| `--token` | `str` | — | Vault token |
| `--provider` | `str` | — | LLM provider: `ollama`, `openai`, `anthropic`, `deepseek` |
| `--model` | `str` | — | LLM model name |
| `--skip-tls-verify` | `bool` | `False` | Disable TLS certificate verification |
| `--disable-web` | `bool` | `False` | Disable automatic web search |
| `--auto-pilot` | `bool` | `False` | Auto-execute high-confidence PoC chains |
| `--stealth` | `bool` | `False` | Enable stealth HTTP rate-limiting |
| `--profile` | `str` | `balanced` | Evasion profile: `turbo`, `aggressive`, `balanced`, `stealth`, `paranoid`, `low_and_slow` |
| `--waf-evasion` | `str` | `none` | WAF evasion: `none`, `light`, `moderate`, `aggressive` |
| `--auto-cleanup` | `bool` | `False` | Auto-rollback state changes on session end |
| `--auto` | `bool` | `False` | Fully autonomous pentest (non-interactive) |
| `--pdf-report` | `str` | — | PDF report output path |
| `--hijack-path` | `str` | — | Scan local path for credentials during auto mode |
| `--auto-max-risk` | `str` | `read_only` | Max risk for auto mode |
| `--auto-max-turns` | `int` | `30` | Max LLM turns during auto mode |
| `--interval` | `int` | — | Repeat auto mode every N seconds (cron-like) |
| `--ui` | `str` | `terminal` | UI mode: `terminal` or `desktop` |

---

## `cleanup` — Rollback State Changes

```
vaultcat cleanup [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | `str` | **required** | Vault address |
| `--token` | `str` | **required** | Vault token with cleanup privileges |
| `--dry-run` | `bool` | `False` | List what would be cleaned without executing |
| `--skip-tls-verify` | `bool` | `False` | Disable TLS certificate verification |

---

## `mcp` — MCP Server

```
vaultcat mcp [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--skip-tls-verify` | `bool` | `False` | Disable TLS certificate verification |

Starts a FastMCP server on `127.0.0.1:8000` exposing 43 pentest tools.
