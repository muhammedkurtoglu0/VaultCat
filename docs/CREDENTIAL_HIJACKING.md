# Credential Hijacking

Local file system and git history scanning for leaked Vault credentials. For post-exploitation or authorized internal assessment.

## Quick Start

```bash
vaultcat hijack ./target-directory
```

## What Gets Detected (56 regex patterns)

### Vault Tokens & Auth
- `hvs.*`, `hvc.*`, `s.*` tokens
- Response-wrapped tokens
- `VAULT_TOKEN`, `vault_token` env vars
- `auth/approle/login` API paths
- Role ID / Secret ID generation paths

### AppRole Material
- `VAULT_ROLE_ID`, `VAULT_SECRET_ID`
- `role_id`, `secret_id`, `roleId`, `secretId`
- `role_id_file_path`, `secret_id_file_path`

### AWS IAM Vault Auth
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- IAM role ARNs, bound principal ARNs
- `X-Vault-AWS-IAM-Server-ID`

### Database Credentials
- PostgreSQL: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `PGUSER`, `PGPASSWORD`
- MySQL: `MYSQL_USER`, `MYSQL_PASSWORD`
- Generic: `DB_USERNAME`, `DB_PASSWORD`, `DATABASE_PASS`
- Connection URLs, `database/config/*`, `database/roles/*`

### Vault Agent & Sidecar
- `auto_auth` config blocks
- File token sinks
- Template destinations
- HCL config blocks with Vault addresses

### Network & Namespace
- `VAULT_ADDR`, `vault_addr`, `:8200` URLs
- `VAULT_NAMESPACE`

## Correlation & Chain Detection

The `hijack_analyzer` performs:
- **Per-file correlation**: `role_id` + `secret_id` in same file → HIGH
- **Cross-file chain detection**: `vault_addr` + AppRole pair across scope → HIGH
- **AWS chain detection**: `vault_addr` + AWS keys + `auth/aws/login` path → HIGH

## Validation (Opt-in)

```bash
# Validate discovered tokens against live Vault
vaultcat hijack ./repo --validate-token --target https://vault:8200 --token AUTH_TOKEN

# Validate AppRole pairs
vaultcat hijack ./repo --validate-approle --target https://vault:8200

# Validate database secrets engine
vaultcat hijack ./repo --validate-db --target https://vault:8200 --token AUTH_TOKEN

# Direct AppRole login + capability audit
vaultcat scan --target https://vault:8200 --validate-approle \
  --role-id ROLE_ID --secret-id SECRET_ID \
  --capability-path "database/roles/*" --capability-path "sys/*"
```

## Noise & Scope Controls

```bash
vaultcat hijack ./repo \
  --min-severity HIGH \
  --no-git-history \
  --exclude-dir vendor --exclude-dir build \
  --max-file-size-mb 2 \
  --workers 8
```

| Flag | Effect |
|------|--------|
| `--min-severity HIGH` | Show/export only HIGH and CRITICAL findings |
| `--no-git-history` | Skip git history for faster triage |
| `--exclude-dir NAME` | Exclude directory (repeatable) |
| `--max-file-size-mb N` | Skip files larger than N MB |
| `--workers N` | Parallel scanner workers (0=auto) |

## Default Excluded Directories
`.git`, `.terraform`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `vendor`, `cache`, `.vscode`, `.idea`

## Export

```bash
vaultcat hijack ./repo --json findings.json --markdown findings.md
```

## Modules

| Module | Role |
|--------|------|
| `patterns.py` | 56 regex patterns + finding metadata |
| `file_secret_scanner.py` | File walker + git history scanner |
| `hijack_analyzer.py` | Cross-file correlation + chain detection |
| `validators.py` | Token/AppRole validation against live Vault |
| `db_validator.py` | Database secrets engine validation |
| `impact_analyzer.py` | Blast-radius analysis |
