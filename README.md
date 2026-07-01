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
core/                  Reporting, risk scoring, and Vault client helpers
credential_hijacking/  Artifact scanning, correlation, validation, and impact analysis
reconnaissance/        Safe unauthenticated Vault recon scanners
scanners/              Optional authenticated/local assessment helpers
test-artifacts/        Synthetic local fixtures for smoke testing
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

## Local Token Discovery

Local discovery is for post-exploitation or local assessment scenarios, not default external recon:

```bash
python main.py --env-scan
```

## Current Modules

- `reconnaissance/health_scanner.py`
- `reconnaissance/fingerprint_scanner.py`
- `reconnaissance/ui_scanner.py`
- `reconnaissance/header_scanner.py`
- `reconnaissance/endpoint_scanner.py`
- `scanners/token_scanner.py`
- `scanners/secret_scanner.py`
- `scanners/policy_scanner.py`
- `scanners/env_scanner.py`
- `credential_hijacking/file_secret_scanner.py`
- `credential_hijacking/hijack_analyzer.py`
- `credential_hijacking/validators.py`
- `credential_hijacking/impact_analyzer.py`

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

The hijack scanner currently looks for:

- Vault tokens: `hvs.*`, `hvc.*`, `VAULT_TOKEN`, `vault_token`
- AppRole material: `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `role_id`, `secret_id`, `roleId`, `secretId`
- AppRole flow clues: `auth/approle/login`, role-id retrieval paths, Secret ID generation paths, CLI AppRole login examples
- Vault addresses and namespaces: `VAULT_ADDR`, `vault_addr`, `:8200`, `VAULT_NAMESPACE`
- AWS IAM Vault auth clues: `auth/aws/login`, `auth/aws/role/*`, AWS credential environment variables, role ARNs, bound IAM principal ARNs, `X-Vault-AWS-IAM-Server-ID`
- Vault Database Secrets Engine clues: `database/config/*`, `database/roles/*`, `database/creds/*`, database plugins, connection URLs, `creation_statements`, `revocation_statements`, `default_ttl`, `max_ttl`
- Static DB credential clues: `DB_USERNAME`, `DB_PASSWORD`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, `PGUSER`, `PGPASSWORD`
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
