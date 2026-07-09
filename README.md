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

Async health, seal, and leader metadata collection:

```bash
python main.py --target http://localhost:8200 --vault-recon
```

`--vault-recon` queries `/v1/sys/health`, `/v1/sys/seal-status`, and `/v1/sys/leader` without a token and returns sealed state, cluster metadata, version, and leader metadata for authorized vulnerability management and version tracking.

When a Vault version is observed, the recon workflow also compares it against a small local advisory table for known Vault CVE ranges. This check does not query the internet at runtime.

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

- `reconnaissance/health_scanner.py`
- `reconnaissance/fingerprint_scanner.py`
- `reconnaissance/ui_scanner.py`
- `reconnaissance/header_scanner.py`
- `reconnaissance/endpoint_scanner.py`
- `reconnaissance/vault_recon.py`
- `reconnaissance/version_cve_matcher.py`
- `scanners/token_scanner.py`
- `scanners/auth_config_scanner.py`
- `scanners/capability_scanner.py`
- `scanners/kv_enumerator.py`
- `scanners/ttl_scanner.py`
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

Read-only active modules can be selected with:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --active-auto
```

State-changing modules, such as token creation attempts, require both an explicit risk level and confirmation:

```bash
python main.py --target http://localhost:8200 --token YOUR_TOKEN --active-auto --active-max-risk state_changing --confirm-active
```

The active execution engine blocks modules above the selected risk level, requires explicit confirmation for state-changing modules, and converts module failures into structured execution results.

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
