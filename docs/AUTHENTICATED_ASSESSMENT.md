# Authenticated Assessment

Token-based Vault security audit. All checks are **read-only** — they inspect configuration, not secrets.

Requires a Vault token with at least default policy access.

## Quick Start

```bash
vault-pentest scan --target https://vault.example.com:8200 --token hvs.xxx
```

## Capability Audit

```bash
vault-pentest scan --target URL --token TOKEN --capability-audit

# With specific paths:
vault-pentest scan --target URL --token TOKEN --capability-audit \
  --capability-path "sys/*" --capability-path "auth/*" \
  --capability-path "database/roles/*"
```

Uses `sys/capabilities-self` to check what the token can do on critical paths. Flags:
- `sudo` or write on `sys/*`, `auth/*`, `identity/*`
- Write on `database/config/*`, `database/roles/*`
- Wildcard policy grants

## Privilege Escalation Simulation

```bash
vault-pentest scan --target URL --token TOKEN --priv-esc-audit
```

Safely simulates whether the token can update its own ACL policy or create child tokens. **Does not create or modify anything.**

## Auth Configuration Audit

```bash
vault-pentest scan --target URL --token TOKEN --auth-config-audit
```

Audits external auth method configurations:
- **Kubernetes**: Broad SA bindings, issuer validation
- **AWS IAM**: Wildcard principal ARN bindings
- **LDAP**: Lockout threshold, rate limiting
- **JWT/OIDC**: Discovery URLs, bound claims, audience validation

## TTL Governance

```bash
vault-pentest scan --target URL --token TOKEN --ttl-audit

# Custom thresholds:
vault-pentest scan --target URL --token TOKEN --ttl-audit \
  --max-mount-ttl-seconds 2592000 \
  --max-pki-cert-ttl-seconds 7776000
```

Checks `sys/mounts` for `max_lease_ttl` and PKI role `ttl`/`max_ttl` values against thresholds.

## KV Enumeration

```bash
vault-pentest scan --target URL --token TOKEN --kv-enum

# Specific path and engine:
vault-pentest scan --target URL --token TOKEN --kv-enum \
  --kv-path secret/ --kv-version 2

# Deep scan:
vault-pentest scan --target URL --token TOKEN --kv-enum \
  --kv-path kv/app --kv-max-depth 5 --kv-concurrency 3

# List-only (don't read metadata):
vault-pentest scan --target URL --token TOKEN --kv-enum --kv-no-read

# Blind brute-force on 403:
vault-pentest scan --target URL --token TOKEN --kv-enum --kv-blind
```

Recursively lists accessible KV paths using parallel async workers. Builds a tree of readable secrets without printing values.

## Policy Analysis

```bash
vault-pentest scan --target URL --token TOKEN --policy admin
```

Enumerates ACL policies and parses HCL rules for wildcard patterns, sudo grants, and privilege boundaries.

## Secret Path Check

```bash
vault-pentest scan --target URL --token TOKEN --secret-path secret/data/myapp
```

Tests read access to a specific secret path.

## AppRole Validation

```bash
vault-pentest scan --target URL --validate-approle \
  --role-id ROLE_ID --secret-id SECRET_ID

# With capability audit of resulting token:
vault-pentest scan --target URL --validate-approle \
  --role-id ROLE_ID --secret-id SECRET_ID \
  --capability-path "database/roles/*" --capability-path "sys/*"
```

Performs an AppRole login with the supplied pair, analyzes the returned token's TTL, policies, and capabilities. Does not read secrets or modify state.

## Database Secrets Engine Validation

```bash
vault-pentest scan --target URL --token TOKEN --validate-db
```

Checks visible database mounts, listable roles, role TTLs, and creation statement exposure. Does **not** generate dynamic credentials.

## Report Export

```bash
vault-pentest scan --target URL --token TOKEN \
  --json report.json --markdown report.md --pdf-report report.pdf \
  --min-severity HIGH
```

## Scanner Modules

| Module | What it does |
|--------|-------------|
| `capability_scanner.py` | Token capability audit + auto-probe |
| `privilege_escalation_scanner.py` | Priv esc risk simulation |
| `policy_auditor.py` | ACL enumeration + HCL analysis |
| `policy_scanner.py` | HCL rule analyzer |
| `auth_config_scanner.py` | K8s/AWS/LDAP/JWT/OIDC audit |
| `ttl_scanner.py` | Mount + PKI TTL governance |
| `kv_enumerator.py` | Async KV enumeration + blind fallback |
| `token_scanner.py` | Token validity + metadata |
| `secret_scanner.py` | Secret path checks |
| `env_scanner.py` | Local env variable scan |
