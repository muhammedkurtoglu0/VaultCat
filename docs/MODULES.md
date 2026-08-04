# Active Execution Modules

30 state-changing assessment modules. All gated behind `--confirm-active` and `--active-max-risk`.

## Risk Levels

| Level | Description | Gate |
|-------|-------------|------|
| `read_only` | No state changes — safe | Runs by default |
| `state_changing` | Creates resources, modifies config | Requires `--confirm-active --active-max-risk state_changing` |
| `destructive` | Destroys or disables resources | Requires `--confirm-active --active-max-risk destructive` |

## Module Reference

### Cloud

| Module ID | Risk | Description |
|-----------|------|-------------|
| `cloud_key_exfiltration.key_dump` | `state_changing` | Locate and exfiltrate cloud provider IAM keys (AWS/Azure/GCP) |
| `cloud_exploit.exploit` | `destructive` | Cloud provider exploitation (IAM user, EC2, S3 creation) |
| `cloud_pivot.exploit` | `destructive` | Cloud infrastructure pivot → enumerate resources |
| `aws_auth.login` | `state_changing` | AWS IAM → Vault login via SigV4 signed GetCallerIdentity |

### Database

| Module ID | Risk | Description |
|-----------|------|-------------|
| `database_credential_harvest.dynamic_creds` | `state_changing` | Generate dynamic DB users from all accessible roles |
| `database_exploit.exploit` | `destructive` | DML/DDL on harvested database credentials |
| `database_pivot.exploit` | `destructive` | Direct database exploitation via harvested credentials |

### General

| Module ID | Risk | Description |
|-----------|------|-------------|
| `agent_sidecar_attack.scan` | `read_only` | Agent HCL discovery, sink token theft, AppRole file reading |
| `cve_scanner.scan` | `state_changing` | Active CVE exploitation (12 known Vault CVEs) |
| `dos_exploit.exploit` | `state_changing` | DoS exploit for CVE-2023-6337 & CVE-2025-6203 |
| `unauthenticated.attack` | `read_only` | Unauthenticated attack surface scanning |

### Persistence

| Module ID | Risk | Description |
|-----------|------|-------------|
| `persistence.backdoor` | `destructive` | Deploy persistent auth backdoor (AppRole) |
| `multi_persistence.backdoor` | `destructive` | Deploy multiple concurrent backdoors (AppRole + K8s + LDAP) |
| `audit_backdoor.disable` | `destructive` | Disable audit devices + log injection |

### Pivot

| Module ID | Risk | Description |
|-----------|------|-------------|
| `pivot_engine.cross_service` | `destructive` | Cross-service pivot: Vault → DB → OS shell |
| `payload_module.reverse_shell` | `destructive` | Reverse shell via PostgreSQL COPY FROM PROGRAM |

### Seal

| Module ID | Risk | Description |
|-----------|------|-------------|
| `vault_seal.seal_status` | `read_only` | Check whether Vault is sealed |
| `vault_seal.seal_vault` | `state_changing` | Seal Vault (**DoS — all tokens invalid, all engines stop**) |
| `vault_seal.unseal_vault` | `state_changing` | Unseal Vault with Shamir key |
| `unseal_key.exfiltration` | `destructive` | Exfiltrate Shamir unseal key material |

### Secrets

| Module ID | Risk | Description |
|-----------|------|-------------|
| `secret_exfiltration.kv_dump` | `read_only` | Enumerate and dump all KV secrets, Transit keys, PKI certs, SSH roles |
| `transit_engine_exploit.operations` | `state_changing` | Transit: key audit, encrypt/decrypt PoC, datakey, HMAC, rotate |
| `pki_engine_exploit.operations` | `state_changing` | PKI: CA/CRL download, 9-flag role audit, cert issuance PoC |
| `raft_storage.exploit` | `destructive` | Raft: snapshot download + raft.db SQLite parsing + WAL analysis |

### Token

| Module ID | Risk | Description |
|-----------|------|-------------|
| `privilege_escalation.token_abuse` | `state_changing` | Auto-detect wildcard sudo, create backdoor policies, generate root tokens |
| `token_exploit.creation` | `state_changing` | Create, renew, lookup, orphan tokens |
| `policy_exploit.modification` | `state_changing` | List, read, clone, escalate policies |
| `kubernetes_auth_exploit.login` | `state_changing` | K8s: JWT decode, auth config audit, SA token login, CVE-2023-46835 |
| `jwt_oidc_exploit.audit` | `state_changing` | JWT/OIDC: discovery doc + JWKS fetch, algorithm confusion |
| `approle_exploit.bypass` | `state_changing` | AppRole: config audit, bind_secret_id bypass, CIDR bypass |

## Usage

```bash
# Read-only: no --confirm-active needed
vaultcat scan --target URL --token TOKEN --active-auto

# State-changing: requires confirmation
vaultcat scan --target URL --token TOKEN --active-auto \
  --active-max-risk state_changing --confirm-active

# Single module
vaultcat scan --target URL --token TOKEN \
  --module privilege_escalation.token_abuse --confirm-active
```
