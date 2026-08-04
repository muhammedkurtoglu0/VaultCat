# Unauthenticated Reconnaissance

Zero-knowledge external recon — start with **only a target URL**, no credentials.

## Quick Start

```bash
vault-pentest scan --target https://vault.example.com:8200
```

This runs all safe unauthenticated checks. No token required.

## What Gets Scanned

### Health & Version
- `/v1/sys/health` — initialized, sealed, standby status, version, cluster metadata
- `/v1/sys/seal-status` — Shamir config (t/n), sealed state, migration status
- `/v1/sys/leader` — HA status, leader address, cluster address

### TLS & Certificates
- Certificate expiry, self-signed detection, subject/SAN parsing
- HTTP → HTTPS redirect behavior
- TLS version and cipher suite audit

### HTTP Security
- HSTS, X-Content-Type-Options, CSP, X-Frame-Options headers
- CORS misconfiguration detection (wildcard origin + credentials)
- Server header leakage

### Vault Fingerprinting
- Confirms target is actually HashiCorp Vault
- UI exposure (`/ui/`, login page reachability)
- Deployment indicators (reverse proxy headers, dev-mode)

### Auth Surface Mapping
- 9 auth method types probed via unauthenticated endpoints
- Identifies which auth methods are enabled (userpass, LDAP, OIDC, etc.)

### Endpoint Discovery
Curated list of known unauthenticated Vault endpoints:
`/v1/sys/health`, `/v1/sys/seal-status`, `/v1/sys/leader`, `/v1/sys/internal/ui/mounts`, `/v1/sys/init`

## Async Recon (`--vault-recon`)

```bash
vault-pentest scan --target https://vault.example.com:8200 --vault-recon
```

Queries health, seal-status, and leader endpoints in parallel. Reports sealed state, cluster metadata, version, and leader info.

## CVE Matching

When a Vault version is discovered, the tool automatically:

1. **Static match**: 11 bundled CVEs covering Vault 1.12–1.19
2. **Live match**: Queries NVD API 2.0 for 36+ CVEs (24h disk cache)

```bash
# Force-refresh NVD cache
vault-pentest scan --target URL --nvd-refresh

# Use NVD API key for higher rate limits
export NVD_API_KEY=your-key-here
```

Results appear in findings and via `get_threat_intel`.

## Skip Recon

If you're re-scanning or only want authenticated checks:

```bash
vault-pentest scan --target URL --token TOKEN --skip-recon
```

## Recon Modules

| Module | What it checks |
|--------|---------------|
| `health_scanner.py` | `/v1/sys/health` reachability |
| `fingerprint_scanner.py` | Confirms Vault identity |
| `ui_scanner.py` | UI exposure |
| `header_scanner.py` | Security headers |
| `endpoint_scanner.py` | Known endpoint probing |
| `vault_recon.py` | Async health/seal/leader metadata |
| `version_cve_matcher.py` | Version → CVE matching |
| `version_risk_scanner.py` | Version risk scoring + honeypot detection |
| `auth_surface_scanner.py` | Auth method surface mapping |
| `cors_scanner.py` | CORS misconfiguration |
| `tls_scanner.py` | TLS/HTTPS + certificate analysis |
| `deployment_scanner.py` | Reverse proxy + dev-mode detection |
| `nvd_client.py` | NVD API 2.0 client |
