# MCP Integration Guide

The Vault Pentest Tool exposes **43 pentest tools** via a FastMCP server on `127.0.0.1:8000`. Connect any MCP-compatible AI client (Claude Desktop, Continue, Cursor, etc.) to give it direct Vault pentest capabilities.

## Quick Start

### 1. Start the MCP Server

```bash
vault-pentest mcp
# or: python main.py mcp
```

The server listens on `127.0.0.1:8000` with streamable HTTP transport.

### 2. Connect Claude Desktop

Open Claude Desktop → **Settings** → **Developer** → **Edit Config**, then add:

```json
{
  "mcpServers": {
    "vault-pentest": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

Restart Claude Desktop. You'll see 43 new tools in Claude's toolbox.

### 3. Start Pentesting

In Claude Desktop, just describe what you want:

- *"Scan https://vault.example.com:8200 for vulnerabilities"*
- *"I found this token: hvs.xxx — audit its capabilities"*
- *"Run a privilege escalation simulation on this target"*

## Available Tool Categories

| Category | Count | Tools |
|----------|-------|-------|
| **Recon** | 6 | `run_unauthenticated_recon`, `run_network_probe`, `run_env_scan`, `run_hijack_scan`, `run_vault_agent_scan`, `get_threat_intel` |
| **Audit** | 7 | `run_capability_audit`, `run_priv_esc_scan`, `run_kv_enumeration`, `run_ttl_audit`, `run_auth_config_audit`, `run_policy_auditor`, `read_single_policy` |
| **Active Execution** | 15+ | `run_active_module` (29 modules), `run_privilege_escalation`, `run_secret_exfiltration`, `run_database_credential_harvest`, `run_cloud_key_exfiltration`, `run_aws_auth_login`, `run_approle_exploit`, `run_jwt_oidc_exploit`, `run_kubernetes_auth_exploit`, `run_raft_exploit`, `run_pki_exploit`, `run_transit_exploit` |
| **Reporting** | 5 | `get_findings`, `get_risk_score`, `get_fix_commands`, `export_full_report`, `generate_diff_report` |
| **Meta** | 10 | `web_search`, `search_to_actions`, `list_active_modules`, `decode_generate_root_otp`, `set_evasion_profile`, `run_cleanup_tool`, `run_compliance_check`, `run_container_scan`, `run_audit_log_scan`, `send_notification` |

## Security

- **Read-only by default**: All tools default to `max_risk="read_only"`. State-changing operations require explicit `max_risk="state_changing"` or `max_risk="destructive"`.
- **No token needed for recon**: Unauthenticated tools work without credentials.
- **Local-only**: MCP server binds to `127.0.0.1` — not exposed to the network.

## Using with Other MCP Clients

Any MCP client supporting streamable HTTP can connect. The endpoint is:

```
http://127.0.0.1:8000/mcp
```

For **VS Code / Continue**, add to `~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "vault-pentest",
        "url": "http://127.0.0.1:8000/mcp"
      }
    ]
  }
}
```

## Troubleshooting

**"Connection refused"**: Make sure the MCP server is running (`vault-pentest mcp`).

**"Tool call failed"**: Check that you've set `--target` and optionally `--token`. The server inherits no default configuration.

**TLS errors**: Pass `--skip-tls-verify` to the MCP server if your Vault uses self-signed certs.
