# Vault Pentest Tool

[![Test](https://github.com/muhammedkurtoglu0/vault-pentest-tool/actions/workflows/test.yml/badge.svg)](https://github.com/muhammedkurtoglu0/vault-pentest-tool/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

Full-lifecycle HashiCorp Vault penetration testing toolkit — recon, hijack, escalate, exfiltrate, pivot, and persist across three operational modes.

- **External Recon** — zero-knowledge Vault fingerprinting, TLS/CORS/header audit, version→CVE matching, auth surface mapping
- **Authenticated Assessment** — token capability audit, policy analysis, KV enumeration, TTL governance, auth config audit
- **Local Post-Exploitation** — filesystem + git credential scanning (56 patterns), cross-file correlation, AppRole/DB validation
- **Active Execution** — 30 state-changing modules (privilege escalation, secret exfiltration, persistence, pivot, CVE exploitation)
- **AI Agent** — ReAct-loop autonomous pentest agent with multi-provider LLM, attack tree walker, and mutation engine
- **MCP Server** — 52 tools exposed via FastMCP for Claude Desktop and other AI clients

> **Ethics**: Use this tool only on systems you own or have explicit permission to assess. Read-only modules run freely; state-changing and destructive operations require `--confirm-active`. No brute-force or password cracking.

## Install

```bash
pip install vault-pentest-tool          # from PyPI (once published)
# or directly from GitHub:
pip install git+https://github.com/muhammedkurtoglu0/vault-pentest-tool.git

# Dev install (clone + deterministic build):
git clone https://github.com/muhammedkurtoglu0/vault-pentest-tool.git
cd vault-pentest-tool
uv sync
```

## Quick Start

```bash
# Unauthenticated recon
vault-pentest scan --target https://vault.example.com:8200

# Authenticated audit
vault-pentest scan --target https://vault.example.com:8200 --token hvs.xxx --capability-audit

# Local credential hijacking
vault-pentest hijack ./my-repo --validate-token --target https://vault.example.com:8200

# AI-powered pentest chat
vault-pentest chat --target https://vault.example.com:8200 --token hvs.xxx

# MCP server (for Claude Desktop integration)
vault-pentest mcp
```

## Documentation

| Guide | What it covers |
|-------|---------------|
| [CLI Flags Reference](docs/CLI_FLAGS.md) | All 50+ flags across 5 commands (`scan`, `hijack`, `chat`, `cleanup`, `mcp`) |
| [MCP Integration](docs/MCP_INTEGRATION.md) | Connect Claude Desktop, VS Code, and other AI clients |
| [Modules](docs/MODULES.md) | 30 active execution modules with risk levels and parameters |
| [Architecture](docs/ARCHITECTURE.md) | Component flow, package layout, attack tree design |
| [Environment Variables](docs/ENV_VARS.md) | LLM keys, base URLs, NVD, web search configuration |

## Connect to Claude Desktop

```bash
vault-pentest mcp --transport stdio
```

Then add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "vault-pentest": {
      "command": "vault-pentest",
      "args": ["mcp", "--transport", "stdio"]
    }
  }
}
```

52 pentest tools appear in Claude's toolbox. [Full MCP guide →](docs/MCP_INTEGRATION.md)

## Supported LLM Providers

| Provider | Env Var | Default Model |
|----------|---------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| DeepSeek | `DEEPSEEK_API_KEY` | auto-detect |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| Kimi | `KIMI_API_KEY` | auto-detect |
| Ollama (local) | `OLLAMA_HOST` | auto-detect |

## Project Layout

```text
main.py                 CLI entry point (Typer, 5 commands)
vault_cli.py            Typer app definition
core/                   Reporting, risk scoring, TLS config
reconnaissance/         14 unauthenticated recon scanners
scanners/               10 authenticated assessment scanners
credential_hijacking/   7 file/git scanning + correlation modules
active_execution/       30 state-changing assessment modules
  modules/
    cloud/              AWS/Azure/GCP exploitation
    database/           DB credential harvest + exploitation
    general/            CVE scanner, agent sidecar, DoS
    persistence/        Backdoors + audit manipulation
    pivot/              Cross-service lateral movement
    seal/               Seal/unseal + key exfiltration
    secrets/            KV dump, PKI, Transit, Raft storage
    token/              Priv esc, token/policy exploits, K8s/JWT/AppRole
ai_core/                LLM agent, MCP server, chat UI, planning, session
vault-pentest-lab/      Docker-based lab (Vault 1.15.3 + PostgreSQL 16)
tests/                  23 test files, 600+ tests
```

## Vault Pentest Lab

```bash
cd vault-pentest-lab
docker compose up -d
./scripts/setup-lab.sh
source lab-tokens.env
```

[Full lab guide →](vault-pentest-lab/README.md)

## License

MIT — see [LICENSE](LICENSE).
