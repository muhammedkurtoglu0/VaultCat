# Environment Variables

Copy `.env.example` to `.env` and fill in your values. All are optional — the tool works without any.

## LLM Providers (at least one required for AI features)

| Variable | Provider | Default Model |
|----------|----------|---------------|
| `ANTHROPIC_API_KEY` | Anthropic | `claude-sonnet-5` |
| `OPENAI_API_KEY` | OpenAI | `gpt-4o-mini` |
| `DEEPSEEK_API_KEY` | DeepSeek | auto-detect |
| `KIMI_API_KEY` | Kimi (Moonshot) | auto-detect |
| `CURSOR_API_KEY` | Cursor | auto-detect |

## LLM Base URLs (override defaults)

| Variable | Default |
|----------|---------|
| `OLLAMA_HOST` | `http://localhost:11434` |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` |
| `KIMI_BASE_URL` | `https://api.moonshot.cn/v1` |
| `CURSOR_BASE_URL` | `https://api.cursor.sh/v1` |

## Model Override

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_DEFAULT_MODEL` | `claude-sonnet-5` | Override the default Anthropic model |

## Web Search

| Variable | Description |
|----------|-------------|
| `TAVILY_API_KEY` | Tavily search API key (1000 free queries/month). Falls back to DuckDuckGo if unset. |

## NVD CVE Database

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API 2.0 key. Without it: 5 req/30s. With it: 50 req/30s. |

## Vault Connection (scanned by `--env-scan`)

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Default Vault address |
| `VAULT_TOKEN` | Default Vault token |
| `VAULT_NAMESPACE` | Default Vault namespace |

## Test-Only

| Variable | Default |
|----------|---------|
| `VAULT_TEST_ADDR` | `https://localhost:8200` |
| `VAULT_TEST_TOKEN` | `""` |
