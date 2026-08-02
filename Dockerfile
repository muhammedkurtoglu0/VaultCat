# ── Vault Pentest Tool — Docker Image ──────────────────────────────────
# Build:  docker build -t vault-pentest .
# Run:    docker run --rm -it vault-pentest --target https://vault:8200
#
# The image uses `uv` for fast, deterministic dependency resolution
# (pinned by uv.lock) and runs as a non-root user for safety.
# ────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

LABEL org.opencontainers.image.title="vault-pentest-tool"
LABEL org.opencontainers.image.description="Authorized HashiCorp Vault reconnaissance & credential hijacking risk assessment CLI"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/muhammedkurtoglu0/vault-pentest-tool"

# ── System dependencies ────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ──────────────────────────────────────────────────────
RUN groupadd --system vault-pentest && \
    useradd --system --no-log-init --gid vault-pentest --create-home vault-pentest

# ── Install uv ─────────────────────────────────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:0.6.17 /uv /usr/local/bin/uv

WORKDIR /app

# ── Dependency layer (cached unless lock files change) ─────────────────
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ── Application layer ──────────────────────────────────────────────────
COPY . .

RUN uv sync --frozen --no-dev \
    && chown -R vault-pentest:vault-pentest /app

USER vault-pentest

# ── Runtime ────────────────────────────────────────────────────────────
ENTRYPOINT ["uv", "run", "python", "main.py"]
CMD ["--help"]
