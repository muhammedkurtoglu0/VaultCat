# ── VaultCat — Docker Image ─────────────────────────────────────────────
# Build:  docker build -t vaultcat .
# Run:    docker run --rm -it vaultcat scan --target https://vault:8200
#
# Deterministic build: Python + dependencies pinned via uv.lock (uv sync --frozen).
# Runs as a non-root user for safety.
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

LABEL org.opencontainers.image.title="vaultcat"
LABEL org.opencontainers.image.description="Full-lifecycle HashiCorp Vault penetration testing toolkit"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/muhammedkurtoglu0/vaultcat"

# ── System dependencies ────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ──────────────────────────────────────────────────────
RUN groupadd --system vaultcat && \
    useradd --system --no-log-init --gid vaultcat --create-home vaultcat

# ── Install uv (pinned to match uv.lock) ───────────────────────────────
COPY --from=ghcr.io/astral-sh/uv:0.11.17 /uv /usr/local/bin/uv

WORKDIR /app

# ── Dependency layer (cached unless lock files change) ─────────────────
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ── Application layer ──────────────────────────────────────────────────
COPY . .

RUN uv sync --frozen --no-dev --no-editable \
    && chown -R vaultcat:vaultcat /app

USER vaultcat

# ── Runtime ────────────────────────────────────────────────────────────
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["vaultcat"]
CMD ["--help"]
