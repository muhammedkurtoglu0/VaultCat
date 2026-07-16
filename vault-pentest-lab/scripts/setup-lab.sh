#!/usr/bin/env bash
# ==============================================================================
# Vault Pentest Lab — Setup Script (Git Bash / Linux)
# ==============================================================================
set -euo pipefail

VAULT_ADDR="https://localhost:8200"
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKENS_FILE="$LAB_DIR/lab-tokens.env"
VAULT_CMD="docker exec vault-target vault"

vault_cmd() { $VAULT_CMD "$@" -tls-skip-verify 2>/dev/null; }

vault_api() {
  local method="$1" path="$2" data="${3:-}"
  local url="$VAULT_ADDR/v1/$path"
  if [ -n "$data" ]; then
    curl -sk -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" -X "$method" "$url" -d "$data"
  else
    curl -sk -H "X-Vault-Token: $VAULT_TOKEN" -X "$method" "$url"
  fi
}

# ── wait for readiness ───────────────────────────────────────────────────
echo "[*] Waiting for Vault..."
for i in $(seq 1 30); do
  out=$($VAULT_CMD status -tls-skip-verify 2>&1) || true
  if echo "$out" | grep -q "Version"; then echo "[+] Vault ready (${i}s)"; break; fi
  sleep 1
done

echo "[*] Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if docker exec vault-db pg_isready -U vault_admin -d app &>/dev/null; then
    echo "[+] PostgreSQL ready (${i}s)"; break
  fi
  sleep 1
done

# ── 1. Init ───────────────────────────────────────────────────────────────
INIT_JSON=$($VAULT_CMD operator init -key-shares=1 -key-threshold=1 -format=json -tls-skip-verify 2>&1)
if echo "$INIT_JSON" | grep -q "already initialized"; then
  echo "[-] Vault already initialized. Run: docker compose down && rm -rf vault-data vault-logs && docker compose up -d"
  exit 0
fi

UNSEAL_KEY=$(echo "$INIT_JSON" | grep -o '"unseal_keys_b64":\["[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
VAULT_TOKEN=$(echo "$INIT_JSON" | grep -o '"root_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')

if [ -z "$VAULT_TOKEN" ]; then echo "[-] Init failed"; echo "$INIT_JSON"; exit 1; fi
echo "[1] Initialized. Token: ${VAULT_TOKEN:0:20}..."

# ── 2. Unseal ─────────────────────────────────────────────────────────────
$VAULT_CMD operator unseal -tls-skip-verify "$UNSEAL_KEY" &>/dev/null && echo "[2] Unsealed"

# ── 3. Login ──────────────────────────────────────────────────────────────
$VAULT_CMD login -no-print -tls-skip-verify "$VAULT_TOKEN" &>/dev/null && echo "[3] Logged in"

# ── 4. KV v2 ──────────────────────────────────────────────────────────────
vault_api POST "sys/mounts/secret" '{"type":"kv-v2"}' && echo "[4] KV v2: secret/"

# ── 5. Test secrets ───────────────────────────────────────────────────────
vault_api POST "secret/data/admin/creds" '{"data":{"username":"admin","password":"SuperSecretAdmin123!","role":"superadmin"}}' && echo "[5] secret/admin/creds"
vault_api POST "secret/data/api/keys" '{"data":{"stripe_key":"sk_live_abc123def456","github_token":"ghp_fake123token","jwt_secret":"eyJhbGciOiJIUzI1NiJ9.fake"}}' && echo "    secret/api/keys"
vault_api POST "secret/data/db/config" '{"data":{"host":"vault-db","port":5432,"db_name":"app","user":"vault_admin","pass":"vault-admin-password"}}' && echo "    secret/db/config"

# ── 6. Database secrets engine ────────────────────────────────────────────
vault_api POST "sys/mounts/database" '{"type":"database"}' && echo "[6] database/ enabled"
vault_api POST "database/config/postgres-prod" \
  '{"plugin_name":"postgresql-database-plugin","allowed_roles":"app-readonly,app-admin","connection_url":"postgresql://{{username}}:{{password}}@vault-db:5432/app?sslmode=disable","username":"vault_admin","password":"vault-admin-password"}' && echo "    postgres-prod configured"
vault_api POST "database/roles/app-readonly" \
  '{"db_name":"postgres-prod","creation_statements":"CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";","default_ttl":"1h","max_ttl":"24h"}' && echo "    role: app-readonly"
vault_api POST "database/roles/app-admin" \
  '{"db_name":"postgres-prod","creation_statements":"CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '"'"'{{password}}'"'"' VALID UNTIL '"'"'{{expiration}}'"'"'; GRANT ALL PRIVILEGES ON DATABASE app TO \"{{name}}\";","default_ttl":"2h","max_ttl":"48h"}' && echo "    role: app-admin (GRANT ALL — over-privileged)"

# ── 7. Transit ────────────────────────────────────────────────────────────
vault_api POST "sys/mounts/transit" '{"type":"transit"}' && echo "[7] transit/"
vault_api POST "transit/keys/my-key" '{"type":"aes256-gcm96"}' && echo "    key: my-key"

# ── 8. PKI ────────────────────────────────────────────────────────────────
vault_api POST "sys/mounts/pki" '{"type":"pki","config":{"max_lease_ttl":"87600h"}}' && echo "[8] pki/"
vault_api POST "pki/root/generate/internal" '{"common_name":"vault-lab-ca","ttl":"87600h"}' && echo "    root CA"
vault_api POST "pki/roles/localhost" '{"allowed_domains":"localhost","allow_subdomains":true,"max_ttl":"720h"}' && echo "    role: localhost"

# ── 9. Auth methods ───────────────────────────────────────────────────────
vault_api POST "sys/auth/approle" '{"type":"approle"}' && echo "[9] approle/ + userpass/"
vault_api POST "sys/auth/userpass" '{"type":"userpass"}'

# ── 10. AppRole ───────────────────────────────────────────────────────────
vault_api POST "auth/approle/role/my-role" \
  '{"token_policies":"app-admin","token_ttl":"1h","token_max_ttl":"4h","secret_id_num_uses":10,"secret_id_ttl":"2h"}' && echo "[10] AppRole: my-role"
ROLE_ID=$(vault_api GET "auth/approle/role/my-role/role-id" | grep -o '"role_id":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
SECRET_ID=$(vault_api POST "auth/approle/role/my-role/secret-id" '{}' | grep -o '"secret_id":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
echo "    role_id: $ROLE_ID"
echo "    secret_id: $SECRET_ID"

# ── 11. Userpass ──────────────────────────────────────────────────────────
vault_api POST "auth/userpass/users/testuser" '{"password":"testpassword","token_policies":"read-only"}' && echo "[11] User: testuser / testpassword"

# ── 12. Policies ──────────────────────────────────────────────────────────
echo "[12] Loading policies..."
for f in "$LAB_DIR"/vault-target/policies/*.hcl; do
  name=$(basename "$f" .hcl)
  $VAULT_CMD policy write -tls-skip-verify "$name" "/vault/policies/$(basename "$f")" &>/dev/null && echo "    $name"
done

# ── 13. Tokens ────────────────────────────────────────────────────────────
echo "[13] Creating tokens..."
LOW_PRIV=$(vault_api POST "auth/token/create" '{"policies":["read-only"],"ttl":"24h","display_name":"low-priv"}' | grep -o '"client_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
PRIV_ESC=$(vault_api POST "auth/token/create" '{"policies":["wildcard-sudo-user"],"ttl":"24h","display_name":"priv-esc"}' | grep -o '"client_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
APP_ADMIN=$(vault_api POST "auth/token/create" '{"policies":["app-admin"],"ttl":"24h","display_name":"app-admin"}' | grep -o '"client_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
DB_READER=$(vault_api POST "auth/token/create" '{"policies":["db-reader"],"ttl":"24h","display_name":"db-reader"}' | grep -o '"client_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
WEAK_TOKEN=$(vault_api POST "auth/token/create" '{"policies":["weak-policy"],"ttl":"24h","display_name":"weak"}' | grep -o '"client_token":"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
echo "    tokens created"

# ── 14. Audit + CORS ─────────────────────────────────────────────────────
$VAULT_CMD audit enable file file_path=/vault/logs/audit.log -tls-skip-verify &>/dev/null && echo "[14] Audit device + CORS"
vault_api POST "sys/config/cors" '{"allowed_origins":"*","allowed_headers":"X-Vault-Token,Content-Type,Authorization"}' && echo "    CORS: wildcard *"

# ── 15. Save tokens ──────────────────────────────────────────────────────
cat > "$TOKENS_FILE" <<EOF
# Vault Pentest Lab Tokens
VAULT_ADDR=$VAULT_ADDR
UNSEAL_KEY=$UNSEAL_KEY
ROOT_TOKEN=$VAULT_TOKEN
LOW_PRIV_TOKEN=$LOW_PRIV
PRIV_ESC_TOKEN=$PRIV_ESC
APP_ADMIN_TOKEN=$APP_ADMIN
DB_READER_TOKEN=$DB_READER
WEAK_TOKEN=$WEAK_TOKEN
APPROLE_ROLE_ID=$ROLE_ID
APPROLE_SECRET_ID=$SECRET_ID
EOF
echo "[15] Tokens saved: $TOKENS_FILE"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Lab Ready!"
echo "============================================"
echo "  Target:  $VAULT_ADDR"
echo "  Root:    ${VAULT_TOKEN:0:24}..."
echo "  Tokens:  source $TOKENS_FILE"
echo "============================================"
