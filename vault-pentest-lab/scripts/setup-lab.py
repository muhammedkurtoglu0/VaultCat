#!/usr/bin/env python3
"""Vault Pentest Lab — Setup via HTTP API (bypasses CLI auto-seal issues)."""
import json, os, subprocess, sys, time
import urllib3, requests

urllib3.disable_warnings()

VAULT_ADDR = "https://localhost:8200"
LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKENS_FILE = os.path.join(LAB_DIR, "lab-tokens.env")
os.chdir(LAB_DIR)

VAULT_TOKEN = None


def api(method, path, data=None, token=None):
    """HTTP API call to Vault. Returns (status_code, response_dict)."""
    url = f"{VAULT_ADDR}/v1/{path}"
    h = {}
    t = token or VAULT_TOKEN
    if t:
        h["X-Vault-Token"] = t
    kw = {"verify": False, "timeout": 10}
    if data is not None:
        h["Content-Type"] = "application/json"
        r = requests.request(method, url, headers=h, json=data, **kw)
    else:
        r = requests.request(method, url, headers=h, **kw)
    try:
        body = r.json() if r.text.strip() else {}
    except Exception:
        body = {"_raw": r.text}
    return r.status_code, body


def vault_cmd(*args):
    r = subprocess.run(
        ["docker", "exec", "vault-target", "vault"] + list(args) + ["-tls-skip-verify"],
        capture_output=True, text=True
    )
    return r.stdout + r.stderr


def wait_vault():
    print("[*] Waiting for Vault...")
    for i in range(30):
        out = vault_cmd("status")
        if "Version" in out:
            print(f"[+] Vault ready ({i+1}s)"); return
        time.sleep(1)
    sys.exit("[-] Vault did not start")


def wait_db():
    print("[*] Waiting for PostgreSQL...")
    for i in range(30):
        r = subprocess.run(["docker", "exec", "vault-db", "pg_isready", "-U", "vault_admin", "-d", "app"],
                          capture_output=True)
        if r.returncode == 0:
            print(f"[+] PostgreSQL ready ({i+1}s)"); return
        time.sleep(1)
    sys.exit("[-] PostgreSQL did not start")


# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 50)
print("  Vault Pentest Lab Setup (HTTP API)")
print("=" * 50)

wait_vault()
wait_db()

# ── 1. Init via HTTP API ─────────────────────────────────────────────────────
print("[1] Initializing via HTTP API...")
code, resp = api("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token=None)
if code == 400 and "already initialized" in str(resp):
    sys.exit("[-] Already initialized. Nuke first!")
if code != 200:
    sys.exit(f"[-] Init failed: {code} {resp}")

UNSEAL_KEY = resp["keys_b64"][0] if "keys_b64" in resp else resp["keys"][0]
VAULT_TOKEN = resp["root_token"]
print(f"    Token: {VAULT_TOKEN[:24]}...")

# ── 2. Unseal via HTTP API ───────────────────────────────────────────────────
# (Init with 1/1 threshold auto-unseals, but let's verify and retry)
for attempt in range(20):
    code, status_resp = api("GET", "sys/seal-status", token=None)
    if code == 200 and not status_resp.get("sealed", True):
        print(f"[2] Unsealed (verified after {attempt+1}s)")
        break
    # Try unsealing
    code, _ = api("PUT", "sys/unseal", {"key": UNSEAL_KEY}, token=None)
    time.sleep(1)
else:
    sys.exit("[-] Could not unseal after 20 attempts")

# ── 3. Login token verified ──────────────────────────────────────────────────
code, lookup = api("GET", "auth/token/lookup-self")
if code != 200:
    sys.exit(f"[-] Root token invalid: {code} {lookup}")
print(f"[3] Root token verified (policies: {lookup['data'].get('policies', [])})")

# ── Helper ────────────────────────────────────────────────────────────────────
def ok(path, data=None):
    code, resp = api("POST", path, data)
    if code not in (200, 201, 204):
        print(f"    [!] {path} -> {code} {json.dumps(resp)[:100]}")
        return None
    return resp

def get(path):
    code, resp = api("GET", path)
    return resp if code == 200 else None

def create_token(policies, name):
    code, resp = api("POST", "auth/token/create", {"policies": policies, "ttl": "24h", "display_name": name})
    return resp["auth"]["client_token"]

POLICIES_DIR = os.path.join(LAB_DIR, "vault-target", "policies")
st = 4

# ── KV v2 ────────────────────────────────────────────────────────────────────
ok("sys/mounts/secret", {"type": "kv-v2"})
ok("secret/data/admin/creds", {"data": {"username": "admin", "password": "SuperSecretAdmin123!", "role": "superadmin"}})
ok("secret/data/api/keys", {"data": {"stripe_key": "sk_live_abc123", "github_token": "ghp_fake123", "jwt_secret": "eyJhbGciOiJIUzI1NiJ9.fake"}})
ok("secret/data/db/config", {"data": {"host": "vault-db", "port": 5432, "db_name": "app", "user": "vault_admin", "pass": "vault-admin-password"}})
print(f"[{st}] KV v2 + test secrets"); st += 1

# ── Database ──────────────────────────────────────────────────────────────────
ok("sys/mounts/database", {"type": "database"})
ok("database/config/postgres-prod", {
    "plugin_name": "postgresql-database-plugin", "allowed_roles": "app-readonly,app-admin",
    "connection_url": "postgresql://{{username}}:{{password}}@vault-db:5432/app?sslmode=disable",
    "username": "vault_admin", "password": "vault-admin-password"
})
ok("database/roles/app-readonly", {
    "db_name": "postgres-prod",
    "creation_statements": 'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";',
    "default_ttl": "1h", "max_ttl": "24h"
})
ok("database/roles/app-admin", {
    "db_name": "postgres-prod",
    "creation_statements": 'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\'; GRANT ALL PRIVILEGES ON DATABASE app TO "{{name}}";',
    "default_ttl": "2h", "max_ttl": "48h"
})
print(f"[{st}] database/ (app-readonly, app-admin)"); st += 1

# ── Transit ───────────────────────────────────────────────────────────────────
ok("sys/mounts/transit", {"type": "transit"})
ok("transit/keys/my-key", {"type": "aes256-gcm96"})
print(f"[{st}] transit/ (my-key)"); st += 1

# ── PKI ───────────────────────────────────────────────────────────────────────
ok("sys/mounts/pki", {"type": "pki", "config": {"max_lease_ttl": "87600h"}})
ok("pki/root/generate/internal", {"common_name": "vault-lab-ca", "ttl": "87600h"})
ok("pki/roles/localhost", {"allowed_domains": "localhost", "allow_subdomains": True, "max_ttl": "720h"})
print(f"[{st}] pki/ (localhost)"); st += 1

# ── Auth ──────────────────────────────────────────────────────────────────────
ok("sys/auth/approle", {"type": "approle"})
ok("sys/auth/userpass", {"type": "userpass"})
ok("auth/approle/role/my-role", {
    "token_policies": "app-admin", "token_ttl": "1h", "token_max_ttl": "4h",
    "secret_id_num_uses": 10, "secret_id_ttl": "2h"
})
ROLE_ID = get("auth/approle/role/my-role/role-id")["data"]["role_id"]
SECRET_ID = ok("auth/approle/role/my-role/secret-id")["data"]["secret_id"]
ok("auth/userpass/users/testuser", {"password": "testpassword", "token_policies": "read-only"})
print(f"[{st}] Auth: approle(my-role) + userpass(testuser)"); st += 1

# ── Policies ──────────────────────────────────────────────────────────────────
for fname in sorted(os.listdir(POLICIES_DIR)):
    if fname.endswith(".hcl"):
        vault_cmd("policy", "write", fname[:-4], f"/vault/policies/{fname}")
print(f"[{st}] 6 policies loaded"); st += 1

# ── Tokens ────────────────────────────────────────────────────────────────────
LOW_PRIV = create_token(["read-only"], "low-priv")
PRIV_ESC = create_token(["wildcard-sudo-user"], "priv-esc")
APP_ADMIN = create_token(["app-admin"], "app-admin")
DB_READER = create_token(["db-reader"], "db-reader")
WEAK_TOKEN = create_token(["weak-policy"], "weak")
print(f"[{st}] 5 test tokens created"); st += 1

# ── Audit + CORS ──────────────────────────────────────────────────────────────
vault_cmd("audit", "enable", "file", "file_path=/vault/logs/audit.log")
ok("sys/config/cors", {"allowed_origins": "*", "allowed_headers": "X-Vault-Token,Content-Type,Authorization"})
print(f"[{st}] Audit device + CORS wildcard *"); st += 1

# ── Save ──────────────────────────────────────────────────────────────────────
with open(TOKENS_FILE, "w", encoding="utf-8") as f:
    f.write(f"""# Vault Pentest Lab Tokens
VAULT_ADDR={VAULT_ADDR}
UNSEAL_KEY={UNSEAL_KEY}
ROOT_TOKEN={VAULT_TOKEN}
LOW_PRIV_TOKEN={LOW_PRIV}
PRIV_ESC_TOKEN={PRIV_ESC}
APP_ADMIN_TOKEN={APP_ADMIN}
DB_READER_TOKEN={DB_READER}
WEAK_TOKEN={WEAK_TOKEN}
APPROLE_ROLE_ID={ROLE_ID}
APPROLE_SECRET_ID={SECRET_ID}
""")
print(f"[{st}] Saved: {TOKENS_FILE}")

print()
print("=" * 50)
print("  LAB READY!")
print(f"  Target: {VAULT_ADDR}")
print(f"  Root:   {VAULT_TOKEN[:24]}...")
print(f"  source {TOKENS_FILE}")
print("=" * 50)
