path "database/creds/app-readonly" {
  capabilities = ["read"]
}

vault write database/config/postgres-prod \
  plugin_name=postgresql-database-plugin \
  allowed_roles="app-readonly" \
  connection_url="postgresql://{{username}}:{{password}}@db.internal:5432/app" \
  username="vault_admin" \
  password="static-db-admin-pass-123"

vault write database/roles/app-readonly \
  db_name=postgres-prod \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
