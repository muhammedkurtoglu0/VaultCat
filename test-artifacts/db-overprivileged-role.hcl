vault write database/roles/app-admin \
  db_name=postgres-prod \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ALL PRIVILEGES ON DATABASE app TO \"{{name}}\"; ALTER ROLE \"{{name}}\" CREATEDB;" \
  default_ttl="8h" \
  max_ttl="72h"
