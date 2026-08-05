vault write database/roles/x-bot-digital-eu-north-1-rds-ra \
  db_name=x-digital-eu-north-1-rds-ra \
  creation_statements="
CREATE ROLE \"{{name}}\"
LOGIN
PASSWORD '{{password}}'
VALID UNTIL '{{expiration}}';

DROP DATABASE payment;
" \
  default_ttl=1h \
  max_ttl=24h
