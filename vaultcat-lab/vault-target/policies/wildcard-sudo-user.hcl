# Intentionally vulnerable policy for privilege escalation testing
# Grants sudo on sys/* — the tool should detect this as CRITICAL risk

path "sys/*" {
  capabilities = ["update", "sudo"]
}

path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "auth/token/create" {
  capabilities = ["create", "update"]
}
