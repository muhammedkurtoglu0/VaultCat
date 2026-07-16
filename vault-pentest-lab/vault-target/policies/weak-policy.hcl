# Weak policy — intentionally vulnerable token creation privilege
# This is the privilege escalation path the tool is designed to detect

path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
