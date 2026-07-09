path "secret/data/app/*" {
  capabilities = ["read"]
}

path "secret/metadata/app/*" {
  capabilities = ["list", "read"]
}

path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
