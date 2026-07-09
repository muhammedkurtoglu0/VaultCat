path "secret/data/*" {
  capabilities = ["read"]
}

path "secret/metadata/*" {
  capabilities = ["list", "read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
