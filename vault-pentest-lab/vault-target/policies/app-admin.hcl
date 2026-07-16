# App admin policy — KV read/write on secret/ but nothing else
path "secret/data/*" {
  capabilities = ["read", "list", "create", "update"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
