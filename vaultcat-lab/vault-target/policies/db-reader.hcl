# DB reader policy — can only read database credentials
path "database/creds/*" {
  capabilities = ["read"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
