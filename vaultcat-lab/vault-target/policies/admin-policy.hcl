# Admin policy — full root-equivalent access
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
