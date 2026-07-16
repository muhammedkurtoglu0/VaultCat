ui = true

listener "tcp" {
  address        = "0.0.0.0:8200"
  tls_cert_file  = "/vault/config/cert.pem"
  tls_key_file   = "/vault/config/key.pem"
}

storage "file" {
  path = "/vault/data"
}

disable_mlock = true
