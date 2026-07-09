$ErrorActionPreference = "Stop"

$container = "vault-lab"
$repoRoot = Split-Path -Parent $PSScriptRoot
$policies = Join-Path $PSScriptRoot "policies"

$running = docker ps --filter "name=$container" --format "{{.Names}}"
if (-not ($running -contains $container)) {
    docker rm -f $container 2>$null | Out-Null
    docker run --rm -d `
        --name $container `
        -p 8200:8200 `
        -e VAULT_DEV_ROOT_TOKEN_ID=root `
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 `
        hashicorp/vault:1.13.3 | Out-Null
    Start-Sleep -Seconds 3
}

docker cp (Join-Path $policies "admin-policy.hcl") "${container}:/tmp/admin-policy.hcl"
docker cp (Join-Path $policies "weak-policy.hcl") "${container}:/tmp/weak-policy.hcl"

$setup = "set -eu; export VAULT_ADDR=http://127.0.0.1:8200; export VAULT_TOKEN=root; vault kv put secret/app/db username=admin password=SuperSecret123 api_key=lab-api-key >/dev/null; vault kv put secret/app/config vault_addr=http://localhost:8200 env=lab feature_flag=true >/dev/null; vault policy write admin-policy /tmp/admin-policy.hcl >/dev/null; vault policy write weak-policy /tmp/weak-policy.hcl >/dev/null; vault token create -format=json -policy=weak-policy -ttl=1h"

$result = docker exec $container sh -c $setup
$result
