# Security Policy

This project is intended only for authorized security testing and internal risk assessment.

Do not use it against systems without explicit written permission. The default workflows are designed to be read-only. Validation options may contact a Vault target and must only be used in approved environments.

## Supported Use

- Authorized Vault reconnaissance
- Repository, artifact, configuration, and log review
- Credential exposure assessment
- Optional metadata-only validation with approved Vault tokens

## Out of Scope

- Brute force
- Secret read/write/delete operations
- Destructive exploitation
- Unauthorized access attempts

## Reporting Issues

If you find a bug that could expose secrets, bypass masking, or perform unintended writes, treat it as sensitive and report it privately to the project owner.
