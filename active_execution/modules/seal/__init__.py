# modules/seal/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register seal-domain modules (seal/unseal, unseal key exfiltration)."""
    from .unseal_key_exfiltration import UnsealKeyExfiltrationModule
    from .vault_seal_manipulation import (
        SealStatusModule,
        SealVaultModule,
        UnsealVaultModule,
    )

    registry.register(UnsealKeyExfiltrationModule())
    registry.register(SealStatusModule())
    registry.register(SealVaultModule())
    registry.register(UnsealVaultModule())
