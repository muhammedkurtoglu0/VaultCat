# modules/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register all active execution modules."""
    from .audit_backdoor import AuditBackdoorModule
    from .cloud_exploit import CloudExploitModule
    from .cloud_key_exfiltration import CloudKeyExfiltrationModule
    from .cloud_pivot import CloudPivotModule
    from .cve_scanner import CVEScannerModule
    from .database_credential_harvest import DatabaseCredentialHarvestModule
    from .database_exploit import DatabaseExploitModule
    from .database_pivot import DatabasePivotModule
    from .multi_persistence import MultiPersistenceModule
    from .payload_module import PayloadModule
    from .persistence import PersistenceModule
    from .policy_exploit import PolicyExploitModule
    from .privilege_escalation import PrivilegeEscalationModule
    from .raft_storage_exploit import RaftStorageExploitModule
    from .secret_exfiltration import SecretExfiltrationModule
    from .token_exploit import TokenExploitModule
    from .unauthenticated_attack import UnauthenticatedAttackModule
    from .unseal_key_exfiltration import UnsealKeyExfiltrationModule

    registry.register(PrivilegeEscalationModule())
    registry.register(SecretExfiltrationModule())
    registry.register(DatabaseCredentialHarvestModule())
    registry.register(CloudKeyExfiltrationModule())
    registry.register(TokenExploitModule())
    registry.register(PolicyExploitModule())
    registry.register(AuditBackdoorModule())
    registry.register(CVEScannerModule())
    registry.register(DatabasePivotModule())
    registry.register(CloudPivotModule())
    registry.register(PersistenceModule())
    registry.register(RaftStorageExploitModule())
    registry.register(UnsealKeyExfiltrationModule())
    registry.register(DatabaseExploitModule())
    registry.register(CloudExploitModule())
    registry.register(MultiPersistenceModule())
    registry.register(PayloadModule())
    registry.register(UnauthenticatedAttackModule())


def get_default_registry() -> ActiveExecutionRegistry:
    """Build and return the default active execution registry."""
    registry = ActiveExecutionRegistry()
    register_all(registry)
    return registry
