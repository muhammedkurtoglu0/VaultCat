# modules/persistence/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register persistence-domain modules (backdoors, audit evasion)."""
    from .persistence import PersistenceModule
    from .multi_persistence import MultiPersistenceModule
    from .audit_backdoor import AuditBackdoorModule

    registry.register(PersistenceModule())
    registry.register(MultiPersistenceModule())
    registry.register(AuditBackdoorModule())
