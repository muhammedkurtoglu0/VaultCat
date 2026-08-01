# modules/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register all active execution modules from domain subpackages."""
    from .secrets import register_all as reg_secrets
    from .token import register_all as reg_token
    from .database import register_all as reg_database
    from .cloud import register_all as reg_cloud
    from .persistence import register_all as reg_persistence
    from .seal import register_all as reg_seal
    from .pivot import register_all as reg_pivot
    from .general import register_all as reg_general

    reg_secrets(registry)
    reg_token(registry)
    reg_database(registry)
    reg_cloud(registry)
    reg_persistence(registry)
    reg_seal(registry)
    reg_pivot(registry)
    reg_general(registry)


def get_default_registry() -> ActiveExecutionRegistry:
    """Build and return the default active execution registry."""
    registry = ActiveExecutionRegistry()
    register_all(registry)
    return registry
