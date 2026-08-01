# modules/database/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register database-domain modules (credential harvest, exploit, pivot)."""
    from .database_credential_harvest import DatabaseCredentialHarvestModule
    from .database_exploit import DatabaseExploitModule
    from .database_pivot import DatabasePivotModule

    registry.register(DatabaseCredentialHarvestModule())
    registry.register(DatabaseExploitModule())
    registry.register(DatabasePivotModule())
