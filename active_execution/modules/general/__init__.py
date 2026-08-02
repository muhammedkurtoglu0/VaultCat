# modules/general/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register general-domain modules."""
    from .agent_sidecar_attack import AgentSidecarAttackModule
    from .cve_scanner import CVEScannerModule
    from .unauthenticated_attack import UnauthenticatedAttackModule
    from .dos_exploit import DoSExploitModule

    registry.register(AgentSidecarAttackModule())
    registry.register(CVEScannerModule())
    registry.register(UnauthenticatedAttackModule())
    registry.register(DoSExploitModule())
