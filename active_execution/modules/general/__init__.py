# modules/general/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register general-domain modules (agent sidecar, CVE scanner, unauthenticated attack)."""
    from .agent_sidecar_attack import AgentSidecarAttackModule
    from .cve_scanner import CVEScannerModule
    from .unauthenticated_attack import UnauthenticatedAttackModule

    registry.register(AgentSidecarAttackModule())
    registry.register(CVEScannerModule())
    registry.register(UnauthenticatedAttackModule())
