# modules/token/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register token-domain modules (token, policy, privilege escalation, auth methods)."""
    from .token_exploit import TokenExploitModule
    from .policy_exploit import PolicyExploitModule
    from .privilege_escalation import PrivilegeEscalationModule
    from .kubernetes_auth_exploit import KubernetesAuthExploitModule
    from .approle_exploit import AppRoleExploitModule
    from .jwt_oidc_exploit import JWTOIDCExploitModule

    registry.register(TokenExploitModule())
    registry.register(PolicyExploitModule())
    registry.register(PrivilegeEscalationModule())
    registry.register(KubernetesAuthExploitModule())
    registry.register(AppRoleExploitModule())
    registry.register(JWTOIDCExploitModule())
