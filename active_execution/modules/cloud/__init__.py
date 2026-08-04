# modules/cloud/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register cloud-domain modules (exploit, key exfiltration, pivot)."""
    from .aws_auth_login import AwsIamAuthLoginModule
    from .cloud_exploit import CloudExploitModule
    from .cloud_key_exfiltration import CloudKeyExfiltrationModule
    from .cloud_pivot import CloudPivotModule

    registry.register(AwsIamAuthLoginModule())
    registry.register(CloudExploitModule())
    registry.register(CloudKeyExfiltrationModule())
    registry.register(CloudPivotModule())
