# modules/secrets/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register secrets-domain modules (Transit, PKI, Raft, KV exfiltration)."""
    from .transit_engine_exploit import TransitEngineExploitModule
    from .pki_engine_exploit import PKIEngineExploitModule
    from .raft_storage_exploit import RaftStorageExploitModule
    from .secret_exfiltration import SecretExfiltrationModule

    registry.register(TransitEngineExploitModule())
    registry.register(PKIEngineExploitModule())
    registry.register(RaftStorageExploitModule())
    registry.register(SecretExfiltrationModule())
