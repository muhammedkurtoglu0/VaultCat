# modules/pivot/__init__.py
from active_execution.registry import ActiveExecutionRegistry


def register_all(registry: ActiveExecutionRegistry):
    """Register pivot-domain modules (cross-service pivot, payload delivery)."""
    from .pivot_engine import PivotEngineModule
    from .payload_module import PayloadModule

    registry.register(PivotEngineModule())
    registry.register(PayloadModule())
