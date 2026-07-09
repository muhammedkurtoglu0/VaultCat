from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    DESTRUCTIVE = "destructive"


@dataclass
class ExecutionResult:
    status: str
    message: str
    evidence: dict = field(default_factory=dict)


class BaseExecutionModule:
    def __init__(
        self,
        module_id: str,
        title: str,
        risk_level: RiskLevel,
        description: str,
        default_enabled: bool = False,
    ):
        self.module_id = module_id
        self.title = title
        self.risk_level = risk_level
        self.description = description
        self.default_enabled = default_enabled

    def can_run(self, context) -> bool:
        raise NotImplementedError

    def execute(self, context, params: Optional[dict] = None) -> ExecutionResult:
        raise NotImplementedError


class ActiveExecutionRegistry:
    def __init__(self):
        self._modules = {}

    def register(self, module: BaseExecutionModule):
        if not isinstance(module, BaseExecutionModule):
            raise TypeError("active execution modules must inherit BaseExecutionModule")
        if not module.module_id:
            raise ValueError("active execution module_id cannot be empty")
        if module.module_id in self._modules:
            raise ValueError(f"duplicate active execution module_id: {module.module_id}")
        self._modules[module.module_id] = module
        return module

    def get(self, module_id: str):
        return self._modules.get(module_id)

    def list_modules(self):
        return list(self._modules.values())

    def module_ids(self):
        return list(self._modules.keys())


RISK_LEVEL_ORDER = {
    RiskLevel.READ_ONLY: 0,
    RiskLevel.STATE_CHANGING: 1,
    RiskLevel.DESTRUCTIVE: 2,
}


def risk_level_allowed(module_risk: RiskLevel, max_risk: RiskLevel) -> bool:
    return RISK_LEVEL_ORDER[module_risk] <= RISK_LEVEL_ORDER[max_risk]
