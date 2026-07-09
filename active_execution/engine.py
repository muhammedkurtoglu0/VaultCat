from .registry import ExecutionResult, RiskLevel, risk_level_allowed


class ActiveExecutionEngine:
    def __init__(self, registry):
        self.registry = registry

    def execute_plan(self, steps, context, max_risk=RiskLevel.READ_ONLY, confirm_state_changing=False):
        if isinstance(max_risk, str):
            max_risk = RiskLevel(max_risk)

        results = []
        for step in steps:
            module_id = step.get("module_id")
            module = self.registry.get(module_id)
            if not module:
                results.append(ExecutionResult(
                    status="error",
                    message=f"Active module not found: {module_id}",
                    evidence={"module_id": module_id},
                ))
                continue

            if not risk_level_allowed(module.risk_level, max_risk):
                results.append(ExecutionResult(
                    status="blocked",
                    message=(
                        f"Active module risk '{module.risk_level.value}' exceeds "
                        f"allowed max_risk '{max_risk.value}'."
                    ),
                    evidence={
                        "module_id": module_id,
                        "module_risk": module.risk_level.value,
                        "max_risk": max_risk.value,
                    },
                ))
                continue

            if module.risk_level != RiskLevel.READ_ONLY and not confirm_state_changing:
                results.append(ExecutionResult(
                    status="blocked",
                    message=(
                        f"Active module requires explicit confirmation: {module_id}"
                    ),
                    evidence={
                        "module_id": module_id,
                        "module_risk": module.risk_level.value,
                        "required_confirmation": "confirm_state_changing",
                    },
                ))
                continue

            if not module.can_run(context):
                results.append(ExecutionResult(
                    status="skipped",
                    message=f"Active module cannot run with current context: {module_id}",
                    evidence={"module_id": module_id},
                ))
                continue

            print(f"[*] Running active module: {module_id}")
            try:
                result = module.execute(context, step.get("params") or step.get("parameters") or {})
            except Exception as error:
                result = ExecutionResult(
                    status="error",
                    message=f"Active module execution failed: {error}",
                    evidence={"module_id": module_id, "error": str(error)},
                )
            results.append(result)
            print(f"    -> {result.status}: {result.message}")
            if result.evidence:
                print(f"    Evidence: {result.evidence}")
        return results
