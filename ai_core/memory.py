from typing import Dict, List, Any
from datetime import datetime


class Memory:
    def __init__(self):
        self.conversation_history: List[Dict] = []
        self.findings: List[Dict] = []
        self.captured_credentials: Dict[str, Any] = {}
        self.context: Dict[str, Any] = {}
        self.execution_history: List[Dict] = []
        self.active_plan: Any = None  # PentestPlan | None
        self.plan_history: List[Any] = []  # completed/aborted plans
    
    def add_conversation(self, role: str, message: str):
        self.conversation_history.append({
            "role": role,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
    
    def add_finding(self, finding: Dict):
        self.findings.append(finding)
    
    def add_credential(self, name: str, value: Any):
        self.captured_credentials[name] = value
    
    def get_credential(self, name: str) -> Any:
        return self.captured_credentials.get(name)
    
    def get_context(self, key: str) -> Any:
        return self.context.get(key)
    
    def set_context(self, key: str, value: Any):
        self.context[key] = value
    
    def add_execution(self, module: str, status: str, evidence: Dict):
        self.execution_history.append({
            "module": module,
            "status": status,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_last_execution(self) -> Dict:
        return self.execution_history[-1] if self.execution_history else {}
    
    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        return [f for f in self.findings if f.get("severity") == severity]

    def store_plan(self, plan) -> None:
        """Store a plan as the active plan."""
        self.active_plan = plan

    def get_active_plan(self):
        """Return the currently active plan or None."""
        return self.active_plan

    def archive_plan(self, plan) -> None:
        """Move the active plan to the history archive."""
        if self.active_plan is plan:
            self.active_plan = None
        self.plan_history.append(plan)