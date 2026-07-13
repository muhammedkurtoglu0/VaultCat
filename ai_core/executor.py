from typing import Dict, List, Any, Optional
from active_execution.context import ExecutionContext
from active_execution.engine import ActiveExecutionEngine
from active_execution.registry import RiskLevel
import sys
import os

# main.py'yi import etmek için path ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Executor:
    def __init__(self, capabilities, memory):
        self.capabilities = capabilities
        self.memory = memory
        self._build_registry()
    
    def _build_registry(self):
        try:
            from main import build_active_execution_registry
            self.registry = build_active_execution_registry()
            self.engine = ActiveExecutionEngine(self.registry)
        except ImportError as e:
            print(f"[!] Registry oluşturulamadı: {e}")
            self.registry = None
            self.engine = None
    
    def execute_plan(self, plan: Dict, vault_addr: str = None, token: str = None) -> List[Dict]:
        if not self.engine:
            return [{"status": "error", "message": "Engine başlatılamadı"}]
        
        results = []
        
        context = ExecutionContext(
            vault_addr=vault_addr or plan.get("vault_addr"),
            token=token or plan.get("token")
        )
        
        if not context.vault_addr:
            return [{"status": "error", "message": "Vault adresi belirtilmedi"}]
        
        if not context.token:
            return [{"status": "error", "message": "Token belirtilmedi"}]
        
        for step in plan["steps"]:
            module_id = step["module"]
            params = step.get("params", {})
            risk = step.get("risk", "read_only")
            
            print(f"\n  ▶ {module_id} çalıştırılıyor...")
            print(f"  📝 {step.get('description', '')}")
            
            risk_map = {
                "read_only": RiskLevel.READ_ONLY,
                "state_changing": RiskLevel.STATE_CHANGING,
                "destructive": RiskLevel.DESTRUCTIVE
            }
            max_risk = risk_map.get(risk, RiskLevel.READ_ONLY)
            
            try:
                single_step = [{"module_id": module_id, "params": params}]
                
                execution_results = self.engine.execute_plan(
                    steps=single_step,
                    context=context,
                    max_risk=max_risk,
                    confirm_state_changing=True
                )
                
                for res in execution_results:
                    result = {
                        "module": module_id,
                        "status": res.status,
                        "message": res.message,
                        "evidence": res.evidence
                    }
                    results.append(result)
                    
                    self.memory.add_execution(module_id, res.status, res.evidence)
                    
                    if res.status == "success" and hasattr(context, "findings"):
                        for finding in context.findings:
                            if finding not in self.memory.findings:
                                self.memory.add_finding(finding)
                    
                    if res.status == "success" and res.evidence:
                        captured_token = res.evidence.get("captured_token") or res.evidence.get("token")
                        if captured_token:
                            self.memory.add_credential("captured_token", captured_token)
                        if "secret_id" in res.evidence:
                            self.memory.add_credential("secret_id", res.evidence["secret_id"])
                        if "role_id" in res.evidence:
                            self.memory.add_credential("role_id", res.evidence["role_id"])
                        if "username" in res.evidence:
                            self.memory.add_credential("db_username", res.evidence["username"])
                        if "password" in res.evidence:
                            self.memory.add_credential("db_password", res.evidence["password"])
                        if "access_key" in res.evidence:
                            self.memory.add_credential("aws_access_key", res.evidence["access_key"])
                
                if execution_results and execution_results[-1].status in ["error", "failed"]:
                    print(f"  ❌ {module_id} başarısız oldu, zincir durduruluyor.")
                    break
                    
            except Exception as e:
                results.append({
                    "module": module_id,
                    "status": "error",
                    "message": str(e),
                    "evidence": {}
                })
                print(f"  ❌ {module_id} hatası: {e}")
                break
        
        return results