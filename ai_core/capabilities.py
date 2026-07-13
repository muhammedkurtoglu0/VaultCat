from typing import Dict, List, Optional


class CapabilityRegistry:
    def __init__(self):
        self._capabilities: Dict[str, Dict] = {}
    
    def register(self, module_id: str, title: str, description: str, 
                 risk_level: str, default_enabled: bool, parameters: Dict):
        self._capabilities[module_id] = {
            "module_id": module_id,
            "title": title,
            "description": description,
            "risk_level": risk_level,
            "default_enabled": default_enabled,
            "parameters": parameters
        }
    
    def get(self, module_id: str) -> Optional[Dict]:
        return self._capabilities.get(module_id)
    
    def get_description(self, module_id: str) -> str:
        cap = self.get(module_id)
        return cap["description"] if cap else "Bilinmeyen modül"
    
    def list_all(self) -> List[Dict]:
        return list(self._capabilities.values())
    
    def list_by_risk(self, max_risk: str) -> List[Dict]:
        risk_order = {"read_only": 0, "state_changing": 1, "destructive": 2}
        max_level = risk_order.get(max_risk, 2)
        return [
            cap for cap in self._capabilities.values()
            if risk_order.get(cap["risk_level"], 2) <= max_level
        ]
    
    def get_module_ids(self) -> List[str]:
        return list(self._capabilities.keys())