"""Regex-based intent-to-module planner — DEPRECATED.

This module is superseded by ``ai_core.planning`` which uses LLM-powered
structured planning.  The regex approach is kept for reference only.
New code should use:

    from ai_core.planning import create_planner
"""

import warnings
from typing import List, Dict, Any, Optional
import re

warnings.warn(
    "ai_core.planner is deprecated — use ai_core.planning.create_planner instead",
    DeprecationWarning,
    stacklevel=2,
)


class Planner:
    def __init__(self, capabilities, memory):
        self.capabilities = capabilities
        self.memory = memory
        self._intent_patterns = self._build_intent_patterns()
    
    def _build_intent_patterns(self) -> Dict:
        """Doğal dil kalıplarını yeteneklere eşleştir"""
        return {
            "token_yukselt": {
                "patterns": [
                    r"token.*yükselt", r"token.*oluştur", r"root.*token",
                    r"yetki.*yükselt", r"admin.*token", r"new.*token",
                    r"privilege.*escalation", r"token.*al", r"token.*create",
                    r"yeni.*token", r"yetki.*arttır"
                ],
                "module": "privilege_escalation.token_abuse",
                "risk": "state_changing"
            },
            "secret_oku": {
                "patterns": [
                    r"secret.*oku", r"gizli.*bul", r"vault.*oku",
                    r"secret.*exfil", r"tüm.*secret", r"kv.*oku",
                    r"transit.*key", r"pki.*cert", r"ssh.*role",
                    r"sırr.*bul", r"veri.*oku"
                ],
                "module": "secret_exfiltration.kv_dump",
                "risk": "read_only"
            },
            "database_harvest": {
                "patterns": [
                    r"database.*credential", r"veritabanı.*topla",
                    r"db.*credential", r"database.*harvest",
                    r"db.*user", r"db.*password", r"veritabanı.*şifre"
                ],
                "module": "database_credential_harvest.dynamic_creds",
                "risk": "state_changing"
            },
            "cloud_harvest": {
                "patterns": [
                    r"aws.*credential", r"azure.*credential", r"gcp.*credential",
                    r"cloud.*key", r"iam.*credential", r"access.*key",
                    r"aws.*anahtar", r"azure.*anahtar"
                ],
                "module": "cloud_key_exfiltration.iam_creds",
                "risk": "state_changing"
            },
            "token_exploit": {
                "patterns": [
                    r"özel.*token", r"custom.*token", r"belirli.*politika",
                    r"policy.*token", r"token.*policy", r"özel.*yetki"
                ],
                "module": "token_exploit.creation",
                "risk": "state_changing"
            },
            "policy_exploit": {
                "patterns": [
                    r"politika.*yükselt", r"policy.*update", r"rule.*add",
                    r"yetki.*ekle", r"capability.*add", r"politika.*değiştir"
                ],
                "module": "policy_exploit.modification",
                "risk": "state_changing"
            },
            "database_pivot": {
                "patterns": [
                    r"veritabanı.*bağlan", r"db.*pivot",
                    r"postgres.*bağlan", r"mysql.*bağlan",
                    r"database.*connect", r"db.*veri.*çek",
                    r"mssql.*bağlan", r"sql.*bağlan"
                ],
                "module": "database_pivot.exploit",
                "risk": "destructive"
            },
            "cloud_pivot": {
                "patterns": [
                    r"aws.*bağlan", r"azure.*bağlan", r"gcp.*bağlan",
                    r"cloud.*pivot", r"ec2.*listele", r"instance.*listele",
                    r"aws.*kaynak", r"cloud.*kaynak"
                ],
                "module": "cloud_pivot.exploit",
                "risk": "destructive"
            },
            "persistence": {
                "patterns": [
                    r"backdoor", r"kalıcı.*erişim", r"persistence",
                    r"approle.*oluştur", r"auth.*method", r"backdoor.*kur",
                    r"kalıcı.*yetki", r"geri.*dön"
                ],
                "module": "persistence.backdoor",
                "risk": "destructive"
            },
            "full_auto": {
                "patterns": [
                    r"hackle", r"exploit", r"saldır", r"penetrate",
                    r"full.*attack", r"complete.*exploit", r"tam.*saldırı",
                    r"her.*şeyi.*yap", r"hepsini.*yap", r"vaultu.*hackle",
                    r"vault'u.*hackle", r"tüm.*işlemler"
                ],
                "module": None,
                "risk": "destructive"
            }
        }
    
    def create_plan(self, message: str, vault_addr: str = None, token: str = None) -> Optional[Dict]:
        """Kullanıcı mesajından plan oluştur"""
        message_lower = message.lower()
        
        # Intent tespit et
        intents = self._detect_intents(message_lower)
        
        if not intents:
            return None
        
        # Plan oluştur
        steps = []
        requires_confirmation = False
        
        for intent in intents:
            if intent == "full_auto":
                steps = self._build_full_attack_plan()
                requires_confirmation = True
                break
            
            intent_info = self._intent_patterns.get(intent)
            if intent_info:
                module_id = intent_info["module"]
                if module_id:
                    # Modülün var olduğunu kontrol et
                    cap = self.capabilities.get(module_id)
                    description = cap["description"] if cap else intent_info.get("description", module_id)
                    
                    steps.append({
                        "module": module_id,
                        "description": description,
                        "risk": intent_info["risk"],
                        "params": self._get_params_for_module(module_id, message)
                    })
                    if intent_info["risk"] in ["state_changing", "destructive"]:
                        requires_confirmation = True
        
        if not steps:
            return None
        
        # HEDEF: Vault adresi ve token'ı plana ekle
        if vault_addr:
            self.memory.set_context("vault_addr", vault_addr)
        if token:
            self.memory.set_context("token", token)
        
        return {
            "original_message": message,
            "steps": steps,
            "requires_confirmation": requires_confirmation,
            "vault_addr": vault_addr or self.memory.get_context("vault_addr"),
            "token": token or self.memory.get_context("token")
        }
    
    def _detect_intents(self, message: str) -> List[str]:
        """Mesajdaki niyetleri bul"""
        detected = []
        for intent, info in self._intent_patterns.items():
            for pattern in info["patterns"]:
                if re.search(pattern, message, re.IGNORECASE):
                    if intent not in detected:
                        detected.append(intent)
                    break
        return detected
    
    def _build_full_attack_plan(self) -> List[Dict]:
        """Tam saldırı zinciri oluştur"""
        return [
            {
                "module": "privilege_escalation.token_abuse",
                "description": "Token yükselt - root/admin token al",
                "risk": "state_changing",
                "params": {}
            },
            {
                "module": "secret_exfiltration.kv_dump",
                "description": "Tüm secret'ları oku",
                "risk": "read_only",
                "params": {"max_depth": 5}
            },
            {
                "module": "database_credential_harvest.dynamic_creds",
                "description": "Database credential'ları topla",
                "risk": "state_changing",
                "params": {}
            },
            {
                "module": "database_pivot.exploit",
                "description": "Veritabanına bağlan ve veri çek",
                "risk": "destructive",
                "params": {"max_tables": 3, "max_rows": 5}
            },
            {
                "module": "persistence.backdoor",
                "description": "Kalıcı backdoor kur",
                "risk": "destructive",
                "params": {"auth_path": "approle-backdoor", "role_name": "backdoor"}
            }
        ]
    
    def _get_params_for_module(self, module_id: str, message: str) -> Dict:
        """Modül için parametreleri çıkar"""
        params = {}
        message_lower = message.lower()
        
        # TTL algıla
        ttl_match = re.search(r"(\d+)(m|h|d)", message_lower)
        if ttl_match:
            params["ttl"] = ttl_match.group(0)
        
        # Policy algıla
        if "root" in message_lower:
            params["policies"] = ["root"]
        elif "admin" in message_lower:
            params["policies"] = ["admin"]
        elif "custom" in message_lower:
            policy_match = re.search(r"policy[\s:]+(\w+)", message_lower)
            if policy_match:
                params["policies"] = [policy_match.group(1)]
        
        # Provider algıla
        if "aws" in message_lower:
            params["provider"] = "aws"
        elif "azure" in message_lower:
            params["provider"] = "azure"
        elif "gcp" in message_lower:
            params["provider"] = "gcp"
        
        # Region algıla
        region_match = re.search(r"region[\s:]+([\w-]+)", message_lower)
        if region_match:
            params["region"] = region_match.group(1)
        
        # Database tipi algıla
        if "postgres" in message_lower or "postgre" in message_lower:
            params["db_type"] = "postgres"
        elif "mysql" in message_lower:
            params["db_type"] = "mysql"
        elif "mssql" in message_lower or "sql server" in message_lower:
            params["db_type"] = "mssql"
        
        # Auth path algıla
        auth_match = re.search(r"auth[\s:]+([\w-]+)", message_lower)
        if auth_match:
            params["auth_path"] = auth_match.group(1)
        
        # Role name algıla
        role_match = re.search(r"role[\s:]+([\w-]+)", message_lower)
        if role_match:
            params["role_name"] = role_match.group(1)
        
        return params