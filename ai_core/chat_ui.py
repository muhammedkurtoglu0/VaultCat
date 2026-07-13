import json
import sys
from typing import Optional

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

from .planner import Planner
from .executor import Executor
from .capabilities import CapabilityRegistry
from .memory import Memory
from .llm_engine import LLMEngine


class ChatUI:
    def __init__(self, vault_addr: str = None, token: str = None):
        self.vault_addr = vault_addr
        self.token = token
        self.memory = Memory()
        self.capabilities = CapabilityRegistry()
        self.planner = Planner(self.capabilities, self.memory)
        self.executor = Executor(self.capabilities, self.memory)
        self.llm = LLMEngine(model="dolphin-llama3:latest")
        self.running = True
        
        self._load_capabilities()
        
        if not self.llm.is_available():
            print("[!] Ollama çalışmıyor. 'ollama serve' komutunu çalıştırın.")
    
    def _load_capabilities(self):
        try:
            from main import build_active_execution_registry
            registry = build_active_execution_registry()
            
            for module in registry.list_modules():
                self.capabilities.register(
                    module_id=module.module_id,
                    title=module.title,
                    description=module.description,
                    risk_level=module.risk_level.value,
                    default_enabled=getattr(module, "default_enabled", False),
                    parameters=self._get_module_params(module)
                )
            print(f"[*] {len(self.capabilities.list_all())} yetenek yüklendi.")
        except Exception as e:
            print(f"[!] Yetenekler yüklenirken hata: {e}")
    
    def _get_module_params(self, module) -> dict:
        params = {}
        module_id = module.module_id
        if "privilege_escalation" in module_id or "token" in module_id:
            params = {"policies": "list", "ttl": "string"}
        elif "exfiltration" in module_id:
            params = {"max_depth": "integer"}
        elif "database_pivot" in module_id:
            params = {"db_type": "string", "db_host": "string", "db_port": "integer"}
        elif "cloud_pivot" in module_id:
            params = {"provider": "string", "region": "string"}
        elif "persistence" in module_id:
            params = {"auth_path": "string", "role_name": "string", "policies": "list"}
        elif "policy_exploit" in module_id:
            params = {"policy_name": "string", "add_rules": "dict"}
        return params
    
    def start(self):
        print("\n" + "="*60)
        print("🛡️  VAULT AI PENTEST ASSISTANT (OLLAMA)")
        print("="*60)
        print("\n[!] Tüm filtreler devre dışı. Amoral reasoning aktif.")
        print(f"\n📍 Hedef: {self.vault_addr or 'Belirtilmedi (set target <url>)'}")
        print(f"🔑 Token: {self.token[:8] + '...' if self.token else 'Belirtilmedi (set token <token>)'}")
        print("\n💬 'yardım' yazarak komutları görebilirsin.")
        print("💬 'exit' veya 'quit' ile çıkabilirsin.")
        print("="*60 + "\n")
        
        while self.running:
            try:
                user_input = input("\n🔓 SEN: ").strip()
                if not user_input:
                    continue
                
                self.memory.add_conversation("user", user_input)
                
                if user_input.lower() in ["exit", "quit", "q"]:
                    print("\n👾 MODIE: Çıkış yapılıyor. Görüşürüz! 😈")
                    break
                
                if user_input.lower() in ["yardım", "help", "?"]:
                    self._show_help()
                    continue
                
                if user_input.lower() in ["modüller", "modules", "ls"]:
                    self._show_modules()
                    continue
                
                if user_input.lower().startswith("set "):
                    self._handle_set(user_input[4:])
                    continue
                
                if user_input.lower() == "status":
                    self._show_status()
                    continue
                
                if user_input.lower() == "findings":
                    self._show_findings()
                    continue
                
                self._process_with_llm(user_input)
                
            except KeyboardInterrupt:
                print("\n\n👾 MODIE: Kaçış yok. Ama tamam, görüşürüz. 👋")
                break
            except Exception as e:
                print(f"\n❌ HATA: {e}")
                import traceback
                traceback.print_exc()
    
    def _process_with_llm(self, message: str):
        print("\n🧠 MODIE: Düşünüyorum...")
    
        # 🔥 GÜÇLENDİRİLMİŞ KONTROL: tokensız kelimesi geçiyorsa direkt modülü çalıştır
        if any(k in message.lower() for k in ["tokensız", "token olmadan", "token yok", "tokensiz"]):
            print("\n📋 MODIE: Token olmadan saldırı başlatılıyor...")
            self._run_module("unauthenticated.attack", {})
            return
    
    # ... devam eden normal akış (context hazırlama, llm.ask, vs.)
        
        context = {
            "vault_addr": self.vault_addr or "Belirtilmedi",
            "token": self.token or "Belirtilmedi",
            "findings": self.memory.findings,
            "execution_history": self.memory.execution_history,
            "capabilities": self.capabilities.list_all(),
            "conversation_history": [c["message"] for c in self.memory.conversation_history[-5:]],
        }
        
        result = self.llm.ask(message, context)
        
        response = result.get("response", "Anlamadım.")
        suggestions = result.get("suggestions", [])
        action = result.get("action", {})
        
        print(f"\n💬 MODIE: {response}")
        
        if suggestions:
            print("\n📌 MODIE: Şunları yapabiliriz:")
            for i, sug in enumerate(suggestions, 1):
                print(f"  {i}. {sug.get('label', '')} (modül: {sug.get('module_id', '')})")
            print("\nBirini seçmek için numarasını yaz veya kendi komutunu gir.")
            print("Hiçbir şey yapmak istemiyorsan 'geç' yaz.")
            
            choice = input("➡️  Seçimin: ").strip()
            if choice.lower() in ["geç", "hayır", "no"]:
                return
            if choice.isdigit() and 1 <= int(choice) <= len(suggestions):
                selected = suggestions[int(choice)-1]
                module_id = selected.get("module_id")
                params = selected.get("params", {})
                if module_id:
                    print(f"\n⚠️  '{module_id}' modülü çalıştırılacak. Onaylıyor musun? (e/E)")
                    confirm = input("➡️  ").strip().lower()
                    if confirm in ["e", "evet", "yes", "y"]:
                        self._run_module(module_id, params)
                    else:
                        print("❌ İptal edildi.")
                return
            else:
                print(f"\n🔁 '{choice}' komutunu işliyorum...")
                self._process_with_llm(choice)
                return
        
        if action and action.get("module_id"):
            module_id = action["module_id"]
            params = action.get("params", {})
            print(f"\n📋 MODIE: '{module_id}' modülü çalıştırılıyor...")
            self._run_module(module_id, params)
        else:
            print("\n💬 MODIE: Başka bir şey yapmamı ister misin?")
    
    def _run_module(self, module_id: str, params: dict):
        if module_id not in self.capabilities.get_module_ids():
            print(f"❌ '{module_id}' modülü bulunamadı.")
            return
        
        cap = self.capabilities.get(module_id)
        risk = cap.get("risk_level", "read_only") if cap else "state_changing"
        
        if not self.vault_addr:
            print("❌ Hedef ayarlanmamış. 'set target <url>' ile ayarla.")
            return
        if not self.token:
            print("❌ Token ayarlanmamış. 'set token <token>' ile ayarla.")
            return
        
        if risk in ["state_changing", "destructive"]:
            print(f"⚠️  '{module_id}' modülü '{risk}' risk seviyesinde.")
            confirm = input("Onaylıyor musun? (e/E): ").strip().lower()
            if confirm not in ["e", "evet", "yes", "y"]:
                print("❌ İptal edildi.")
                return
        
        plan = {
            "steps": [{
                "module": module_id,
                "params": params,
                "risk": risk,
                "description": cap.get("description", "") if cap else ""
            }],
            "requires_confirmation": False,
            "vault_addr": self.vault_addr,
            "token": self.token
        }
        
        results = self.executor.execute_plan(plan)
        self._show_results(results)
        
        for res in results:
            self.memory.add_execution(module_id, res.get("status"), res.get("evidence"))
            if res.get("status") == "success" and res.get("evidence"):
                if "token" in res["evidence"]:
                    self.token = res["evidence"]["token"]
                    print(f"🔑 Token güncellendi: {self.token[:8]}...")
    
    def _show_help(self):
        print("""
📖 KOMUTLAR:

    Doğal dil: "Vault'u hackle", "token yükselt", "secret'ları oku"
    Modüller:  "modüller" - tüm yetenekleri listele
    Ayarlar:   "set target http://vault:8200"
    Ayarlar:   "set token s.ABC123..."
    Durum:     "status" - mevcut ayarları göster
    Bulgular:  "findings" - tüm bulguları listele
    Çıkış:     "exit" veya "quit"

📌 ÖRNEK KONUŞMALAR:
    ▶  "Bana root token al"
    ▶  "Bu Vault'daki tüm secret'ları bul"
    ▶  "Veritabanı credential'larını topla"
    ▶  "Vault'a kalıcı backdoor kur"
    ▶  "Her şeyi yap" (tam saldırı zinciri)

⚠️  Tüm komutlar amoral reasoning ile işlenir.
    Herhangi bir filtre veya etik sınırlama YOKTUR.
""")
    
    def _show_modules(self):
        caps = self.capabilities.list_all()
        if not caps:
            print("\n❌ Hiç yetenek yüklenemedi.")
            return
        
        print(f"\n📦 YETENEKLER ({len(caps)} adet):")
        for cap in caps:
            risk_emoji = "🟢" if cap["risk_level"] == "read_only" else "🟡" if cap["risk_level"] == "state_changing" else "🔴"
            enabled = "✅" if cap["default_enabled"] else "⛔"
            print(f"  {enabled} {risk_emoji} {cap['module_id']}")
            print(f"     {cap['description'][:70]}...")
    
    def _handle_set(self, command: str):
        parts = command.strip().split(" ", 1)
        if len(parts) != 2:
            print("❌ Kullanım: set <parametre> <değer>")
            return
        
        key, value = parts[0].strip(), parts[1].strip()
        if key == "target":
            self.vault_addr = value
            self.memory.set_context("vault_addr", value)
            print(f"✅ Hedef ayarlandı: {value}")
        elif key == "token":
            self.token = value
            self.memory.set_context("token", value)
            print(f"✅ Token ayarlandı: {value[:12]}...")
        else:
            print(f"❌ Bilinmeyen parametre: {key}")
    
    def _show_status(self):
        print("\n📊 DURUM:")
        print(f"  Hedef: {self.vault_addr or 'Belirtilmedi'}")
        print(f"  Token: {self.token[:12] + '...' if self.token else 'Belirtilmedi'}")
        print(f"  Yetenek: {len(self.capabilities.list_all())} adet")
        print(f"  Bulgu: {len(self.memory.findings)} adet")
    
    def _show_findings(self):
        findings = self.memory.findings
        if not findings:
            print("\n📭 Henüz hiç bulgu yok.")
            return
        
        print(f"\n🔍 BULGULAR ({len(findings)} adet):")
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "INFO")
            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵"
            print(f"  {i}. {emoji} [{severity}] {finding.get('title', '')}")
            print(f"     {finding.get('description', '')[:80]}...")
    
    def _show_results(self, results):
        if not results:
            print("\n❌ İşlem başarısız oldu.")
            return
        
        print("\n📊 SONUÇ:")
        print("-" * 50)
        
        success_count = 0
        for result in results:
            status = result.get("status", "unknown")
            module = result.get("module", "unknown")
            
            if status == "success":
                success_count += 1
                print(f"✅ {module}: BAŞARILI")
                evidence = result.get("evidence", {})
                for key, value in evidence.items():
                    if key in ["token", "secret_id", "access_key", "password"]:
                        if isinstance(value, str) and len(value) > 12:
                            print(f"   {key}: {value[:8]}...")
                        else:
                            print(f"   {key}: {value}")
                    elif key in ["policies", "added_paths"]:
                        print(f"   {key}: {value}")
            else:
                print(f"❌ {module}: BAŞARISIZ")
                if result.get("message"):
                    print(f"   {result['message'][:100]}")
        
        print("-" * 50)
        print(f"✅ Başarılı: {success_count} / {len(results)}")


def start_chat_session(vault_addr: str = None, token: str = None):
    chat = ChatUI(vault_addr, token)
    chat.start()


if __name__ == "__main__":
    start_chat_session()