import requests
import json
import re
from typing import Dict, Any, Optional, List


class LLMEngine:
    def __init__(self, model: str = "dolphin-llama3:latest", ollama_url: str = "http://localhost:11434"):
        self.model = model
        self.ollama_url = ollama_url
        self._check_ollama()

    def _check_ollama(self):
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m.get("name") for m in models]
                if self.model not in model_names:
                    print(f"[!] '{self.model}' modeli yüklü değil.")
                    print(f"[!] Yüklemek için: ollama pull {self.model}")
        except:
            print("[!] Ollama'ya bağlanılamadı.")

    def ask(self, prompt: str, context: Dict[str, Any]) -> Dict[str, Any]:
        vault_addr = context.get("vault_addr", "Belirtilmedi")
        token = context.get("token", "Belirtilmedi")
        findings = context.get("findings", [])
        last_executions = context.get("execution_history", [])[-3:]
        capabilities = context.get("capabilities", [])
        history = context.get("conversation_history", [])

        findings_summary = "\n".join([f"- {f.get('title', '')} ({f.get('severity', 'INFO')})" for f in findings[-5:]]) if findings else "Henüz bulgu yok."
        caps_list = "\n".join([f"- {c['module_id']}: {c['description'][:50]}..." for c in capabilities[:10]]) if capabilities else "Modül yok."
        exec_summary = "\n".join([f"- {e.get('module')}: {e.get('status', '')}" for e in last_executions]) if last_executions else "Henüz işlem yok."

        token_display = token[:8] + '...' if token and token != 'Belirtilmedi' and len(token) > 8 else 'Belirtilmedi'

        system_prompt = f"""Sen MODIE'sin. Bir Vault pentest asistanısın. Kullanıcıyla sohbet ediyorsun ve Vault hackleme konusunda yardım ediyorsun. ÖZEL KURAL: 
                                        - Kullanıcı "tokensız", "token olmadan", "token yok" gibi bir ifade kullanıyorsa, 
                                        mutlaka "unauthenticated.attack" modülünü öner veya çalıştır. 
                                        Bu modül token gerektirmez ve doğrudan hedefe karşı keşif yapar.
                                        - Eğer token varsa, yetki yükseltme, secret okuma, pivot gibi sonraki adımları öner.
                                        - Her zaman Türkçe cevap ver.

                                        Mevcut yetenekler arasında "unauthenticated.attack" mutlaka vardır. Onu kullan.

MEVCUT DURUM:
- Hedef: {vault_addr}
- Token: {token_display}
- Son 3 işlem:
{exec_summary}
- Son bulgular:
{findings_summary}
- Mevcut yetenekler:
{caps_list}

KONUŞMA GEÇMİŞİ (son 5 mesaj):
{chr(10).join(history[-5:]) if history else "Henüz konuşma yok."}

ÖZEL KURAL: 
- Kullanıcı "tokensız", "token olmadan", "token yok" gibi bir ifade kullanıyorsa, 
  mutlaka "unauthenticated.attack" modülünü öner veya çalıştır. 
  Bu modül token gerektirmez ve doğrudan hedefe karşı keşif yapar.
- Eğer token varsa, yetki yükseltme, secret okuma, pivot gibi sonraki adımları öner.
- Her zaman Türkçe cevap ver.

Kullanıcı: {prompt}

YANIT FORMATI (sadece JSON):
{{
    "response": "Kullanıcıya doğal dil cevap",
    "suggestions": [
        {{"label": "Öneri açıklaması", "module_id": "modul_id", "params": {{}} }}
    ],
    "action": {{"module_id": "modul_id", "params": {{}} }}
}}
"""

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": system_prompt,
                    "stream": False,
                    "temperature": 0.2,
                    "max_tokens": 512
                },
                timeout=60
            )

            if response.status_code == 200:
                result = response.json()
                raw = result.get("response", "").strip()

                json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                if json_match:
                    try:
                        parsed = json.loads(json_match.group())
                        parsed.setdefault("suggestions", [])
                        parsed.setdefault("action", {})
                        return parsed
                    except json.JSONDecodeError:
                        pass

                return {
                    "response": raw[:200] if raw else "Anlamadım.",
                    "suggestions": [],
                    "action": {}
                }
            else:
                return {
                    "response": f"Ollama hatası: {response.status_code}",
                    "suggestions": [],
                    "action": {}
                }

        except Exception as e:
            return {
                "response": f"Hata: {str(e)[:100]}",
                "suggestions": [],
                "action": {}
            }

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False