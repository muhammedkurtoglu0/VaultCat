import os


class VaultPentestHelper:
    def __init__(self, provider="openai"):
        self.provider = provider
        self.api_key = os.getenv("AI_API_KEY")

    def analyze_error(self, status_code, response_text, module_name):
        """Interpret module errors from a Vault pentest perspective."""
        response_text = response_text or ""
        analysis = {
            "status_code": status_code,
            "module": module_name,
            "explanation": "Bilinmeyen bir hata olustu.",
            "next_steps": [],
        }

        if status_code == 400:
            if "root tokens may not be created" in response_text:
                analysis["explanation"] = (
                    "Vault hiyerarsi engeli: root olmayan bir token ile dogrudan "
                    "root policy tasiyan yeni bir token uretilemez."
                )
                analysis["next_steps"] = [
                    "Yukseltme hedefi olarak root yerine admin, admin-policy veya vault-admin gibi policy adlarini deneyin.",
                    "Araci active-auto policy discovery moduyla calistirin.",
                ]
            else:
                analysis["explanation"] = (
                    "Bad Request: Vault istegi kabul etmedi. Payload, policy adi, mount path veya KV surumu hatali olabilir."
                )
                analysis["next_steps"] = [
                    "Response metnindeki errors alanini kontrol edin.",
                    "Ilgili modulun gonderdigi URL ve JSON payload degerlerini dogrulayin.",
                ]
        elif status_code == 403:
            analysis["explanation"] = (
                f"Yetkilendirme hatasi: mevcut token {module_name} modulunun "
                "erismeye calistigi API ucuna yetkili degil."
            )
            analysis["next_steps"] = [
                "Token yetkilerini dogrulamak icin --capability-audit moduluyle sys/capabilities-self calistirin.",
                "KV exfiltration icin secret/data/* ve secret/metadata/* uzerinde read/list capability gerektigini kontrol edin.",
            ]
        elif status_code == 404:
            analysis["explanation"] = (
                "Endpoint bulunamadi: hedef path, mount noktasi veya KV v1/v2 endpoint bicimi uyusmuyor."
            )
            analysis["next_steps"] = [
                "Hedef Vault'un KV v1 mi KV v2 mi kullandigini kontrol edin.",
                "KV v2 icin metadata ve data prefixlerinin dogru kullanildigindan emin olun.",
            ]

        return analysis

    def generate_chat_response(self, user_message, context_data=None):
        """Return a rule-based Vault pentest answer for the first chat iteration."""
        msg = (user_message or "").lower()
        context_data = context_data or {}

        if "token" in msg and ("yetki" in msg or "capability" in msg):
            return (
                "Token yetkilerini gormek icin --capability-audit kullanabilir veya "
                "sys/capabilities-self endpointine hedef path listesini gonderebiliriz."
            )
        if "sizdir" in msg or "sızdır" in msg or "exfil" in msg or "secret" in msg:
            return (
                "Secret exfiltration icin once sys/mounts ile KV engine'leri bulunur; "
                "sonra KV v2 icin metadata ile LIST, data ile GET istekleri yapilir."
            )
        if "400" in msg or "root token" in msg:
            return self.analyze_error(
                400,
                "root tokens may not be created without parent token being root",
                context_data.get("module", "privilege_escalation"),
            )["explanation"]
        if "403" in msg or "permission denied" in msg:
            return self.analyze_error(
                403,
                "permission denied",
                context_data.get("module", "vault_module"),
            )["explanation"]

        return (
            "Anlasildi. Vault pentest surecinde token yetkisi, policy escalation, "
            "KV enumeration veya secret exfiltration konusunda yardimci olabilirim."
        )

