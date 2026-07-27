from typing import Optional, Dict, Any, List
import requests
import json
import base64

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Cloud SDK'lar için opsiyonel bağımlılıklar
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import resource_manager
    from google.oauth2 import service_account
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False


class CloudKeyExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_key_exfiltration.key_dump",
            title="Cloud Key Exfiltration",
            risk_level=RiskLevel.STATE_CHANGING,
            domain="cloud",
            description=(
                "Attempts to locate and exfiltrate cloud provider keys and service account secrets."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        # Require a vault address and some credentials to operate
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        # Minimal implementation: do not perform any network calls here.
        if not getattr(context, "vault_addr", None):
            return ExecutionResult(status="skipped", message="Missing vault_addr", evidence={"missing": ["vault_addr"]})

        # This module is a placeholder in tests; return a harmless partial result.
        return ExecutionResult(status="partial", message="Cloud key exfiltration module is not configured.", evidence={})


# ─── YARDIMCILAR ──────────────────────────────────────────────────────────────

def _get_tag(instance, tag_name):
    """EC2 instance'dan tag değerini al"""
    for tag in instance.get('Tags', []):
        if tag.get('Key') == tag_name:
            return tag.get('Value')
    return None


def _has_cloud_creds(context):
    """Context'te cloud credential'ları var mı kontrol et"""
    for finding in getattr(context, "findings", []):
        if "cloud" in finding.get("title", "").lower():
            return True
    return False


def _get_cloud_creds(context, provider):
    """Context'ten cloud credential'larını topla"""
    creds = []
    
    for finding in getattr(context, "findings", []):
        evidence = finding.get("evidence", {})
        if "credentials" in evidence:
            for cred in evidence.get("credentials", []):
                if cred.get("provider", "").lower() == provider:
                    creds.append(cred)
    
    # Doğrudan attribute
    if hasattr(context, "cloud_credentials"):
        for cred in context.cloud_credentials:
            if cred.get("provider", "").lower() == provider:
                creds.append(cred)
    
    return creds