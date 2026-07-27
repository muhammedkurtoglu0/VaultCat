from typing import Optional
from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10


class CloudPivotModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="cloud_pivot.exploit",
            title="Cloud Pivot - Connect and Enumerate Resources",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="cloud",
            description=(
                "Uses harvested cloud credentials to connect to AWS, Azure, or GCP "
                "and enumerate resources (EC2 instances, VMs, projects)."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}
        provider = params.get("provider", "aws").lower()
        region = params.get("region", "us-east-1")
        
        print(f"[*] [ACTIVE] Connecting to {provider.upper()} cloud...")

        # AWS
        if provider == "aws":
            return self._execute_aws(context, params)
        
        # Azure
        elif provider == "azure":
            return self._execute_azure(context, params)
        
        # GCP
        elif provider == "gcp":
            return self._execute_gcp(context, params)
        
        else:
            return ExecutionResult(
                status="error",
                message=f"Unsupported cloud provider: {provider}",
                evidence={"error": "Invalid provider"},
            )

    def _execute_aws(self, context, params):
        """AWS kaynaklarını listele"""
        try:
            import boto3
        except ImportError:
            return ExecutionResult(
                status="error",
                message="boto3 not installed. Run: pip install boto3",
                evidence={"error": "Missing dependency: boto3"},
            )

        access_key = params.get("access_key")
        secret_key = params.get("secret_key")
        session_token = params.get("security_token")
        region = params.get("region", "us-east-1")

        if not access_key or not secret_key:
            return ExecutionResult(
                status="failed",
                message="AWS credentials incomplete.",
                evidence={"error": "Missing access_key or secret_key"},
            )

        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region,
            )

            results = {}
            
            # EC2 instance'ları listele
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
                            "public_ip": instance.get('PublicIpAddress'),
                            "private_ip": instance.get('PrivateIpAddress'),
                        })
                results["ec2_instances"] = instance_list
            except Exception as e:
                results["ec2_error"] = str(e)

            # S3 bucket'ları listele
            try:
                s3 = session.client('s3')
                buckets = s3.list_buckets()
                results["s3_buckets"] = [b['Name'] for b in buckets.get('Buckets', [])]
            except Exception as e:
                results["s3_error"] = str(e)

            context.add_finding(
                title="HIGH: AWS Resources Enumerated",
                description=f"Found {len(results.get('ec2_instances', []))} EC2 instances and {len(results.get('s3_buckets', []))} S3 buckets.",
                severity="HIGH",
                evidence=results,
            )

            return ExecutionResult(
                status="success",
                message=f"AWS pivot completed. Found {len(results.get('ec2_instances', []))} instances.",
                evidence=results,
            )

        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"AWS pivot failed: {str(e)}",
                evidence={"error": str(e)},
            )

    def _execute_azure(self, context, params):
        """Azure kaynaklarını listele"""
        return ExecutionResult(
            status="success",
            message="Azure pivot placeholder - implement with azure-mgmt-resource",
            evidence={"provider": "azure", "status": "pending"},
        )

    def _execute_gcp(self, context, params):
        """GCP kaynaklarını listele"""
        return ExecutionResult(
            status="success",
            message="GCP pivot placeholder - implement with google-cloud-resource-manager",
            evidence={"provider": "gcp", "status": "pending"},
        )