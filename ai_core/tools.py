"""Pentest tool definitions in LLM function-calling format.

Each tool is described with a name, description, and parameter schema so the
LLM can decide *when* and *why* to use it — not just pattern-match keywords.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Tool definition schema (OpenAI function-calling compatible)
# ---------------------------------------------------------------------------


@dataclass
class ToolParam:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    enum: list[str] | None = None
    default: Any = None


@dataclass
class ToolDef:
    """Definition of a callable tool the agent can invoke."""

    name: str
    description: str
    parameters: list[ToolParam] = field(default_factory=list)
    handler: Optional[Callable] = None
    phase: str = ""  # recon | audit | hijack | active | meta
    risk: str = "read_only"

    def to_openai_function(self) -> dict:
        props: dict[str, dict] = {}
        required: list[str] = []
        for p in self.parameters:
            prop: dict = {"type": p.type, "description": p.description}
            if p.enum:
                prop["enum"] = p.enum
            if p.default is not None:
                prop["default"] = p.default
            props[p.name] = prop
            if p.required:
                required.append(p.name)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        }

    def to_anthropic_tool(self) -> dict:
        props: dict[str, dict] = {}
        required: list[str] = []
        for p in self.parameters:
            prop: dict = {"type": p.type, "description": p.description}
            if p.enum:
                prop["enum"] = p.enum
            props[p.name] = prop
            if p.required:
                required.append(p.name)
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        }


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOL_RUN_RECON = ToolDef(
    name="run_unauthenticated_recon",
    description=(
        "Run FULL passive reconnaissance against a Vault target WITHOUT authentication. "
        "Discovers: TLS config, health/initialization/seal status, version, cluster metadata, "
        "exposed UI endpoints, authentication methods (userpass/ldap/oidc/kubernetes/approle), "
        "CORS configuration, HTTP security headers, deployment indicators. "
        "USE THIS FIRST on any new target — it requires NO credentials and maps the attack surface."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL, e.g. http://192.168.1.100:8200", required=True),
    ],
    phase="recon",
)

TOOL_RUN_HIJACK_SCAN = ToolDef(
    name="run_hijack_scan",
    description=(
        "Scan a LOCAL directory/file tree for exposed Vault credentials: tokens, "
        "AppRole role_id/secret_id, AWS access keys, database passwords, Vault addresses, "
        "connection URLs, Vault Agent configs. Also scans GIT HISTORY for committed credentials. "
        "USE THIS when you have local file system access, after gaining shell access, "
        "examining config repos, CI/CD pipelines, or developer workstations."
    ),
    parameters=[
        ToolParam("path", "string",
                  "Local directory or file path to scan", required=True),
        ToolParam("vault_addr", "string",
                  "Vault address for optional token validation"),
        ToolParam("token", "string",
                  "Vault token for optional credential validation"),
        ToolParam("validate_token", "boolean",
                  "Live-validate discovered tokens against vault_addr"),
        ToolParam("validate_approle", "boolean",
                  "Live-validate discovered AppRole pairs"),
        ToolParam("include_git_history", "boolean",
                  "Scan git commit history (default: true)"),
        ToolParam("max_file_size_mb", "integer",
                  "Max file size in MB (default: 5)"),
    ],
    phase="hijack",
)

TOOL_RUN_ENV_SCAN = ToolDef(
    name="run_env_scan",
    description=(
        "Scan LOCAL environment variables and ~/.vault-token file for Vault credentials. "
        "Checks: VAULT_TOKEN, VAULT_ADDR, VAULT_NAMESPACE. "
        "USE THIS on compromised hosts, CI runners, or when you have shell access."
    ),
    parameters=[],
    phase="hijack",
)

TOOL_RUN_CAPABILITY_AUDIT = ToolDef(
    name="run_capability_audit",
    description=(
        "Audit a Vault token's capabilities using sys/capabilities-self. Shows exactly which "
        "Vault paths the token can read/write/delete/sudo. Checks CRITICAL paths: sys/*, "
        "auth/*, identity/*, database/config/*, database/roles/*. "
        "USE THIS immediately after obtaining ANY token to understand its blast radius. "
        "BEFORE responding, if the capability results show read access on sys/mounts, "
        "sys/auth, or sys/policy, use run_raw_vault_request to read those endpoints "
        "and discover mounts, auth methods, and policies. "
        "ALSO use run_raw_vault_request to read sys/mounts and sys/auth regardless — "
        "many tokens have read access that capability audit doesn't highlight."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token to audit", required=True),
        ToolParam("paths", "array",
                  "Specific paths to check (uses comprehensive defaults if omitted)"),
        ToolParam("namespace", "string", "Vault namespace if applicable"),
    ],
    phase="audit",
)

TOOL_RUN_PRIV_ESC_SCAN = ToolDef(
    name="run_priv_esc_scan",
    description=(
        "SIMULATE privilege escalation risk SAFELY using sys/capabilities-self. "
        "Checks if the token can modify its own ACL policy or create new tokens. "
        "This is READ-ONLY — does NOT actually create tokens or modify policies. "
        "USE THIS to assess whether a low-privilege token can escalate."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token to audit", required=True),
        ToolParam("policy_names", "array",
                  "Policy names to check escalation to"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="audit",
)

TOOL_RUN_KV_ENUMERATION = ToolDef(
    name="run_kv_enumeration",
    description=(
        "Recursively enumerate ALL accessible KV secret paths and list their keys. "
        "Builds a complete tree of readable secrets using async parallel workers. "
        "USE THIS after obtaining a token to map what secrets are accessible. "
        "IMPORTANT: The tree shows NESTED paths like secret/admin/creds — "
        "use run_secret_exfiltration to dump the actual secret values. "
        "NEVER brute-force flat paths like secret/data/admin — KV v2 uses "
        "nested paths (secret/data/admin/creds), not flat ones. "
        "If enumeration shows 'creds (readable)', the full path is already known."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token", required=True),
        ToolParam("kv_path", "string",
                  "KV start path, e.g. secret/ or kv/"),
        ToolParam("kv_version", "integer",
                  "KV engine version (1 or 2, auto-detected)"),
        ToolParam("namespace", "string", "Vault namespace"),
        ToolParam("max_depth", "integer",
                  "Max recursion depth (default: 5)"),
        ToolParam("read_leaves", "boolean",
                  "Read leaf secret metadata (default: false)"),
    ],
    phase="audit",
)

TOOL_RUN_TTL_AUDIT = ToolDef(
    name="run_ttl_audit",
    description=(
        "Audit Vault mount TTLs and PKI certificate TTL governance. "
        "Flags mounts with unlimited TTLs and PKI roles with dangerously long cert lifetimes. "
        "USE THIS to find weak TTL configurations enabling long-lived credential abuse."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token", required=True),
        ToolParam("namespace", "string", "Vault namespace"),
        ToolParam("max_mount_ttl_seconds", "integer",
                  "Max allowed mount TTL in seconds"),
        ToolParam("max_pki_cert_ttl_seconds", "integer",
                  "Max allowed PKI cert TTL in seconds"),
    ],
    phase="audit",
)

TOOL_RUN_AUTH_CONFIG_AUDIT = ToolDef(
    name="run_auth_config_audit",
    description=(
        "Audit Kubernetes, AWS IAM, and LDAP auth method security configurations. "
        "Flags wildcard service account bindings, wildcard IAM principal ARNs, "
        "disabled LDAP lockout, and other misconfigurations. "
        "USE THIS to find authentication bypass paths."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token", required=True),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="audit",
)

TOOL_RUN_POLICY_AUDITOR = ToolDef(
    name="run_policy_auditor",
    description=(
        "Download and analyze ALL Vault ACL policies the token can read. "
        "Performs HCL analysis to find wildcard paths, write/delete/sudo capabilities "
        "on sys/auth/identity paths, and broad policy grants. "
        "USE THIS to find over-privileged policies and lateral movement paths."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token", required=True),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="audit",
)

TOOL_READ_SINGLE_POLICY = ToolDef(
    name="read_single_policy",
    description=(
        "Read a single Vault ACL policy by name. "
        "Use this when the token cannot LIST sys/policies/acl but might still "
        "have READ access to individual policies via sys/policies/acl/*. "
        "Try common names first: 'default', 'root', and the token's own policy "
        "names from lookup-self. Returns the raw HCL policy text. Read-only."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token", required=True),
        ToolParam("policy_name", "string", "Policy name to read (e.g. 'default', 'root', 'wildcard-sudo-user')", required=True),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="audit",
)

TOOL_RUN_RAW_VAULT_REQUEST = ToolDef(
    name="run_raw_vault_request",
    description=(
        "Ham Vault API istegi gonder (GET/POST/PUT/DELETE/LIST). "
        "Token OPSIYONELDIR — AppRole/login gibi unauthenticated islemler icin "
        "token='' gonder, X-Vault-Token header eklenmez. "
        "Kullaniciya manuel curl komutu onermek yerine BU TOOL'U KULLAN. "
        "path='auth/approle/login' gibi (basinda /v1/ olmadan). "
        "body dict olarak POST/PUT icin gonderilir. "
        "ORNEK AppRole: method='POST', path='auth/approle/login', "
        "body={'role_id':'...','secret_id':'...'}, token=''. "
        "ONEMLI: Eger ayni islemi yapan bir aktif modul varsa (seal, unseal, "
        "database harvest gibi) MODULU KULLAN, bu tool'u degil. "
        "Moduller bulgu kaydeder ve risk kontrolu yapar, raw request yapmaz. "
        "Bu tool SADECE modul olmayan ozel islemler icindir."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("method", "string", "HTTP method: GET/POST/PUT/DELETE/LIST", required=True),
        ToolParam("path", "string", "Vault API path, e.g. 'auth/approle/login'", required=True),
        ToolParam("token", "string", "Vault token (bos birakilirsa unauthenticated)"),
        ToolParam("body", "object", "JSON body for POST/PUT requests"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="exec",
)

# ── Active execution ─────────────────────────────────────────────────────

TOOL_RUN_PRIVILEGE_ESCALATION = ToolDef(
    name="run_privilege_escalation",
    description=(
        "ACTIVELY attempt privilege escalation by creating new tokens via "
        "auth/token/create. Tries to add high-privilege policies (admin, root, "
        "vault-admin, master, etc.). STATE-CHANGING: creates real tokens. "
        "The escalated token is stored for subsequent steps automatically. "
        "USE THIS when capability audit shows token creation permissions."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Low-privilege Vault token", required=True),
        ToolParam("policies", "array",
                  "Policy names to attempt (auto-discovers critical policies if omitted)"),
        ToolParam("ttl", "string",
                  "Requested token TTL (default: 30m)"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_SECRET_EXFILTRATION = ToolDef(
    name="run_secret_exfiltration",
    description=(
        "EXFILTRATE secrets using a captured/elevated token. Enumerates and reads: "
        "KV secrets (with full values), Transit encryption keys, PKI certificates, SSH roles. "
        "Automatically uses the token from a previous privilege escalation step. "
        "USE THIS after KV enumeration to dump actual secret VALUES — "
        "NEVER brute-force individual secret paths with run_raw_vault_request. "
        "This tool handles nested KV paths correctly (secret/admin/creds, not secret/data/admin)."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Token to use (uses captured token from previous step if omitted)"),
        ToolParam("max_depth", "integer",
                  "KV recursion depth (default: 3)"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="read_only",
)

TOOL_RUN_DATABASE_CREDENTIAL_HARVEST = ToolDef(
    name="run_database_credential_harvest",
    description=(
        "HARVEST database credentials from Vault Database Secrets Engine. "
        "Generates dynamic database users from ALL accessible roles. "
        "STATE-CHANGING: creates real database users. Automatically flags admin/dba roles. "
        "USE THIS after privilege escalation to pivot from Vault to databases. "
        "CRITICAL: Whenever sys/mounts shows a 'database/' mount, ALWAYS try this tool "
        "even if the token seems low-privilege — many limited tokens have read access "
        "to database/creds/* which allows harvesting admin database credentials. "
        "NEVER skip this tool just because KV enumeration is empty."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token (uses captured token if omitted)"),
        ToolParam("mount_path", "string",
                  "Specific database mount path (auto-discovers if omitted)"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_CLOUD_KEY_EXFILTRATION = ToolDef(
    name="run_cloud_key_exfiltration",
    description=(
        "EXFILTRATE cloud IAM credentials from Vault AWS/Azure/GCP Secrets Engines. "
        "Generates access keys, service principals, or service account keys. "
        "Automatically flags high-privilege roles (Administrator, Owner, PowerUser). "
        "STATE-CHANGING: creates real cloud credentials. "
        "USE THIS after privilege escalation to pivot from Vault to cloud infrastructure."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token (uses captured token if omitted)"),
        ToolParam("provider", "string",
                  "Cloud provider filter: aws, azure, or gcp"),
        ToolParam("mount_path", "string",
                  "Specific cloud mount path"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_LIST_ACTIVE_MODULES = ToolDef(
    name="list_active_modules",
    description=(
        "List ALL available active execution modules with their IDs, risk levels, "
        "and descriptions. Use this to discover additional attack capabilities "
        "beyond the standard tools (persistence, pivoting, exploitation, backdoors)."
    ),
    parameters=[],
    phase="meta",
)

TOOL_RUN_ACTIVE_MODULE = ToolDef(
    name="run_active_module",
    description=(
        "Execute ANY registered active module by its module_id. Supports: "
        "persistence backdoors, database/cloud pivoting, audit disabling, CVE exploitation, "
        "token/policy exploitation, unauthenticated attacks, and more. "
        "USE list_active_modules first to see available module IDs."
    ),
    parameters=[
        ToolParam("module_id", "string",
                  "Module ID from list_active_modules", required=True),
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token (uses captured token if omitted)"),
        ToolParam("params", "object",
                  "Module-specific parameters"),
        ToolParam("max_risk", "string",
                  "Max risk level: read_only, state_changing, destructive"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
)

TOOL_RUN_AWS_AUTH_LOGIN = ToolDef(
    name="run_aws_auth_login",
    description=(
        "AWS IAM credential'lari ile Vault'a login ol. Vault token'i GEREKMEZ. "
        "SigV4 ile sts:GetCallerIdentity imzalanir, POST auth/aws/login yapilir, "
        "alinan token sonraki tum islemlerde otomatik kullanilir. "
        "Eger elinde AWS_ACCESS_KEY_ID ve AWS_SECRET_ACCESS_KEY varsa token'siz "
        "authenticated assessment zincirini baslatabilirsin."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("access_key", "string", "AWS Access Key ID (AKIA...)", required=True),
        ToolParam("secret_key", "string", "AWS Secret Access Key", required=True),
        ToolParam("session_token", "string", "AWS Session Token (STS / assumed roles)"),
        ToolParam("role", "string", "Vault AWS auth role name (auto-detect if omitted)"),
        ToolParam("mount_path", "string", "Auth mount path (default: aws)"),
        ToolParam("region", "string", "AWS region for STS signing (default: us-east-1)"),
    ],
    phase="active",
)

# ── Meta / reporting ─────────────────────────────────────────────────────

TOOL_GET_FINDINGS = ToolDef(
    name="get_findings",
    description=(
        "Get ALL accumulated pentest findings so far with severity breakdowns "
        "and risk score. USE THIS to review progress, decide next steps, "
        "or prepare the final report."
    ),
    parameters=[],
    phase="meta",
)

TOOL_GET_RISK_SCORE = ToolDef(
    name="get_risk_score",
    description=(
        "Get the current risk score (0-100) and letter grade (A-F) based on "
        "all findings. USE THIS to quickly assess overall security posture."
    ),
    parameters=[],
    phase="meta",
)

TOOL_REFRESH_NVD_CACHE = ToolDef(
    name="refresh_nvd_cache",
    description=(
        "FETCH the latest HashiCorp Vault CVEs from the NVD (National Vulnerability "
        "Database) API. Results are cached for 24 hours. Set NVD_API_KEY env var "
        "for higher rate limits. USE THIS at the start of an engagement."
    ),
    parameters=[],
    phase="meta",
)

# ── Security MCP tools ──────────────────────────────────────────────────

TOOL_RUN_COMPLIANCE_CHECK = ToolDef(
    name="run_compliance_check",
    description=(
        "CIS-aligned Vault configuration audit. Checks TLS, audit logging, "
        "root token usage, seal status, and CORS configuration. Read-only."
    ),
    parameters=[
        ToolParam(name="vault_addr", type="string", description="Target Vault URL", required=True),
        ToolParam(name="token", type="string", description="Vault token for authenticated checks", required=False),
    ],
    phase="audit",
)

TOOL_RUN_NETWORK_PROBE = ToolDef(
    name="run_network_probe",
    description=(
        "Lightweight network scan of Vault target: port accessibility, HTTP "
        "response timing, TLS certificate chain analysis, rate-limiting detection."
    ),
    parameters=[
        ToolParam(name="vault_addr", type="string", description="Target Vault URL", required=True),
        ToolParam(name="ports", type="array", description="Ports to scan (default: 8200,8201,443,80)", required=False),
    ],
    phase="recon",
)

TOOL_GET_FIX_COMMANDS = ToolDef(
    name="get_fix_commands",
    description=(
        "Return exact Vault CLI commands to fix a specific finding. "
        "Give it a finding title or description and it returns the "
        "concrete 'vault policy write ...' / 'vault token revoke ...' "
        "commands to remediate the issue. USE THIS when user asks "
        "'how do I fix this?' or wants remediation steps."
    ),
    parameters=[
        ToolParam(name="finding_title", type="string", description="Finding title or description to get fix commands for", required=True),
        ToolParam(name="finding_module", type="string", description="Module that produced the finding (optional, helps narrow fixes)", required=False),
        ToolParam(name="evidence", type="string", description="Finding evidence JSON (optional, for policy name extraction)", required=False),
    ],
    phase="report",
)

TOOL_SEARCH_TO_ACTIONS = ToolDef(
    name="search_to_actions",
    description=(
        "Web'de arama yap ve sonuclari dogrudan calistirilabilir Vault API "
        "cagrilarina (curl, vault CLI, requests) donustur. CVE exploit'leri "
        "veya pentest teknikleri icin optimize edilmistir. "
        "Sonuclar run_raw_vault_request ile hemen calistirilabilir."
    ),
    parameters=[
        ToolParam(name="query", type="string", description="Search query (CVE ID, technique name, or free text)", required=True),
        ToolParam(name="vault_addr", type="string", description="Target Vault URL to inject into action params", required=False),
        ToolParam(name="max_results", type="integer", description="Max search results (default 3)", required=False),
    ],
    phase="recon",
)

TOOL_SET_PROFILE = ToolDef(
    name="set_evasion_profile",
    description=(
        "Switch HTTP evasion profile mid-session. "
        "'turbo' = 0 jitter, 15 concurrency (max speed, lab only). "
        "'aggressive' = 0 jitter, 8 concurrency. "
        "'balanced' = 0-1s jitter, 5 concurrency (default). "
        "'stealth' = 1-4s jitter, 2 concurrency. "
        "'paranoid' = 5-15s jitter, 1 concurrency."
    ),
    parameters=[
        ToolParam(name="profile", type="string", description="Profile: turbo|aggressive|balanced|stealth|paranoid", required=True),
    ],
    phase="recon",
)

TOOL_EXPORT_FULL_REPORT = ToolDef(
    name="export_full_report",
    description=(
        "Export all findings as JSON + Markdown + PDF in a single call. "
        "Returns paths to all three report formats."
    ),
    parameters=[
        ToolParam(name="output_prefix", type="string", description="Output file prefix", required=False),
        ToolParam(name="target", type="string", description="Target URL for report metadata", required=False),
    ],
    phase="meta",
)

TOOL_SEND_NOTIFICATION = ToolDef(
    name="send_notification",
    description=(
        "Send pentest results summary via webhook (Slack, Discord, Teams). "
        "Includes top critical/high findings and risk score."
    ),
    parameters=[
        ToolParam(name="webhook_url", type="string", description="Webhook URL", required=True),
        ToolParam(name="target", type="string", description="Target identifier", required=False),
        ToolParam(name="notification_type", type="string", description="slack, discord, teams, or generic", required=False),
    ],
    phase="meta",
)

TOOL_RUN_AUDIT_LOG_SCAN = ToolDef(
    name="run_audit_log_scan",
    description=(
        "Scan Vault audit logs for anomalies and security events. "
        "Detects suspicious token usage, policy changes, auth modifications."
    ),
    parameters=[
        ToolParam(name="audit_log_path", type="string", description="Path to local audit log file", required=False),
        ToolParam(name="vault_addr", type="string", description="Vault address for API-based check", required=False),
        ToolParam(name="token", type="string", description="Vault token", required=False),
        ToolParam(name="max_lines", type="integer", description="Max lines to scan (default 10000)", required=False),
    ],
    phase="audit",
)

TOOL_RUN_CONTAINER_SCAN = ToolDef(
    name="run_container_scan",
    description=(
        "Docker/K8s container security scan for Vault. Checks root user, "
        "IPC_LOCK, memory limits, privileged mode, port exposure."
    ),
    parameters=[
        ToolParam(name="container_name", type="string", description="Docker container name (default: vault-target)", required=False),
        ToolParam(name="vault_addr", type="string", description="Target Vault URL", required=False),
    ],
    phase="audit",
)

TOOL_GET_THREAT_INTEL = ToolDef(
    name="get_threat_intel",
    description=(
        "Fetch latest Vault-related CVEs and threat intelligence from "
        "NVD cache and version-based CVE matching."
    ),
    parameters=[
        ToolParam(name="vault_version", type="string", description="Vault version to match CVEs against", required=False),
    ],
    phase="meta",
)

TOOL_GENERATE_DIFF_REPORT = ToolDef(
    name="generate_diff_report",
    description=(
        "Compare current findings with a previous JSON report. "
        "Shows new findings, resolved findings, and severity changes."
    ),
    parameters=[
        ToolParam(name="previous_json_path", type="string", description="Path to previous JSON report", required=True),
        ToolParam(name="target", type="string", description="Target URL", required=False),
    ],
    phase="meta",
)

TOOL_WEB_SEARCH = ToolDef(
    name="web_search",
    description=(
        "Search the web for Vault CVE details, exploit techniques, error message "
        "solutions, and configuration references. Results are cached for 24 hours. "
        "Use this when you encounter an unknown CVE, error code, or need exploit "
        "documentation. Parameters: query (search string), max_results (1-10, default 5), "
        "prefer_domains (optional list of preferred domains for higher ranking), "
        "fetch_top_n (optional, fetch full page content for top N results, default 0)."
    ),
    parameters=[
        ToolParam(name="query", type="string", description="Search query string", required=True),
        ToolParam(name="max_results", type="integer", description="Max results (1-10)", required=False),
        ToolParam(name="prefer_domains", type="array", description="Preferred domains for higher ranking (e.g. developer.hashicorp.com, nvd.nist.gov). Uses official Vault/CVE sources by default.", required=False),
        ToolParam(name="fetch_top_n", type="integer", description="If > 0, fetch full page content for the top N results (adds full_text field)", required=False),
    ],
    phase="meta",
)

TOOL_RUN_DATABASE_PIVOT = ToolDef(
    name="run_database_pivot",
    description=(
        "Connect to a DATABASE using discovered credentials and extract data. "
        "Use this IMMEDIATELY after finding DB credentials (from KV, env scan, "
        "or database_credential_harvest). Tests connection, checks SUPERUSER status, "
        "lists tables, and reads data. If connection succeeds, follow up with "
        "run_reverse_shell to execute OS commands on the database host. "
        "Params: host, port, user, password, db_name."
    ),
    parameters=[
        ToolParam(name="vault_addr", type="string", description="Vault URL", required=True),
        ToolParam(name="token", type="string", description="Vault token", required=False),
        ToolParam(name="params", type="object", description="Connection params: {host, port, user, password, db_name}", required=False),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_REVERSE_SHELL = ToolDef(
    name="run_reverse_shell",
    description=(
        "Execute OS commands on the DATABASE HOST via PostgreSQL COPY FROM PROGRAM. "
        "Requires database connection params (host, port, user, password, db_name) "
        "and SUPERUSER privilege. Use IMMEDIATELY after a successful database_pivot. "
        "Default command: whoami && id && uname -a. "
        "For a full reverse shell, set command to a bash/python reverse shell one-liner."
    ),
    parameters=[
        ToolParam(name="vault_addr", type="string", description="Vault URL", required=True),
        ToolParam(name="token", type="string", description="Vault token", required=False),
        ToolParam(name="params", type="object", description="Connection + command: {host, port, user, password, db_name, command}", required=False),
    ],
    phase="active",
    risk="destructive",
)

TOOL_RUN_VAULT_AGENT_SCAN = ToolDef(
    name="run_vault_agent_scan",
    description=(
        "Scan the LOCAL filesystem for Vault Agent / Sidecar configurations. "
        "Discovers HCL agent config files, parses auto_auth blocks, extracts "
        "cached tokens from file sinks, reads AppRole credential files, checks "
        "environment variables for VAULT_TOKEN, and identifies misconfigurations. "
        "USE THIS when you have local filesystem access to a host running Vault Agent."
    ),
    parameters=[
        ToolParam("path", "string",
                  "Directory or file to scan (default: current directory)"),
        ToolParam("vault_addr", "string",
                  "Vault address for optional token validation"),
        ToolParam("validate_tokens", "boolean",
                  "Live-validate discovered tokens (default: false)"),
        ToolParam("max_file_size_mb", "integer",
                  "Max file size in MB (default: 5)"),
    ],
    phase="hijack",
    risk="read_only",
)

TOOL_RUN_APPROLE_EXPLOIT = ToolDef(
    name="run_approle_exploit",
    description=(
        "Audit and exploit Vault AppRole auth method configurations. Audits role "
        "settings for dangerous configs (bind_secret_id=false, unlimited uses, "
        "missing CIDR restrictions). Tests bind_secret_id bypass (empty secret_id), "
        "CIDR bypass via X-Forwarded-For, and performs direct login attempts. "
        "STATE-CHANGING: creates real Vault tokens on successful login."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token for role config reads"),
        ToolParam("mode", "string", "'audit' (default) or 'exploit'", enum=["audit", "exploit"]),
        ToolParam("role_id", "string", "Known AppRole role_id for exploit mode"),
        ToolParam("secret_id", "string", "Known AppRole secret_id for login"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_RAFT_EXPLOIT = ToolDef(
    name="run_raft_exploit",
    description=(
        "Exploit Vault Raft storage. In API mode (token provided), reads raft "
        "cluster configuration, downloads snapshots containing ALL secrets, checks "
        "autopilot. In filesystem mode (path provided), parses raft.db SQLite "
        "database, extracts log entries, reads peers.json. USE THIS when you have "
        "a high-privilege token or local filesystem access to Vault's data directory."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token for API-based access"),
        ToolParam("data_path", "string", "Local path to Vault data directory for filesystem mode"),
        ToolParam("mode", "string", "'api' (default), 'filesystem', or 'both'"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="destructive",
)

TOOL_RUN_JWT_OIDC_EXPLOIT = ToolDef(
    name="run_jwt_oidc_exploit",
    description=(
        "Audit and exploit Vault JWT/OIDC auth methods. Reads auth config "
        "(OIDC discovery URL, bound_issuer, JWKS), fetches OIDC discovery "
        "documents and JWKS keys, audits role bound_claims for weaknesses, "
        "detects algorithm confusion (alg:none, RS256→HS256), and tests login "
        "bypasses. USE THIS when JWT/OIDC auth methods are enabled."
    ),
    parameters=[
        ToolParam("vault_addr", "string", "Target Vault URL", required=True),
        ToolParam("token", "string", "Vault token (optional for config reads)"),
        ToolParam("test_login", "boolean", "Test login bypass techniques (default: false, STATE_CHANGING)"),
        ToolParam("jwt", "string", "JWT to test for login (optional)"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_KUBERNETES_AUTH_EXPLOIT = ToolDef(
    name="run_kubernetes_auth_exploit",
    description=(
        "Exploit Vault Kubernetes auth configurations. Decodes service account "
        "JWTs, discovers auth mounts, extracts configs (issuer, disable flags), "
        "analyzes role-to-SA bindings, and attempts login with discovered "
        "credentials. Includes CVE-2023-46835 exploit. STATE-CHANGING: "
        "creates real Vault tokens via K8s auth. USE THIS when you have access "
        "to a Kubernetes pod or the K8s auth method is enabled."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token (optional for config reads)"),
        ToolParam("jwt", "string",
                  "K8s service account JWT (auto-discovers if omitted)"),
        ToolParam("namespace", "string",
                  "Vault namespace"),
        ToolParam("target_roles", "array",
                  "Specific K8s auth roles to target"),
        ToolParam("exploit_cve", "boolean",
                  "Attempt CVE-2023-46835 exploit (default: true)"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_PKI_EXPLOIT = ToolDef(
    name="run_pki_exploit",
    description=(
        "Audit and exploit Vault PKI Secrets Engine. In 'audit' mode (default), "
        "downloads and analyzes CA certificates, CRLs, performs deep role audits "
        "flagging dangerous configurations (allow_any_name, wildcard certs, IP SANs, "
        "enforce_hostnames=false, etc). In 'operate' mode, issues test certificates "
        "(PoC). USE THIS when the token has pki/* capabilities."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token", required=True),
        ToolParam("mode", "string",
                  "Operation mode: 'audit' (default) or 'operate'",
                  enum=["audit", "operate"]),
        ToolParam("mount_path", "string",
                  "Specific PKI mount path (auto-discovers if omitted)"),
        ToolParam("role_name", "string",
                  "Specific PKI role name to target"),
        ToolParam("common_name", "string",
                  "Common name for cert issuance PoC (default: test.local)"),
        ToolParam("issue_test_cert", "boolean",
                  "Issue a test certificate (STATE_CHANGING, default: false)"),
        ToolParam("namespace", "string", "Vault namespace"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_RUN_TRANSIT_EXPLOIT = ToolDef(
    name="run_transit_exploit",
    description=(
        "Audit and exploit Vault Transit Secrets Engine. In 'audit' mode (default), "
        "extracts key metadata, finds exportable keys, and flags misconfigurations. "
        "In 'operate' mode, performs encryption/decryption PoC, datakey generation, "
        "HMAC/sign operations, and key rotation. USE THIS when the token has "
        "transit/* capabilities."
    ),
    parameters=[
        ToolParam("vault_addr", "string",
                  "Target Vault URL", required=True),
        ToolParam("token", "string",
                  "Vault token", required=True),
        ToolParam("mode", "string",
                  "Operation mode: 'audit' (default) or 'operate'",
                  enum=["audit", "operate"]),
        ToolParam("mount_path", "string",
                  "Specific transit mount path (auto-discovers if omitted)"),
        ToolParam("key_name", "string",
                  "Specific key name to target"),
        ToolParam("operations", "array",
                  "Specific operations: encrypt, decrypt, datakey, hmac, rotate"),
        ToolParam("namespace", "string", "Vault namespace"),
        ToolParam("exploit_cve", "boolean",
                  "Test CVE-2022-41316 (default: true)"),
    ],
    phase="active",
    risk="state_changing",
)

TOOL_DECODE_GENERATE_ROOT_OTP = ToolDef(
    name="decode_generate_root_otp",
    description=(
        "Decode a Vault generate-root OTP + encoded_token into a ROOT TOKEN. "
        "This is a CLIENT-SIDE operation — no Vault API call or token needed. "
        "Use this AFTER calling sys/generate-root/attempt (gets OTP + nonce) "
        "and sys/generate-root/update with unseal key (gets encoded_token). "
        "The otp_length comes from the attempt response's 'otp_length' field. "
        "For Vault >= 1.15 (otp_length > 0): OTP is used as raw bytes, "
        "encoded_token is base64-decoded, then XORed to produce the root token. "
        "IMPORTANT: After decoding, use the root token with run_capability_audit "
        "to verify it has root policies."
    ),
    parameters=[
        ToolParam(name="encoded_token", type="string",
                  description="The encoded_token from sys/generate-root/update response", required=True),
        ToolParam(name="otp", type="string",
                  description="The OTP from sys/generate-root/attempt response", required=True),
        ToolParam(name="otp_length", type="integer",
                  description="The otp_length from sys/generate-root/attempt response (default 0 = legacy)", required=False),
    ],
    phase="active",
    risk="state_changing",
)

# ── Domain-to-tool mapping for specialist agents ──────────────────────────
# Maps every MCP tool name to the domain(s) it serves.  ``"*"`` means the
# tool is universal — available to every specialist regardless of domain.
# Used by :class:`AttackOrchestrator` to decompose plans and by
# :class:`SpecialistAgent` to build its filtered tool list.

TOOL_DOMAIN_MAP: dict[str, set[str]] = {
    # ── Recon — typically run once, assigned to general ────────────────
    "run_unauthenticated_recon":     {"general"},
    "run_hijack_scan":               {"general"},
    "run_env_scan":                  {"general"},
    "run_vault_agent_scan":          {"general"},
    "search_to_actions":             {"general"},
    "set_evasion_profile":           {"general"},

    # ── Audit — token domain ───────────────────────────────────────────
    "run_capability_audit":          {"token"},
    "run_priv_esc_scan":             {"token"},
    "run_policy_auditor":            {"token"},
    "read_single_policy":            {"token"},
    "run_auth_config_audit":         {"token", "cloud"},

    # ── Audit — secrets domain ─────────────────────────────────────────
    "run_kv_enumeration":            {"secrets"},
    "run_ttl_audit":                 {"secrets", "general"},

    # ── Active execution — domain-specific ─────────────────────────────
    "run_privilege_escalation":      {"token"},
    "run_jwt_oidc_exploit":          {"token"},
    "run_approle_exploit":           {"token"},
    "run_kubernetes_auth_exploit":   {"token"},
    "run_secret_exfiltration":       {"secrets"},
    "run_database_credential_harvest":{"database"},
    "run_cloud_key_exfiltration":    {"cloud"},
    "run_raft_exploit":              {"secrets"},
    "run_pki_exploit":               {"secrets"},
    "run_transit_exploit":           {"secrets"},

    # ── Raw API — broad access, available to most domains ─────────────
    "run_raw_vault_request":         {"token", "secrets", "database",
                                       "cloud", "persistence", "seal",
                                       "pivot", "general"},

    # ── Active module gateway — domain filtering at runtime via registry
    "list_active_modules":           {"*"},
    "run_active_module":             {"*"},
    "run_aws_auth_login":            {"cloud"},

    # ── Universal — all specialists ────────────────────────────────────
    "web_search":                    {"*"},
    "get_findings":                  {"*"},
    "get_risk_score":                {"*"},
    "refresh_nvd_cache":             {"*"},

    # ── Security MCP operations — domain-specific ──────────────────────
    "run_compliance_check":          {"general"},
    "run_network_probe":             {"general"},
    "run_audit_log_scan":            {"general"},
    "run_container_scan":            {"general"},
    "get_threat_intel":              {"general"},

    # ── Reporting / notifications — universal ─────────────────────────
    "export_full_report":            {"*"},
    "send_notification":             {"*"},
    "generate_diff_report":          {"*"},
    "get_fix_commands":              {"*"},
    "decode_generate_root_otp":      {"*"},
    "run_database_pivot":            {"database"},
    "run_reverse_shell":             {"payload"},
}

# Tools that are always available regardless of domain.
UNIVERSAL_TOOL_NAMES: set[str] = {
    name for name, domains in TOOL_DOMAIN_MAP.items() if "*" in domains
}


# ── Master registry ──────────────────────────────────────────────────────

ALL_TOOLS: list[ToolDef] = [
    TOOL_RUN_RECON,
    TOOL_RUN_HIJACK_SCAN,
    TOOL_RUN_ENV_SCAN,
    TOOL_RUN_CAPABILITY_AUDIT,
    TOOL_RUN_PRIV_ESC_SCAN,
    TOOL_RUN_KV_ENUMERATION,
    TOOL_RUN_TTL_AUDIT,
    TOOL_RUN_AUTH_CONFIG_AUDIT,
    TOOL_RUN_POLICY_AUDITOR,
    TOOL_READ_SINGLE_POLICY,
    TOOL_RUN_RAW_VAULT_REQUEST,
    TOOL_RUN_PRIVILEGE_ESCALATION,
    TOOL_RUN_SECRET_EXFILTRATION,
    TOOL_RUN_DATABASE_CREDENTIAL_HARVEST,
    TOOL_RUN_CLOUD_KEY_EXFILTRATION,
    TOOL_LIST_ACTIVE_MODULES,
    TOOL_RUN_ACTIVE_MODULE,
    TOOL_RUN_AWS_AUTH_LOGIN,
    TOOL_GET_FINDINGS,
    TOOL_GET_RISK_SCORE,
    TOOL_REFRESH_NVD_CACHE,
    TOOL_WEB_SEARCH,
    TOOL_RUN_DATABASE_PIVOT,
    TOOL_RUN_REVERSE_SHELL,
    TOOL_RUN_VAULT_AGENT_SCAN,
    TOOL_RUN_RAFT_EXPLOIT,
    TOOL_RUN_APPROLE_EXPLOIT,
    TOOL_RUN_JWT_OIDC_EXPLOIT,
    TOOL_RUN_KUBERNETES_AUTH_EXPLOIT,
    TOOL_RUN_PKI_EXPLOIT,
    TOOL_RUN_TRANSIT_EXPLOIT,
    TOOL_DECODE_GENERATE_ROOT_OTP,
    TOOL_RUN_COMPLIANCE_CHECK,
    TOOL_RUN_NETWORK_PROBE,
    TOOL_EXPORT_FULL_REPORT,
    TOOL_SEND_NOTIFICATION,
    TOOL_RUN_AUDIT_LOG_SCAN,
    TOOL_RUN_CONTAINER_SCAN,
    TOOL_GET_THREAT_INTEL,
    TOOL_GENERATE_DIFF_REPORT,
    TOOL_GET_FIX_COMMANDS,
    TOOL_SEARCH_TO_ACTIONS,
    TOOL_SET_PROFILE,
]


def get_tool_by_name(name: str) -> Optional[ToolDef]:
    for tool in ALL_TOOLS:
        if tool.name == name:
            return tool
    return None


def tools_by_phase(phase: str) -> list[ToolDef]:
    return [t for t in ALL_TOOLS if t.phase == phase]
