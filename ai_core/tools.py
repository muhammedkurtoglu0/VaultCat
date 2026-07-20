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

TOOL_WEB_SEARCH = ToolDef(
    name="web_search",
    description=(
        "Search the web for Vault CVE details, exploit techniques, error message "
        "solutions, and configuration references. Results are cached for 24 hours. "
        "Use this when you encounter an unknown CVE, error code, or need exploit "
        "documentation. Parameters: query (search string), max_results (1-10, default 5)."
    ),
    parameters=[
        ToolParam(name="query", type="string", description="Search query string", required=True),
        ToolParam(name="max_results", type="integer", description="Max results (1-10)", required=False),
    ],
    phase="meta",
)

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
    TOOL_GET_FINDINGS,
    TOOL_GET_RISK_SCORE,
    TOOL_REFRESH_NVD_CACHE,
    TOOL_WEB_SEARCH,
]


def get_tool_by_name(name: str) -> Optional[ToolDef]:
    for tool in ALL_TOOLS:
        if tool.name == name:
            return tool
    return None


def tools_by_phase(phase: str) -> list[ToolDef]:
    return [t for t in ALL_TOOLS if t.phase == phase]
