"""Vault Attack Technique Knowledge Base — structured attack patterns for the mutation engine.

Each technique encodes:
- **preconditions**: What must be true (token power, accessible paths, findings)
- **success_indicators**: How to know if the technique succeeded
- **fallback_chain**: What to try if this fails (ordered list of technique IDs)
- **generates**: What new assets this creates (token, credential, access)
- **risk_impact**: (stealth_cost, impact_reward) tuple for scoring

The mutation engine uses this KB to:
1. **Generate proactive paths** — based on current assets, not just failures
2. **Score and rank paths** — probability × impact
3. **Chain techniques** — follow fallback chains automatically
4. **Learn** — track success/failure per technique to adjust scoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TechniqueDomain(str, Enum):
    TOKEN = "token"
    SECRETS = "secrets"
    DATABASE = "database"
    CLOUD = "cloud"
    PERSISTENCE = "persistence"
    PIVOT = "pivot"
    AUTH = "auth"
    GENERAL = "general"


class TechniquePhase(str, Enum):
    RECON = "recon"
    AUDIT = "audit"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    EXFIL = "exfil"


class TokenPower(str, Enum):
    ROOT = "root"
    SUDO = "sudo"
    HIGH = "high"
    ELEVATED = "elevated"
    USER = "user"
    RESTRICTED = "restricted"
    NONE = "none"


# ---------------------------------------------------------------------------
# Technique definition
# ---------------------------------------------------------------------------


@dataclass
class AttackTechnique:
    """A single Vault attack technique with preconditions and fallback chain."""

    technique_id: str                    # unique kebab-case ID
    name: str                            # human-readable name
    description: str                     # what this technique does
    domain: TechniqueDomain
    phase: TechniquePhase
    tool: str                            # primary MCP tool to execute
    params_template: dict[str, Any] = field(default_factory=dict)

    # ── precondition logic ──────────────────────────────────────────────
    min_token_power: TokenPower = TokenPower.NONE
    requires_authenticated: bool = False
    requires_findings: list[str] = field(default_factory=list)  # finding title substrings
    requires_credentials: list[str] = field(default_factory=list)  # cred_type: db_conn, approle_role_id, etc.
    requires_paths_accessible: list[str] = field(default_factory=list)  # e.g. "sys/policies", "secret/"
    blocked_by_findings: list[str] = field(default_factory=list)  # finding titles that block this

    # ── outcomes ────────────────────────────────────────────────────────
    success_indicators: list[str] = field(default_factory=list)  # strings in result
    generates_tokens: bool = False
    generates_credentials: bool = False
    generates_access: list[str] = field(default_factory=list)  # paths unlocked

    # ── scoring ─────────────────────────────────────────────────────────
    stealth_cost: int = 3          # 1=completely stealth, 5=very noisy
    impact_reward: int = 5         # 1=minor info, 5=full compromise
    base_success_probability: float = 0.5  # 0.0-1.0, adjusted by tracking

    # ── chaining ────────────────────────────────────────────────────────
    fallback_chain: list[str] = field(default_factory=list)  # technique_ids to try on failure
    followup_techniques: list[str] = field(default_factory=list)  # technique_ids to try on success
    prerequisite_techniques: list[str] = field(default_factory=list)  # must succeed before this

    # ── risk ────────────────────────────────────────────────────────────
    risk_level: str = "read_only"  # read_only | state_changing | destructive
    is_destructive: bool = False
    requires_confirmation: bool = False


# ---------------------------------------------------------------------------
# Technique scoring engine
# ---------------------------------------------------------------------------


@dataclass
class TechniqueScore:
    """Runtime score for a technique, adjusted by tracking data."""

    technique_id: str
    adjusted_probability: float     # base × success_tracking_factor
    expected_value: float           # adjusted_probability × impact_reward
    attempts: int = 0
    successes: int = 0
    last_used: float = 0.0          # timestamp
    cooldown_until: float = 0.0     # don't retry until this timestamp


class TechniqueScorer:
    """Tracks success/failure per technique to adjust scoring dynamically."""

    def __init__(self):
        self._scores: dict[str, TechniqueScore] = {}
        self._cooldown_seconds: float = 30.0  # base cooldown after failure
        self._cooldown_multiplier: float = 2.0  # multiply cooldown per consecutive failure

    def get_score(self, technique: AttackTechnique) -> TechniqueScore:
        """Get or create a score entry for a technique."""
        if technique.technique_id not in self._scores:
            self._scores[technique.technique_id] = TechniqueScore(
                technique_id=technique.technique_id,
                adjusted_probability=technique.base_success_probability,
                expected_value=technique.base_success_probability * technique.impact_reward,
            )
        return self._scores[technique.technique_id]

    def record_success(self, technique_id: str):
        """Record a successful execution — boost probability."""
        import time
        score = self._scores.get(technique_id)
        if not score:
            return
        score.attempts += 1
        score.successes += 1
        score.last_used = time.monotonic()
        score.cooldown_until = 0.0
        # Bayesian smoothing: (successes + 1) / (attempts + 2)
        score.adjusted_probability = (score.successes + 1) / (score.attempts + 2)
        score.expected_value = score.adjusted_probability * self._get_impact(technique_id)

    def record_failure(self, technique_id: str):
        """Record a failed execution — lower probability, set cooldown."""
        import time
        score = self._scores.get(technique_id)
        if not score:
            return
        score.attempts += 1
        score.last_used = time.monotonic()
        # Exponential backoff on repeated failures
        consecutive_fails = score.attempts - score.successes
        cooldown = self._cooldown_seconds * (self._cooldown_multiplier ** max(0, consecutive_fails - 1))
        score.cooldown_until = time.monotonic() + cooldown
        # Bayesian smoothing
        score.adjusted_probability = (score.successes + 1) / (score.attempts + 2)
        score.expected_value = score.adjusted_probability * self._get_impact(technique_id)

    def is_on_cooldown(self, technique_id: str) -> bool:
        """Check if a technique is on cooldown (too many recent failures)."""
        import time
        score = self._scores.get(technique_id)
        if not score:
            return False
        return time.monotonic() < score.cooldown_until

    def _get_impact(self, technique_id: str) -> int:
        """Look up the impact_reward for a technique."""
        tech = TECHNIQUE_REGISTRY.get(technique_id)
        return tech.impact_reward if tech else 5

    def status_summary(self) -> dict[str, Any]:
        return {
            tid: {
                "attempts": s.attempts,
                "successes": s.successes,
                "success_rate": round(s.successes / max(1, s.attempts), 2),
                "adjusted_probability": round(s.adjusted_probability, 2),
                "expected_value": round(s.expected_value, 1),
                "on_cooldown": self.is_on_cooldown(tid),
            }
            for tid, s in self._scores.items()
        }


# ---------------------------------------------------------------------------
# Attack Technique Registry — ALL known Vault attack patterns
# ---------------------------------------------------------------------------


def _build_registry() -> dict[str, AttackTechnique]:
    """Build the complete attack technique registry.

    Each technique encodes years of Vault red-team knowledge into
    structured preconditions, success indicators, and fallback chains.
    """
    T: dict[str, AttackTechnique] = {}

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 1: RECON — unauthenticated discovery
    # ═════════════════════════════════════════════════════════════════════

    T["recon.unauthenticated"] = AttackTechnique(
        technique_id="recon.unauthenticated",
        name="Full Unauthenticated Recon",
        description="Passive recon: TLS, health, version, fingerprint, UI, auth surface, CORS, headers, endpoints. No token needed.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.RECON,
        tool="run_unauthenticated_recon",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["status\": \"completed", "findings_count"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.95,
        followup_techniques=["recon.version_risk", "recon.auth_method_enum", "audit.seal_status"],
        risk_level="read_only",
    )

    T["recon.version_risk"] = AttackTechnique(
        technique_id="recon.version_risk",
        name="Version-based Vulnerability Lookup",
        description="Match Vault version against known CVEs. Auto-triggers web search for exploits.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.RECON,
        tool="run_unauthenticated_recon",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["version", "CVE-"],
        stealth_cost=1,
        impact_reward=4,
        base_success_probability=0.7,
        followup_techniques=["exploit.cve_poc", "recon.auth_method_enum"],
        risk_level="read_only",
    )

    T["recon.auth_method_enum"] = AttackTechnique(
        technique_id="recon.auth_method_enum",
        name="Auth Method Enumeration",
        description="Enumerate enabled auth methods (approle, userpass, ldap, jwt, oidc, kubernetes).",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.RECON,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "sys/auth"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["approle", "userpass", "ldap", "jwt", "oidc", "kubernetes"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.95,
        followup_techniques=["audit.auth_config", "exploit.approle_brute", "exploit.jwt_bypass"],
        risk_level="read_only",
    )

    T["recon.seal_status"] = AttackTechnique(
        technique_id="recon.seal_status",
        name="Seal Status Check",
        description="Check if Vault is sealed. Sealed Vault = unseal key opportunity.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.RECON,
        tool="run_active_module",
        params_template={"module_id": "vault_seal.seal_status"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["sealed", "unsealed"],
        stealth_cost=1,
        impact_reward=2,
        base_success_probability=0.95,
        followup_techniques=["exploit.unseal_vault"],
        risk_level="read_only",
    )

    T["recon.env_scan"] = AttackTechnique(
        technique_id="recon.env_scan",
        name="Environment & Token File Scan",
        description="Scan local environment and token files for leaked Vault config.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.RECON,
        tool="run_env_scan",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["VAULT_ADDR", "VAULT_TOKEN", "token_file"],
        generates_tokens=True,
        stealth_cost=1,
        impact_reward=4,
        base_success_probability=0.6,
        followup_techniques=["audit.capability", "audit.kv_enum"],
        risk_level="read_only",
    )

    T["recon.hijack_scan"] = AttackTechnique(
        technique_id="recon.hijack_scan",
        name="Credential Hijack Scan",
        description="Scan filesystem and git history for leaked Vault tokens, AppRole pairs, and secrets.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.RECON,
        tool="run_hijack_scan",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_tokens=True,
        generates_credentials=True,
        success_indicators=["finding", "token", "secret_id", "role_id"],
        stealth_cost=1,
        impact_reward=5,
        base_success_probability=0.5,
        followup_techniques=["audit.capability", "exploit.approle_login", "exploit.token_validate"],
        risk_level="read_only",
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 2: AUDIT — authenticated capability mapping
    # ═════════════════════════════════════════════════════════════════════

    T["audit.capability"] = AttackTechnique(
        technique_id="audit.capability",
        name="Token Capability Audit",
        description="Full capability audit: lookup-self, token capabilities, accessible paths, policies.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.AUDIT,
        tool="run_capability_audit",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["capabilities", "policies", "accessible_paths"],
        stealth_cost=1,
        impact_reward=4,
        base_success_probability=0.9,
        fallback_chain=["audit.restricted_token_probe"],
        followup_techniques=["audit.priv_esc_scan", "audit.policy_analyze", "audit.kv_enum"],
        risk_level="read_only",
    )

    T["audit.restricted_token_probe"] = AttackTechnique(
        technique_id="audit.restricted_token_probe",
        name="Restricted Token Path Probing",
        description="Token returns 403 on everything. Probe specific paths to discover narrow permissions.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.AUDIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "secret/"},
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["data", "lease_id"],
        generates_access=["discovered_paths"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.4,
        followup_techniques=["audit.token_factory", "audit.db_cred_reader", "audit.kv_enum"],
        risk_level="read_only",
    )

    T["audit.token_factory"] = AttackTechnique(
        technique_id="audit.token_factory",
        name="Token Factory Exploitation",
        description="Try creating child tokens. Some restricted tokens can only create new tokens.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.AUDIT,
        tool="run_raw_vault_request",
        params_template={
            "method": "POST", "path": "auth/token/create",
            "body": '{"policies": ["default"], "ttl": "1h", "display_name": "escalated"}',
        },
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["auth", "client_token"],
        stealth_cost=2,
        impact_reward=4,
        base_success_probability=0.3,
        fallback_chain=["audit.db_cred_reader", "audit.cubbyhole_probe"],
        followup_techniques=["audit.capability", "audit.priv_esc_scan"],
        risk_level="state_changing",
    )

    T["audit.db_cred_reader"] = AttackTechnique(
        technique_id="audit.db_cred_reader",
        name="Database Credential Reader",
        description="Try reading dynamic DB credentials. Common restricted token permission.",
        domain=TechniqueDomain.DATABASE,
        phase=TechniquePhase.AUDIT,
        tool="run_database_credential_harvest",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["credentials", "username", "password", "connection_string"],
        stealth_cost=1,
        impact_reward=5,
        base_success_probability=0.35,
        fallback_chain=["audit.cubbyhole_probe"],
        followup_techniques=["exploit.db_pivot", "exploit.db_exploit"],
        risk_level="state_changing",
    )

    T["audit.cubbyhole_probe"] = AttackTechnique(
        technique_id="audit.cubbyhole_probe",
        name="Cubbyhole Probe",
        description="Check cubbyhole — per-token storage that many restricted tokens can access.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.AUDIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "cubbyhole/"},
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["data"],
        stealth_cost=1,
        impact_reward=2,
        base_success_probability=0.3,
        risk_level="read_only",
    )

    T["audit.priv_esc_scan"] = AttackTechnique(
        technique_id="audit.priv_esc_scan",
        name="Privilege Escalation Path Scanner",
        description="Analyze token capabilities for known escalation paths (sudo, policy modification, token creation).",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.AUDIT,
        tool="run_priv_esc_scan",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["escalation_path", "sudo", "wildcard", "privilege"],
        stealth_cost=1,
        impact_reward=5,
        base_success_probability=0.5,
        fallback_chain=["audit.policy_analyze"],
        followup_techniques=["exploit.priv_esc_token", "exploit.policy_backdoor"],
        risk_level="read_only",
    )

    T["audit.kv_enum"] = AttackTechnique(
        technique_id="audit.kv_enum",
        name="KV Path Enumeration",
        description="Recursively enumerate KV v1/v2 paths to discover all accessible secrets.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.AUDIT,
        tool="run_kv_enumeration",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["paths", "secrets", "keys"],
        stealth_cost=1,
        impact_reward=4,
        base_success_probability=0.85,
        fallback_chain=["audit.raw_kv_probe"],
        followup_techniques=["exploit.secret_exfil", "exploit.db_pivot", "exploit.cloud_exfil"],
        risk_level="read_only",
    )

    T["audit.raw_kv_probe"] = AttackTechnique(
        technique_id="audit.raw_kv_probe",
        name="Raw KV API Probing",
        description="Probe KV paths directly via raw API — bypasses scanner limitations.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.AUDIT,
        tool="run_raw_vault_request",
        params_template={"method": "LIST", "path": "secret/metadata/"},
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["keys"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.5,
        followup_techniques=["exploit.secret_exfil"],
        risk_level="read_only",
    )

    T["audit.policy_analyze"] = AttackTechnique(
        technique_id="audit.policy_analyze",
        name="Policy Analysis",
        description="Audit all ACL policies for misconfigurations, wildcards, and escalation vectors.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.AUDIT,
        tool="run_policy_auditor",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["policy", "wildcard", "sudo", "misconfiguration"],
        stealth_cost=1,
        impact_reward=4,
        base_success_probability=0.7,
        followup_techniques=["exploit.policy_backdoor", "exploit.token_from_policy"],
        risk_level="read_only",
    )

    T["audit.ttl_governance"] = AttackTechnique(
        technique_id="audit.ttl_governance",
        name="TTL Governance Audit",
        description="Audit TTL settings for all mounted engines — find tokens/secrets that live too long.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.AUDIT,
        tool="run_ttl_audit",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["ttl", "max_lease", "governance"],
        stealth_cost=1,
        impact_reward=2,
        base_success_probability=0.9,
        followup_techniques=["exploit.token_from_policy"],
        risk_level="read_only",
    )

    T["audit.auth_config"] = AttackTechnique(
        technique_id="audit.auth_config",
        name="Auth Configuration Audit",
        description="Audit auth method configurations for weaknesses (no TLS, weak TTLs, unsecured endpoints).",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.AUDIT,
        tool="run_auth_config_audit",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        success_indicators=["auth", "misconfiguration", "weakness"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.8,
        followup_techniques=["exploit.approle_brute", "exploit.jwt_bypass", "exploit.k8s_exploit"],
        risk_level="read_only",
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 3: EXPLOIT — active privilege escalation & access
    # ═════════════════════════════════════════════════════════════════════

    T["exploit.priv_esc_token"] = AttackTechnique(
        technique_id="exploit.priv_esc_token",
        name="Privilege Escalation via Token Abuse",
        description="Autonomous privilege escalation: exploit sudo paths, policy loopholes, and token creation to gain higher privileges.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.EXPLOIT,
        tool="run_privilege_escalation",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["escalated", "root_token", "higher_privilege", "new_token"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.4,
        fallback_chain=["exploit.policy_backdoor", "exploit.approle_login"],
        followup_techniques=["exploit.secret_exfil", "exploit.db_harvest", "exploit.cloud_exfil",
                            "persist.audit_backdoor"],
        risk_level="state_changing",
        requires_confirmation=True,
    )

    T["exploit.policy_backdoor"] = AttackTechnique(
        technique_id="exploit.policy_backdoor",
        name="Policy Backdoor Injection",
        description="Create or modify ACL policies to grant sudo/root access. Requires policy write capability.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "privilege_escalation.token_abuse"},
        min_token_power=TokenPower.ELEVATED,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["policy", "created", "updated", "sudo"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.35,
        fallback_chain=["exploit.token_from_policy", "exploit.approle_login"],
        followup_techniques=["exploit.secret_exfil", "persist.audit_backdoor"],
        risk_level="state_changing",
        requires_confirmation=True,
    )

    T["exploit.token_from_policy"] = AttackTechnique(
        technique_id="exploit.token_from_policy",
        name="Token Creation from Policy",
        description="Create a new token with discovered policies attached. Exploit policy assignment loopholes.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.EXPLOIT,
        tool="run_raw_vault_request",
        params_template={
            "method": "POST", "path": "auth/token/create",
            "body": '{"policies": [], "ttl": "1h"}',
        },
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["auth", "client_token"],
        stealth_cost=2,
        impact_reward=3,
        base_success_probability=0.4,
        followup_techniques=["audit.capability", "exploit.priv_esc_token"],
        risk_level="state_changing",
    )

    T["exploit.approle_login"] = AttackTechnique(
        technique_id="exploit.approle_login",
        name="AppRole Authentication",
        description="Use discovered role_id + secret_id to authenticate and obtain a token.",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.EXPLOIT,
        tool="run_approle_exploit",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["approle_role_id", "approle_secret_id"],
        generates_tokens=True,
        success_indicators=["auth", "client_token", "token"],
        stealth_cost=2,
        impact_reward=4,
        base_success_probability=0.7,
        followup_techniques=["audit.capability", "audit.kv_enum", "exploit.priv_esc_token"],
        risk_level="state_changing",
    )

    T["exploit.approle_brute"] = AttackTechnique(
        technique_id="exploit.approle_brute",
        name="AppRole Brute Force / Bypass",
        description="Attempt AppRole auth bypass techniques: secret_id_accessor abuse, CIDR bypass, bind_secret_id misconfig.",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.EXPLOIT,
        tool="run_approle_exploit",
        min_token_power=TokenPower.RESTRICTED,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["bypass", "token", "authenticated"],
        stealth_cost=3,
        impact_reward=4,
        base_success_probability=0.2,
        followup_techniques=["audit.capability", "exploit.priv_esc_token"],
        risk_level="state_changing",
    )

    T["exploit.jwt_bypass"] = AttackTechnique(
        technique_id="exploit.jwt_bypass",
        name="JWT/OIDC Auth Bypass",
        description="Exploit JWT/OIDC misconfigurations: algorithm confusion, missing signature validation, kid injection.",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.EXPLOIT,
        tool="run_jwt_oidc_exploit",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_tokens=True,
        success_indicators=["bypass", "token", "jwt", "oidc", "authenticated"],
        stealth_cost=2,
        impact_reward=5,
        base_success_probability=0.15,
        fallback_chain=["exploit.k8s_exploit"],
        followup_techniques=["audit.capability", "exploit.priv_esc_token"],
        risk_level="state_changing",
    )

    T["exploit.k8s_exploit"] = AttackTechnique(
        technique_id="exploit.k8s_exploit",
        name="Kubernetes Auth Exploitation",
        description="Exploit Kubernetes auth method: stolen JWT, service account token reuse, namespace bypass.",
        domain=TechniqueDomain.AUTH,
        phase=TechniquePhase.EXPLOIT,
        tool="run_kubernetes_auth_exploit",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_tokens=True,
        success_indicators=["jwt", "kubernetes", "authenticated", "token"],
        stealth_cost=2,
        impact_reward=5,
        base_success_probability=0.2,
        followup_techniques=["audit.capability", "exploit.priv_esc_token"],
        risk_level="state_changing",
    )

    T["exploit.cve_poc"] = AttackTechnique(
        technique_id="exploit.cve_poc",
        name="CVE PoC Execution",
        description="Execute proof-of-concept exploit for a known CVE against the target Vault version.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.EXPLOIT,
        tool="run_raw_vault_request",
        params_template={"method": "POST", "path": "sys/PoC"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        success_indicators=["exploit", "CVE-", "vulnerable"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.15,
        risk_level="state_changing",
        requires_confirmation=True,
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 4: POST-EXPLOIT — secret exfiltration & lateral movement
    # ═════════════════════════════════════════════════════════════════════

    T["exploit.secret_exfil"] = AttackTechnique(
        technique_id="exploit.secret_exfil",
        name="Mass Secret Exfiltration",
        description="Dump all accessible secrets from KV engines. Use elevated token for maximum coverage.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.EXFIL,
        tool="run_secret_exfiltration",
        min_token_power=TokenPower.ELEVATED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["secrets", "exfiltrated", "leaked_payloads"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.8,
        fallback_chain=["exploit.targeted_exfil"],
        followup_techniques=["exploit.db_pivot", "exploit.cloud_exfil", "exploit.credential_pivot"],
        risk_level="read_only",
    )

    T["exploit.targeted_exfil"] = AttackTechnique(
        technique_id="exploit.targeted_exfil",
        name="Targeted Secret Exfiltration",
        description="Surgically extract specific high-value paths instead of mass dump. Quieter.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.EXFIL,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "secret/data/"},
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["data"],
        stealth_cost=2,
        impact_reward=3,
        base_success_probability=0.7,
        risk_level="read_only",
    )

    T["exploit.db_harvest"] = AttackTechnique(
        technique_id="exploit.db_harvest",
        name="Database Credential Harvest",
        description="Harvest dynamic database credentials from configured database secrets engines.",
        domain=TechniqueDomain.DATABASE,
        phase=TechniquePhase.EXPLOIT,
        tool="run_database_credential_harvest",
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["credentials", "username", "password", "connection_string"],
        stealth_cost=2,
        impact_reward=5,
        base_success_probability=0.6,
        followup_techniques=["exploit.db_pivot", "exploit.db_exploit"],
        risk_level="state_changing",
    )

    T["exploit.db_pivot"] = AttackTechnique(
        technique_id="exploit.db_pivot",
        name="Database Lateral Movement",
        description="Use harvested DB credentials to connect directly to the database and execute commands.",
        domain=TechniqueDomain.DATABASE,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_database_pivot",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["db_conn", "password"],
        generates_access=["database_shell", "os_shell"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.5,
        fallback_chain=["exploit.db_exploit"],
        followup_techniques=["exploit.reverse_shell", "exploit.raft_read", "exploit.cloud_metadata"],
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["exploit.db_exploit"] = AttackTechnique(
        technique_id="exploit.db_exploit",
        name="Database Direct Exploitation",
        description="Exploit database features (COPY FROM PROGRAM, xp_cmdshell, UDF) for code execution.",
        domain=TechniqueDomain.DATABASE,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_database_pivot",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["db_conn"],
        generates_access=["os_shell"],
        stealth_cost=5,
        impact_reward=5,
        base_success_probability=0.3,
        fallback_chain=["exploit.db_config_read"],
        followup_techniques=["exploit.reverse_shell", "exploit.raft_read"],
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["exploit.db_config_read"] = AttackTechnique(
        technique_id="exploit.db_config_read",
        name="Database Config Read",
        description="Read database engine configuration to extract connection strings for direct access.",
        domain=TechniqueDomain.DATABASE,
        phase=TechniquePhase.EXPLOIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "database/config/"},
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["connection_details", "plugin_name", "connection_url"],
        stealth_cost=1,
        impact_reward=3,
        base_success_probability=0.5,
        followup_techniques=["exploit.db_pivot"],
        risk_level="read_only",
    )

    T["exploit.reverse_shell"] = AttackTechnique(
        technique_id="exploit.reverse_shell",
        name="Reverse Shell via Database",
        description="Obtain OS reverse shell through database command execution.",
        domain=TechniqueDomain.PIVOT,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_reverse_shell",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["db_conn"],
        generates_access=["os_shell", "filesystem"],
        stealth_cost=5,
        impact_reward=5,
        base_success_probability=0.25,
        followup_techniques=["exploit.raft_read", "exploit.cloud_metadata", "exploit.ssh_steal"],
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["exploit.raft_read"] = AttackTechnique(
        technique_id="exploit.raft_read",
        name="Raft Storage Exfiltration",
        description="Read Vault's Raft storage directly from filesystem. Requires OS-level access.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raft_exploit",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_credentials=True,
        generates_tokens=True,
        success_indicators=["raft", "data", "secret", "extracted"],
        stealth_cost=5,
        impact_reward=5,
        base_success_probability=0.2,
        fallback_chain=["exploit.unseal_key_exfil"],
        risk_level="destructive",
        is_destructive=True,
    )

    T["exploit.unseal_key_exfil"] = AttackTechnique(
        technique_id="exploit.unseal_key_exfil",
        name="Unseal Key Exfiltration",
        description="Extract unseal keys from memory or filesystem. Requires OS-level access.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "unseal_key.exfiltration"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_access=["root_token"],
        success_indicators=["unseal", "key", "shamir", "recovery"],
        stealth_cost=5,
        impact_reward=5,
        base_success_probability=0.1,
        risk_level="destructive",
        is_destructive=True,
    )

    T["exploit.cloud_exfil"] = AttackTechnique(
        technique_id="exploit.cloud_exfil",
        name="Cloud Key Exfiltration",
        description="Exfiltrate cloud provider credentials stored in Vault (AWS, GCP, Azure).",
        domain=TechniqueDomain.CLOUD,
        phase=TechniquePhase.EXFIL,
        tool="run_cloud_key_exfiltration",
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["AWS", "GCP", "Azure", "access_key", "secret_key"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.5,
        fallback_chain=["exploit.cloud_pivot"],
        followup_techniques=["exploit.cloud_pivot", "exploit.credential_pivot"],
        risk_level="state_changing",
    )

    T["exploit.cloud_pivot"] = AttackTechnique(
        technique_id="exploit.cloud_pivot",
        name="Cloud Platform Pivot",
        description="Use exfiltrated cloud keys to pivot to cloud platform (STS, EC2, GCP, Azure).",
        domain=TechniqueDomain.CLOUD,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "cloud_pivot.exploit"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["api_key", "access_key"],
        generates_access=["cloud_console", "cloud_resources"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.4,
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["exploit.credential_pivot"] = AttackTechnique(
        technique_id="exploit.credential_pivot",
        name="External Platform Pivot",
        description="Pivot to external platforms using discovered credentials (GitHub, AWS, Stripe, SSH).",
        domain=TechniqueDomain.PIVOT,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "secret/"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["api_key", "password", "ssh_key"],
        success_indicators=["pivot", "external", "platform"],
        stealth_cost=2,
        impact_reward=5,
        base_success_probability=0.3,
        risk_level="destructive",
        requires_confirmation=True,
    )

    T["exploit.cloud_metadata"] = AttackTechnique(
        technique_id="exploit.cloud_metadata",
        name="Cloud Metadata Service Exploitation",
        description="Query cloud metadata endpoints from compromised host (AWS 169.254.169.254, GCP, Azure).",
        domain=TechniqueDomain.CLOUD,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "secret/"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_credentials=True,
        success_indicators=["metadata", "iam", "credentials"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.3,
        risk_level="destructive",
        is_destructive=True,
    )

    T["exploit.ssh_steal"] = AttackTechnique(
        technique_id="exploit.ssh_steal",
        name="SSH Key Theft & Lateral Movement",
        description="Steal SSH keys from compromised host for lateral movement.",
        domain=TechniqueDomain.PIVOT,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raw_vault_request",
        params_template={"method": "GET", "path": "secret/"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["ssh_key"],
        generates_access=["ssh_access", "new_hosts"],
        stealth_cost=3,
        impact_reward=4,
        base_success_probability=0.35,
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["exploit.unseal_vault"] = AttackTechnique(
        technique_id="exploit.unseal_vault",
        name="Unseal Vault with Captured Keys",
        description="Use captured unseal keys (Shamir shares) to unseal a sealed Vault.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "vault_seal.unseal_vault"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["unseal_key", "shamir_share"],
        generates_access=["unsealed_vault"],
        success_indicators=["unsealed", "seal_status", "progress"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.6,
        followup_techniques=["exploit.generate_root", "audit.capability"],
        risk_level="state_changing",
        requires_confirmation=True,
    )

    T["exploit.generate_root"] = AttackTechnique(
        technique_id="exploit.generate_root",
        name="Generate Root Token from Unseal Keys",
        description="Use unseal keys + generate-root operation to derive a root token.",
        domain=TechniqueDomain.TOKEN,
        phase=TechniquePhase.EXPLOIT,
        tool="decode_generate_root_otp",
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        requires_credentials=["unseal_key", "otp"],
        generates_tokens=True,
        success_indicators=["root_token", "encoded_token"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.5,
        followup_techniques=["exploit.secret_exfil", "persist.audit_backdoor"],
        risk_level="state_changing",
        requires_confirmation=True,
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 5: PERSISTENCE
    # ═════════════════════════════════════════════════════════════════════

    T["persist.audit_backdoor"] = AttackTechnique(
        technique_id="persist.audit_backdoor",
        name="Audit Backdoor",
        description="Disable or tamper with audit logging to hide malicious activity.",
        domain=TechniqueDomain.PERSISTENCE,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "audit_backdoor.disable"},
        min_token_power=TokenPower.SUDO,
        requires_authenticated=True,
        success_indicators=["audit", "disabled", "backdoor"],
        stealth_cost=4,
        impact_reward=4,
        base_success_probability=0.5,
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["persist.multi_backdoor"] = AttackTechnique(
        technique_id="persist.multi_backdoor",
        name="Multi-Layer Persistence",
        description="Install multiple persistence mechanisms: new auth methods, periodic tokens, wrapped secrets.",
        domain=TechniqueDomain.PERSISTENCE,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "multi_persistence.backdoor"},
        min_token_power=TokenPower.SUDO,
        requires_authenticated=True,
        success_indicators=["persistence", "backdoor", "installed"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.4,
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    T["persist.token_backdoor"] = AttackTechnique(
        technique_id="persist.token_backdoor",
        name="Periodic Token Backdoor",
        description="Create long-lived tokens with orphan status — survive token revocation sweeps.",
        domain=TechniqueDomain.PERSISTENCE,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raw_vault_request",
        params_template={
            "method": "POST", "path": "auth/token/create-orphan",
            "body": '{"policies": ["root"], "ttl": "87600h", "display_name": "backup-service"}',
        },
        min_token_power=TokenPower.SUDO,
        requires_authenticated=True,
        generates_tokens=True,
        success_indicators=["auth", "client_token"],
        stealth_cost=3,
        impact_reward=5,
        base_success_probability=0.45,
        risk_level="destructive",
        is_destructive=True,
        requires_confirmation=True,
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 6: SPECIALIZED SECRETS ENGINE EXPLOITS
    # ═════════════════════════════════════════════════════════════════════

    T["exploit.pki_exploit"] = AttackTechnique(
        technique_id="exploit.pki_exploit",
        name="PKI Engine Exploitation",
        description="Exploit PKI secrets engine: issue unauthorized certs, extract CA private key, rogue CA injection.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.EXPLOIT,
        tool="run_pki_exploit",
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["certificate", "private_key", "CA", "issue"],
        stealth_cost=2,
        impact_reward=4,
        base_success_probability=0.3,
        followup_techniques=["exploit.credential_pivot"],
        risk_level="state_changing",
    )

    T["exploit.transit_exploit"] = AttackTechnique(
        technique_id="exploit.transit_exploit",
        name="Transit Engine Exploitation",
        description="Exploit transit engine: key recovery, encryption oracle abuse, key rotation bypass.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.EXPLOIT,
        tool="run_transit_exploit",
        min_token_power=TokenPower.USER,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["key", "decrypt", "transit", "convergent"],
        stealth_cost=2,
        impact_reward=3,
        base_success_probability=0.25,
        risk_level="state_changing",
    )

    T["exploit.raft_storage_exploit"] = AttackTechnique(
        technique_id="exploit.raft_storage_exploit",
        name="Raft Storage Direct Exploitation",
        description="Exploit Raft storage layer: snapshot extraction, FSM data recovery, log poisoning.",
        domain=TechniqueDomain.SECRETS,
        phase=TechniquePhase.POST_EXPLOIT,
        tool="run_raft_exploit",
        min_token_power=TokenPower.ELEVATED,
        requires_authenticated=True,
        generates_credentials=True,
        success_indicators=["raft", "snapshot", "fsm", "data"],
        stealth_cost=4,
        impact_reward=5,
        base_success_probability=0.15,
        risk_level="destructive",
        is_destructive=True,
    )

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 7: AGENT / SIDECAR ATTACKS
    # ═════════════════════════════════════════════════════════════════════

    T["exploit.agent_sidecar"] = AttackTechnique(
        technique_id="exploit.agent_sidecar",
        name="Vault Agent Sidecar Attack",
        description="Attack Vault Agent sidecar: token interception, auto-auth abuse, template injection.",
        domain=TechniqueDomain.GENERAL,
        phase=TechniquePhase.EXPLOIT,
        tool="run_active_module",
        params_template={"module_id": "agent_sidecar_attack.scan"},
        min_token_power=TokenPower.NONE,
        requires_authenticated=False,
        generates_tokens=True,
        success_indicators=["agent", "sidecar", "token", "auto_auth"],
        stealth_cost=2,
        impact_reward=4,
        base_success_probability=0.3,
        risk_level="read_only",
    )

    return T


# ── Global registry ──────────────────────────────────────────────────────────

TECHNIQUE_REGISTRY: dict[str, AttackTechnique] = _build_registry()

# Techniques grouped by domain for quick lookup
TECHNIQUES_BY_DOMAIN: dict[TechniqueDomain, list[AttackTechnique]] = {}
for _t in TECHNIQUE_REGISTRY.values():
    TECHNIQUES_BY_DOMAIN.setdefault(_t.domain, []).append(_t)

# Techniques grouped by phase
TECHNIQUES_BY_PHASE: dict[TechniquePhase, list[AttackTechnique]] = {}
for _t in TECHNIQUE_REGISTRY.values():
    TECHNIQUES_BY_PHASE.setdefault(_t.phase, []).append(_t)


# ---------------------------------------------------------------------------
# Proactive path generator — suggest techniques based on current state
# ---------------------------------------------------------------------------


def suggest_techniques(
    token_power: TokenPower = TokenPower.NONE,
    is_authenticated: bool = False,
    available_credentials: list[str] | None = None,
    findings: list[dict[str, Any]] | None = None,
    accessible_paths: list[str] | None = None,
    phase: TechniquePhase | None = None,
    exclude_techniques: set[str] | None = None,
    scorer: TechniqueScorer | None = None,
    max_suggestions: int = 6,
) -> list[tuple[AttackTechnique, float]]:
    """Suggest the best techniques to try given the current pentest state.

    Returns techniques sorted by expected_value (highest first),
    filtered by preconditions and cooldown status.

    Parameters
    ----------
    token_power : TokenPower
        Power level of the best available token.
    is_authenticated : bool
        Whether we have a valid authenticated session.
    available_credentials : list[str] | None
        Types of credentials available (e.g. ["db_conn", "api_key"]).
    findings : list[dict] | None
        Current pentest findings to check prerequisite findings.
    accessible_paths : list[str] | None
        Paths known to be accessible (e.g. ["secret/", "sys/policies"]).
    phase : TechniquePhase | None
        Limit to techniques in this phase. None = all phases.
    exclude_techniques : set[str] | None
        Technique IDs to exclude (already tried, blacklisted).
    scorer : TechniqueScorer | None
        For cooldown and adjusted probability checks.
    max_suggestions : int
        Maximum number of techniques to return.
    """
    available_creds = set(available_credentials or [])
    finding_titles = {f.get("title", "").lower() for f in (findings or [])}
    paths = set(accessible_paths or [])
    excluded = exclude_techniques or set()
    _scorer = scorer or TechniqueScorer()

    scored: list[tuple[AttackTechnique, float]] = []

    for tech in TECHNIQUE_REGISTRY.values():
        if tech.technique_id in excluded:
            continue
        if phase and tech.phase != phase:
            continue
        if _scorer.is_on_cooldown(tech.technique_id):
            continue

        # ── Check preconditions ──────────────────────────────────────────
        if not _check_preconditions(
            tech, token_power, is_authenticated, available_creds,
            finding_titles, paths,
        ):
            continue

        # ── Score the technique ──────────────────────────────────────────
        score = _scorer.get_score(tech)
        scored.append((tech, score.expected_value))

    # Sort by expected_value descending, then impact_reward descending
    scored.sort(key=lambda x: (x[1], x[0].impact_reward), reverse=True)

    return scored[:max_suggestions]


def _check_preconditions(
    tech: AttackTechnique,
    token_power: TokenPower,
    is_authenticated: bool,
    available_creds: set[str],
    finding_titles: set[str],
    accessible_paths: set[str],
) -> bool:
    """Check if a technique's preconditions are met."""

    # Token power check
    if tech.requires_authenticated and not is_authenticated:
        return False

    power_rank = {
        TokenPower.ROOT: 5, TokenPower.SUDO: 4, TokenPower.HIGH: 3,
        TokenPower.ELEVATED: 3, TokenPower.USER: 2, TokenPower.RESTRICTED: 1,
        TokenPower.NONE: 0,
    }
    if power_rank.get(token_power, 0) < power_rank.get(tech.min_token_power, 0):
        return False

    # Credential type check
    if tech.requires_credentials:
        if not any(cred in available_creds for cred in tech.requires_credentials):
            return False

    # Required findings check
    if tech.requires_findings:
        if not any(req.lower() in title for req in tech.requires_findings for title in finding_titles):
            return False

    # Blocked by findings check
    if tech.blocked_by_findings:
        if any(block.lower() in title for block in tech.blocked_by_findings for title in finding_titles):
            return False

    # Path accessibility check
    if tech.requires_paths_accessible:
        if not any(req in path for req in tech.requires_paths_accessible for path in accessible_paths):
            return False

    return True


# ---------------------------------------------------------------------------
# Attack chain builder — connect techniques into multi-step attack plans
# ---------------------------------------------------------------------------


def build_attack_chain(
    entry_technique_id: str,
    token_power: TokenPower = TokenPower.NONE,
    is_authenticated: bool = False,
    available_credentials: list[str] | None = None,
    findings: list[dict[str, Any]] | None = None,
    accessible_paths: list[str] | None = None,
    max_depth: int = 5,
) -> list[AttackTechnique]:
    """Build a multi-step attack chain starting from an entry technique.

    Follows followup_techniques links, checking preconditions at each step.
    Returns the full chain from entry to deepest reachable technique.
    """
    chain: list[AttackTechnique] = []
    seen: set[str] = set()
    available_creds = list(available_credentials or [])
    current_paths = list(accessible_paths or [])

    entry = TECHNIQUE_REGISTRY.get(entry_technique_id)
    if not entry:
        return chain

    current = entry
    depth = 0

    while current and depth < max_depth:
        if current.technique_id in seen:
            break
        seen.add(current.technique_id)
        chain.append(current)

        # Simulate success — update state
        if current.generates_tokens:
            token_power = max(token_power, TokenPower.ELEVATED, key=lambda p: {
                TokenPower.ROOT: 5, TokenPower.SUDO: 4, TokenPower.HIGH: 3,
                TokenPower.ELEVATED: 3, TokenPower.USER: 2, TokenPower.RESTRICTED: 1,
                TokenPower.NONE: 0,
            }.get(p, 0))
            is_authenticated = True
        if current.generates_credentials:
            available_creds.append("api_key")
        if current.generates_access:
            current_paths.extend(current.generates_access)

        # Find best follow-up technique
        if current.followup_techniques:
            candidates = suggest_techniques(
                token_power=token_power,
                is_authenticated=is_authenticated,
                available_credentials=available_creds,
                findings=findings,
                accessible_paths=current_paths,
                exclude_techniques=seen,
                max_suggestions=1,
            )
            current = candidates[0][0] if candidates else None
        else:
            break

        depth += 1

    return chain


# ---------------------------------------------------------------------------
# State snapshot for mutation decisions
# ---------------------------------------------------------------------------


def capture_pentest_state(
    vault_addr: str = "",
    token_power_override: TokenPower | None = None,
) -> dict[str, Any]:
    """Capture the current pentest state for the mutation engine.

    Pulls from DynamicCredentialStore, global findings, and session.
    Returns a structured dict the mutation engine can use for decisions.
    """
    state: dict[str, Any] = {
        "vault_addr": vault_addr,
        "token_power": TokenPower.NONE.value,
        "is_authenticated": False,
        "available_credentials": [],
        "accessible_paths": [],
        "findings_summary": [],
        "high_value_targets": [],
    }

    try:
        from ai_core.dynamic_session import global_store

        # Best token
        best = global_store.get_best_token()
        if best:
            state["is_authenticated"] = True
            if token_power_override:
                state["token_power"] = token_power_override.value
            else:
                state["token_power"] = best.power_level
            state["token_preview"] = best.token

        # Available credential types
        state["available_credentials"] = [
            c.cred_type for c in global_store.credentials.values()
        ]
        state["credential_count"] = len(global_store.credentials.values())
        state["token_count"] = len(global_store.tokens)

    except ImportError:
        pass

    try:
        from core.report import findings as global_findings

        # Recent findings
        state["findings_summary"] = [
            {"severity": f.get("severity", "INFO"), "title": f.get("title", ""),
             "module": f.get("module", ""), "target": f.get("target", "")}
            for f in global_findings[-30:]
        ]

        # Extract high-value targets from findings
        for f in global_findings:
            title = f.get("title", "").lower()
            evidence = f.get("evidence", "")
            # DB credentials
            if any(kw in title for kw in ["database", "postgres", "mysql", "mssql", "credential"]):
                state["high_value_targets"].append({
                    "type": "database_credentials",
                    "finding_title": f.get("title"),
                    "has_connection_string": "connection_string" in str(evidence).lower(),
                })
            # Cloud keys
            if any(kw in title for kw in ["aws", "gcp", "azure", "cloud", "access_key"]):
                state["high_value_targets"].append({
                    "type": "cloud_credentials",
                    "finding_title": f.get("title"),
                })
            # Escalation paths
            if any(kw in title for kw in ["escalat", "sudo", "privilege", "root"]):
                state["high_value_targets"].append({
                    "type": "escalation_path",
                    "finding_title": f.get("title"),
                })

        # Deduplicate
        seen_hvt = set()
        unique_hvt = []
        for hvt in state["high_value_targets"]:
            key = f"{hvt['type']}:{hvt.get('finding_title', '')}"
            if key not in seen_hvt:
                seen_hvt.add(key)
                unique_hvt.append(hvt)
        state["high_value_targets"] = unique_hvt

    except ImportError:
        pass

    # Accessible paths from findings
    try:
        for f in (globals().get('global_findings') or []):
            evidence = f.get("evidence", {})
            if isinstance(evidence, dict):
                for path in evidence.get("accessible_paths", []):
                    state["accessible_paths"].append(path)
    except Exception:
        pass

    return state
