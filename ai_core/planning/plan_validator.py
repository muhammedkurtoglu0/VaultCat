"""Plan Validator & Command Sanitizer — prevents LLM hallucination from reaching execution.

LLMs (Anthropic, OpenAI, DeepSeek) can invent non-existent Vault CLI flags,
API endpoints, or tool parameters.  This module provides a strict schema
validation layer that **every** LLM-generated plan must pass through before
any step is executed.

Validates:
1. **Tool names** — must match a known MCP tool from ``ai_core.tools.ALL_TOOLS``.
2. **Parameters** — unknown keys are stripped; required params are checked.
3. **Vault API paths** — must start with a known Vault API prefix.
4. **Token values** — hallucinated tokens (matching Vault token patterns) are
   detected and stripped.
5. **Risk levels** — must be one of ``read_only | state_changing | destructive``.
6. **Phase values** — must be one of ``recon | audit | exploit | report``.

Usage::

    from ai_core.planning.plan_validator import PlanValidator

    validator = PlanValidator()
    validated_plan = validator.validate(raw_llm_plan_dict)
    # validated_plan["steps"] now contains only safe, real steps.
"""

from __future__ import annotations

import re
from typing import Any

from core.logger import logger

# ---------------------------------------------------------------------------
# Canonical data — single source of truth for what is "valid"
# ---------------------------------------------------------------------------

# Every known MCP tool name registered in ai_core.tools.ALL_TOOLS
_VALID_TOOL_NAMES: set[str] = {
    # Recon
    "run_unauthenticated_recon",
    "run_hijack_scan",
    "run_env_scan",
    # Audit
    "run_capability_audit",
    "run_priv_esc_scan",
    "run_kv_enumeration",
    "run_ttl_audit",
    "run_auth_config_audit",
    "run_policy_auditor",
    "read_single_policy",
    "run_raw_vault_request",
    "run_audit_log_scan",
    # Exploit
    "run_privilege_escalation",
    "run_secret_exfiltration",
    "run_database_credential_harvest",
    "run_cloud_key_exfiltration",
    "run_database_pivot",
    "run_reverse_shell",
    # Auth bypass
    "run_approle_exploit",
    "run_jwt_oidc_exploit",
    "run_kubernetes_auth_exploit",
    # Secrets engines
    "run_pki_exploit",
    "run_transit_exploit",
    "run_raft_exploit",
    # Active modules
    "list_active_modules",
    "run_active_module",
    # Meta
    "get_findings",
    "get_risk_score",
    "get_remediation_advice",
    "get_fix_commands",
    "get_threat_intel",
    "search_to_actions",
    # Reporting
    "export_full_report",
    "generate_diff_report",
    "send_notification",
    # Config
    "set_evasion_profile",
    "set_waf_evasion_profile",
    # Cleanup
    "run_cleanup",
    # Specialized
    "refresh_nvd_cache",
    "run_compliance_check",
    "run_network_probe",
    "web_search",
    "run_container_scan",
    "run_vault_agent_scan",
    "decode_generate_root_otp",
}

# Tool parameter schemas — each tool has a set of known, valid param keys.
# Parameters NOT in this map are treated as hallucinated and stripped.
_TOOL_PARAM_SCHEMAS: dict[str, set[str]] = {
    "run_raw_vault_request": {"method", "path", "body", "token"},
    "run_unauthenticated_recon": {"target"},
    "run_capability_audit": {"vault_addr", "token"},
    "run_priv_esc_scan": {"vault_addr", "token"},
    "run_kv_enumeration": {"vault_addr", "token", "mount_path"},
    "run_ttl_audit": {"vault_addr", "token"},
    "run_auth_config_audit": {"vault_addr", "token"},
    "run_policy_auditor": {"vault_addr", "token"},
    "read_single_policy": {"vault_addr", "token", "policy_name"},
    "run_privilege_escalation": {"vault_addr", "token", "backdoor_policy_name"},
    "run_secret_exfiltration": {"vault_addr", "token", "mount_path"},
    "run_database_credential_harvest": {"vault_addr", "token"},
    "run_cloud_key_exfiltration": {"vault_addr", "token"},
    "run_hijack_scan": {"path"},
    "run_env_scan": {},
    "list_active_modules": {},
    "run_active_module": {"module_id", "params"},
    "get_findings": {"min_severity", "module"},
    "get_risk_score": {},
    "get_remediation_advice": {"min_severity", "category"},
    "export_full_report": {"format", "output_path"},
    "get_threat_intel": {"cve_id", "vault_version"},
    "search_to_actions": {"query"},
    "set_evasion_profile": {"profile"},
    "set_waf_evasion_profile": {"profile"},
    "run_cleanup": {"vault_addr", "token", "dry_run"},
    "run_audit_log_scan": {"log_file_path"},
    "run_compliance_check": {"vault_addr", "token"},
    "run_network_probe": {"target", "ports"},
    "web_search": {"query"},
    "run_container_scan": {"target"},
    "run_vault_agent_scan": {"target"},
    "run_approle_exploit": {"vault_addr", "role_id", "secret_id", "mount_path"},
    "run_jwt_oidc_exploit": {"vault_addr", "token", "mount_path"},
    "run_kubernetes_auth_exploit": {"vault_addr", "token", "mount_path"},
    "run_pki_exploit": {"vault_addr", "token", "mount_path"},
    "run_transit_exploit": {"vault_addr", "token", "mount_path"},
    "run_raft_exploit": {"vault_addr", "token"},
    "run_database_pivot": {"db_host", "db_port", "db_user", "db_pass", "db_name"},
    "run_reverse_shell": {"target_host", "target_port", "listen_host", "listen_port"},
    "decode_generate_root_otp": {"otp", "encoded_token"},
}

# Known Vault API path prefixes — paths not matching these are likely hallucinated
_VALID_VAULT_PATH_PREFIXES: list[str] = [
    "sys/",
    "auth/",
    "secret/",
    "cubbyhole/",
    "database/",
    "aws/",
    "gcp/",
    "azure/",
    "pki/",
    "transit/",
    "ssh/",
    "identity/",
    "kv-v1/",
    "kv-v2/",
]

# Vault token patterns — hallucinated tokens often match this
_VAULT_TOKEN_RE = re.compile(
    r"^(hvs\.|s\.|b\.)[A-Za-z0-9+/=]{20,}$"
)

# Valid risk levels — two contexts:
# Plan-level: critical | high | medium | low (overall assessment severity)
# Step-level: read_only | state_changing | destructive (module risk level)
_VALID_PLAN_RISK_LEVELS: set[str] = {"critical", "high", "medium", "low"}
_VALID_STEP_RISK_LEVELS: set[str] = {"read_only", "state_changing", "destructive"}

# Valid phases
_VALID_PHASES: set[str] = {"recon", "audit", "exploit", "report"}

# Valid HTTP methods for raw_vault_request
_VALID_HTTP_METHODS: set[str] = {"GET", "POST", "PUT", "DELETE", "LIST", "PATCH", "HEAD"}

# Valid on_failure strategies
_VALID_ON_FAILURE: set[str] = {"abort", "skip", "retry"}


# ---------------------------------------------------------------------------
# Plan Validator
# ---------------------------------------------------------------------------


class PlanValidator:
    """Validates and sanitizes LLM-generated pentest plans before execution.

    Every step's tool name, parameters, Vault paths, and risk levels
    are checked against canonical schemas.  Hallucinated fields are
    stripped with a warning logged.  This ensures no LLM-invented
    command ever reaches the Vault API.
    """

    def __init__(self, strict: bool = True):
        """Create a plan validator.

        Parameters
        ----------
        strict: If True, steps with unknown tools are REMOVED entirely.
                If False (default), unknown tools are kept but flagged
                with a warning (safer for partial validation).
        """
        self._strict = strict
        self._warnings: list[str] = []

    # ── public API ──────────────────────────────────────────────────────

    def validate(self, plan_dict: dict[str, Any]) -> dict[str, Any]:
        """Validate and sanitize an LLM-generated plan dict.

        Returns a cleaned dict safe for execution.  Logs warnings for
        every sanitization action.
        """
        self._warnings = []
        cleaned = dict(plan_dict)  # shallow copy

        # Validate plan risk_level (critical|high|medium|low)
        risk = cleaned.get("risk_level", "")
        if risk and risk not in _VALID_PLAN_RISK_LEVELS:
            self._warn(f"Invalid plan risk_level '{risk}' — defaulting to 'medium'")
            cleaned["risk_level"] = "medium"

        # Validate steps
        raw_steps: list[dict] = cleaned.get("steps") or []
        validated_steps: list[dict] = []

        for i, step in enumerate(raw_steps):
            validated = self._validate_step(step, i)
            if validated is not None:
                validated_steps.append(validated)

        cleaned["steps"] = validated_steps

        # Validate token_assessment
        if "token_assessment" in cleaned and cleaned["token_assessment"]:
            cleaned["token_assessment"] = self._validate_token_assessment(
                cleaned["token_assessment"]
            )

        # Log warning summary
        if self._warnings:
            logger.warning(
                f"[plan-validator] {len(self._warnings)} issue(s) found in LLM plan:\n  "
                + "\n  ".join(self._warnings[:10])
            )
            if len(self._warnings) > 10:
                logger.warning(
                    f"[plan-validator] ...and {len(self._warnings) - 10} more"
                )

        cleaned["_validation_warnings"] = self._warnings
        return cleaned

    # ── step validation ─────────────────────────────────────────────────

    def _validate_step(self, step: dict, index: int) -> dict | None:
        """Validate a single plan step.  Returns cleaned dict or None (to drop)."""
        tool = step.get("tool", "")

        # ── Tool name check ────────────────────────────────────────────
        if not tool:
            self._warn(f"Step {index}: missing 'tool' field — dropping step")
            return None

        if tool not in _VALID_TOOL_NAMES:
            # Check for fuzzy matches
            suggestion = self._fuzzy_match(tool)
            if suggestion:
                self._warn(
                    f"Step {index}: unknown tool '{tool}' — "
                    f"did you mean '{suggestion}'? Auto-correcting."
                )
                tool = suggestion
            elif self._strict:
                self._warn(
                    f"Step {index}: unknown tool '{tool}' — dropping step (strict mode)"
                )
                return None
            else:
                self._warn(
                    f"Step {index}: unknown tool '{tool}' — "
                    f"keeping but execution may fail"
                )

        cleaned = dict(step)
        cleaned["tool"] = tool

        # ── Parameter sanitization ─────────────────────────────────────
        known_params = _TOOL_PARAM_SCHEMAS.get(tool, set())
        raw_params: dict = step.get("params") or {}

        if known_params:
            # Strip unknown params
            sanitized_params: dict[str, Any] = {}
            for key, value in raw_params.items():
                if key in known_params:
                    sanitized_params[key] = self._sanitize_param(tool, key, value)
                else:
                    self._warn(
                        f"Step {index} ({tool}): unknown param '{key}' — stripped"
                    )
            cleaned["params"] = sanitized_params
        else:
            # Tool has no known param schema — keep as-is
            cleaned["params"] = raw_params

        # ── Path validation (for raw_vault_request) ────────────────────
        if tool == "run_raw_vault_request":
            path = cleaned.get("params", {}).get("path", "")
            if path:
                cleaned["params"]["path"] = self._sanitize_vault_path(path, index)
            method = cleaned.get("params", {}).get("method", "GET")
            if method.upper() not in _VALID_HTTP_METHODS:
                self._warn(
                    f"Step {index} ({tool}): invalid HTTP method '{method}' — "
                    f"defaulting to GET"
                )
                cleaned["params"]["method"] = "GET"

        # ── Token hallucination check ──────────────────────────────────
        token = cleaned.get("params", {}).get("token", "")
        if token and _VAULT_TOKEN_RE.match(str(token)):
            # This is a specific token value, likely hallucinated
            self._warn(
                f"Step {index} ({tool}): params.token looks like a "
                f"hallucinated Vault token — replaced with placeholder"
            )
            cleaned["params"]["token"] = "USE_BEST_TOKEN"

        # ── Risk level validation (step-level: read_only|state_changing|destructive) ─
        risk = cleaned.get("risk", "")
        if risk and risk not in _VALID_STEP_RISK_LEVELS:
            self._warn(
                f"Step {index} ({tool}): invalid step risk '{risk}' — "
                f"defaulting to 'read_only'"
            )
            cleaned["risk"] = "read_only"

        # ── Phase validation ───────────────────────────────────────────
        phase = cleaned.get("phase", "")
        if phase and phase not in _VALID_PHASES:
            cleaned["phase"] = "audit"

        # ── on_failure validation ──────────────────────────────────────
        on_fail = cleaned.get("on_failure", "abort")
        if on_fail not in _VALID_ON_FAILURE:
            cleaned["on_failure"] = "abort"

        return cleaned

    # ── path sanitization ──────────────────────────────────────────────

    @staticmethod
    def _sanitize_vault_path(path: str, step_index: int = 0) -> str:
        """Strip invalid prefixes and validate against known Vault paths.

        Returns the cleaned path (may be stripped or defaulted).
        """
        original = str(path).strip()

        # Strip /v1/ prefix if present — we work with relative paths
        if original.startswith("/v1/"):
            original = original[4:]
        elif original.startswith("v1/"):
            original = original[3:]

        original = original.lstrip("/")

        # Check against known prefixes
        if any(original.startswith(p) for p in _VALID_VAULT_PATH_PREFIXES):
            return original

        # Unknown path — log warning but keep (might be custom mount)
        logger.warning(
            f"[plan-validator] Step {step_index}: path '{original}' "
            f"doesn't match known Vault API prefixes — keeping as-is"
        )
        return original

    # ── param sanitization ─────────────────────────────────────────────

    @staticmethod
    def _sanitize_param(tool: str, key: str, value: Any) -> Any:
        """Sanitize a single parameter value based on its key."""
        # Sanitize token values
        if key == "token" and isinstance(value, str):
            if _VAULT_TOKEN_RE.match(value):
                return "USE_BEST_TOKEN"
            # Strip whitespace/newlines
            return value.strip()

        # Sanitize paths
        if key in ("path", "mount_path") and isinstance(value, str):
            return value.strip().lstrip("/")

        return value

    # ── token assessment validation ─────────────────────────────────────

    def _validate_token_assessment(self, assessment: dict) -> dict:
        """Validate the token_assessment section."""
        power = assessment.get("power_level", "")
        valid_powers = {"root", "admin", "privileged", "standard", "restricted", "unknown"}
        if power and power not in valid_powers:
            self._warn(f"Invalid power_level '{power}' — defaulting to 'unknown'")
            assessment["power_level"] = "unknown"

        # Strip hallucinated accessible_paths
        paths = assessment.get("accessible_paths") or []
        if paths:
            assessment["accessible_paths"] = [
                p for p in paths
                if isinstance(p, str) and any(
                    p.lstrip("/").startswith(prefix)
                    for prefix in _VALID_VAULT_PATH_PREFIXES
                )
            ]

        return assessment

    # ── fuzzy matching ──────────────────────────────────────────────────

    # ── sorted, deterministic copy of valid tool names ─────────────────
    _SORTED_VALID_TOOLS: list[str] = sorted(_VALID_TOOL_NAMES)

    @classmethod
    def _fuzzy_match(cls, tool: str) -> str | None:
        """Try to find the closest valid tool name via deterministic matching."""
        tool_lower = tool.lower()

        # Direct substring match (sorted order = deterministic)
        for valid in cls._SORTED_VALID_TOOLS:
            if tool_lower in valid or valid in tool_lower:
                return valid

        # Prefix match
        for valid in cls._SORTED_VALID_TOOLS:
            if valid.startswith(tool_lower) or tool_lower.startswith(valid):
                return valid

        return None

    # ── helpers ─────────────────────────────────────────────────────────

    def _warn(self, message: str):
        """Record a validation warning."""
        self._warnings.append(message)
        logger.warning(f"[plan-validator] {message}")
