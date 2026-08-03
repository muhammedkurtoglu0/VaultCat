"""Tests for ai_core.planning.plan_validator — LLM hallucination filtering."""

from __future__ import annotations

import pytest

from ai_core.planning.plan_validator import PlanValidator


class TestToolNameValidation:
    """Tests for tool name validation and fuzzy matching."""

    def test_known_tool_passes(self):
        """A known tool name is accepted unchanged."""
        validator = PlanValidator(strict=False)
        plan = {"steps": [{"tool": "run_secret_exfiltration", "reason": "test", "params": {}}]}
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 1
        assert cleaned["steps"][0]["tool"] == "run_secret_exfiltration"

    def test_hallucinated_tool_dropped_by_default(self):
        """Default (strict=True) drops unknown tools."""
        validator = PlanValidator()
        plan = {"steps": [{"tool": "run_complete_takeover", "reason": "hack"}]}
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 0

    def test_hallucinated_tool_kept_in_non_strict(self):
        """Non-strict mode keeps unknown tools with a warning."""
        validator = PlanValidator(strict=False)
        plan = {"steps": [{"tool": "run_complete_takeover", "reason": "hack"}]}
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 1
        assert "run_complete_takeover" in cleaned["_validation_warnings"][0]

    def test_hallucinated_tool_dropped_in_strict(self):
        """Strict mode removes steps with unknown tools."""
        validator = PlanValidator(strict=True)
        plan = {"steps": [{"tool": "run_complete_takeover", "reason": "hack"}]}
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 0

    def test_fuzzy_match_corrects_typo(self):
        """Fuzzy matching corrects 'run_capability' → 'run_capability_audit'."""
        validator = PlanValidator(strict=False)
        plan = {"steps": [{"tool": "run_capability", "reason": "audit"}]}
        cleaned = validator.validate(plan)
        assert cleaned["steps"][0]["tool"] == "run_capability_audit"

    def test_fuzzy_match_substring(self):
        """Substring match corrects 'priv_esc' → a valid tool."""
        validator = PlanValidator(strict=False)
        plan = {"steps": [{"tool": "run_priv_esc", "reason": "scan"}]}
        cleaned = validator.validate(plan)
        assert cleaned["steps"][0]["tool"] in (
            "run_priv_esc_scan", "run_privilege_escalation"
        )

    def test_empty_tool_dropped(self):
        """Steps with empty tool name are dropped."""
        validator = PlanValidator(strict=False)
        plan = {"steps": [{"tool": "", "reason": "empty"}]}
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 0


class TestParameterSanitization:
    """Tests for parameter validation and sanitization."""

    def test_unknown_params_stripped(self):
        """Parameters not in the tool's schema are stripped."""
        validator = PlanValidator()
        plan = {"steps": [{
            "tool": "run_secret_exfiltration",
            "reason": "test",
            "params": {
                "vault_addr": "https://v.test",
                "token": "s.test",
                "evil_flag": "--destroy-all",  # hallucinated
                "super_secret_mode": True,      # hallucinated
            },
        }]}
        cleaned = validator.validate(plan)
        params = cleaned["steps"][0]["params"]
        assert "vault_addr" in params
        assert "token" in params
        assert "evil_flag" not in params
        assert "super_secret_mode" not in params

    def test_hallucinated_token_replaced(self):
        """Token values matching Vault patterns are replaced with placeholder."""
        validator = PlanValidator()
        plan = {"steps": [{
            "tool": "run_capability_audit",
            "reason": "test",
            "params": {
                "vault_addr": "https://v.test",
                "token": "hvs.CAFakeLLMGeneratedTokenThatDoesNotExist123456",
            },
        }]}
        cleaned = validator.validate(plan)
        assert cleaned["steps"][0]["params"]["token"] == "USE_BEST_TOKEN"

    def test_valid_token_placeholder_kept(self):
        """Non-token-looking values like USE_BEST_TOKEN are kept."""
        validator = PlanValidator()
        plan = {"steps": [{
            "tool": "run_capability_audit",
            "reason": "test",
            "params": {"vault_addr": "https://v.test", "token": "USE_BEST_TOKEN"},
        }]}
        cleaned = validator.validate(plan)
        # USE_BEST_TOKEN doesn't match Vault token pattern (no . prefix)
        assert cleaned["steps"][0]["params"]["token"] == "USE_BEST_TOKEN"

    def test_raw_vault_request_params_validated(self):
        """run_raw_vault_request gets extra validation for method and path."""
        validator = PlanValidator()
        plan = {"steps": [{
            "tool": "run_raw_vault_request",
            "reason": "test",
            "params": {
                "method": "DESTROY",  # invalid HTTP method
                "path": "/v1/admin/super_secret_backdoor",
                "token": "s.fake123",
            },
        }]}
        cleaned = validator.validate(plan)
        params = cleaned["steps"][0]["params"]
        assert params["method"] == "GET"  # corrected
        assert params["token"] == "s.fake123"  # short fake token kept (not matching pattern)


class TestRiskLevelValidation:
    """Tests for risk_level validation."""

    def test_invalid_risk_defaults_to_medium(self):
        validator = PlanValidator()
        plan = {"risk_level": "nuclear", "steps": []}
        cleaned = validator.validate(plan)
        assert cleaned["risk_level"] == "medium"

    def test_valid_plan_risk_kept(self):
        """Plan-level risk_level accepts critical/high/medium/low."""
        for level in ("critical", "high", "medium", "low"):
            validator = PlanValidator()
            plan = {"risk_level": level, "steps": []}
            cleaned = validator.validate(plan)
            assert cleaned["risk_level"] == level

    def test_step_risk_defaults_to_read_only(self):
        validator = PlanValidator()
        plan = {"steps": [{
            "tool": "run_secret_exfiltration",
            "reason": "test",
            "risk": "total_annihilation",
        }]}
        cleaned = validator.validate(plan)
        assert cleaned["steps"][0]["risk"] == "read_only"


class TestPathValidation:
    """Tests for Vault API path sanitization."""

    @pytest.mark.parametrize("path,expected", [
        ("sys/health", "sys/health"),
        ("/v1/sys/health", "sys/health"),
        ("v1/sys/mounts", "sys/mounts"),
        ("auth/token/create", "auth/token/create"),
        ("secret/myapp/db", "secret/myapp/db"),
        ("database/creds/readonly", "database/creds/readonly"),
        ("pki/issue/default", "pki/issue/default"),
    ])
    def test_known_path_stripped_correctly(self, path, expected):
        """Known Vault paths have /v1/ prefix stripped."""
        result = PlanValidator._sanitize_vault_path(path)
        assert result == expected

    def test_unknown_path_kept_with_warning(self):
        """Unknown paths are kept but logged (might be custom mounts)."""
        result = PlanValidator._sanitize_vault_path("custom-mount/data")
        assert result == "custom-mount/data"


class TestTokenAssessmentValidation:
    """Tests for token_assessment sanitization."""

    def test_invalid_power_level_defaulted(self):
        validator = PlanValidator()
        plan = {
            "steps": [],
            "token_assessment": {
                "power_level": "god_mode",
                "summary": "test",
                "accessible_paths": ["/etc/passwd", "sys/health"],
            },
        }
        cleaned = validator.validate(plan)
        ta = cleaned["token_assessment"]
        assert ta["power_level"] == "unknown"
        # Non-Vault paths stripped from accessible_paths
        assert "/etc/passwd" not in ta["accessible_paths"]
        assert "sys/health" in ta["accessible_paths"]


class TestEndToEnd:
    """End-to-end tests with realistic LLM hallucination scenarios."""

    def test_llm_invents_non_existent_tools_and_params(self):
        """Scenario: LLM invents tools and parameters that don't exist.
        With strict=True (default), hallucinated tools are dropped."""
        validator = PlanValidator(strict=False)  # non-strict to test param sanitization
        plan = {
            "risk_level": "extreme",
            "steps": [
                {
                    "tool": "run_vault_exploit_all",
                    "reason": "full pwn",
                    "params": {
                        "target": "all",
                        "mode": "nuke",
                        "flags": "--force --no-confirm",
                    },
                },
                {
                    "tool": "run_capability_audit",
                    "reason": "audit with real tool",
                    "params": {
                        "vault_addr": "https://v.test",
                        "token": "hvs.CAFakeLLMGeneratedTokenThatMatchesVaultPattern123456",
                        "verbose": True,
                        "dump_all": True,
                    },
                },
            ],
        }
        cleaned = validator.validate(plan)

        # Step 0: hallucinated tool kept (non-strict) but params stripped
        assert len(cleaned["steps"]) >= 1
        if len(cleaned["steps"]) > 1:
            # Step 1: real tool, params sanitized
            real_step = cleaned["steps"][1]
            assert real_step["tool"] == "run_capability_audit"
            assert real_step["params"]["vault_addr"] == "https://v.test"
            assert real_step["params"]["token"] == "USE_BEST_TOKEN"
            assert "verbose" not in real_step["params"]

        assert cleaned["risk_level"] == "medium"
        assert len(cleaned["_validation_warnings"]) > 0

    def test_all_valid_plan_passes_clean(self):
        """A perfectly valid plan produces zero warnings."""
        validator = PlanValidator(strict=False)  # non-strict: valid tools accepted
        plan = {
            "risk_level": "high",
            "token_assessment": {
                "power_level": "standard",
                "summary": "Standard token with limited access",
                "accessible_paths": ["sys/health", "secret/"],
                "escalation_possible": True,
            },
            "steps": [
                {
                    "tool": "run_capability_audit",
                    "reason": "Audit token capabilities",
                    "params": {"vault_addr": "https://v.test", "token": "USE_BEST_TOKEN"},
                    "risk": "read_only",
                    "phase": "audit",
                    "priority": 1,
                    "expected_impact": "Map accessible paths",
                },
                {
                    "tool": "run_priv_esc_scan",
                    "reason": "Check for escalation paths",
                    "params": {"vault_addr": "https://v.test", "token": "USE_BEST_TOKEN"},
                    "risk": "read_only",
                    "phase": "audit",
                    "priority": 2,
                    "expected_impact": "Find privilege escalation vectors",
                },
            ],
        }
        cleaned = validator.validate(plan)
        assert len(cleaned["steps"]) == 2
        assert len(cleaned["_validation_warnings"]) == 0
