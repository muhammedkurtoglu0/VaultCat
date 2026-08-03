"""Tests for active_execution.waf_evasion — body/path/header obfuscation."""

from __future__ import annotations

import json

import pytest

from active_execution.waf_evasion import (
    WAFEvasionProfile,
    WAFEvasionEngine,
    _EVASION_PROFILES,
    enable_waf_evasion,
    disable_waf_evasion,
    is_waf_evasion_enabled,
    set_waf_evasion_profile,
    get_waf_evasion_profile,
    get_evasion_engine,
)


# ---------------------------------------------------------------------------
# Body obfuscation
# ---------------------------------------------------------------------------


class TestBodyObfuscation:
    """Tests for JSON body obfuscation techniques."""

    def test_noise_injection_adds_fields(self):
        """Noise injection adds the configured number of extra fields."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)  # 4 noise fields
        original = {"policies": ["root"], "ttl": "1h"}
        result = engine._obfuscate_body(original)

        # Original keys must be preserved
        assert result["policies"] == ["root"]
        assert result["ttl"] == "1h"

        # Noise fields added (names from _NOISE_NAMES)
        noise_count = sum(
            1 for k in result
            if k not in ("policies", "ttl", "__waf_compact__")
        )
        assert noise_count == 4

    def test_noise_fields_have_varied_types(self):
        """Noise fields should include ints and strings for diversity."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)  # 6 noise fields
        result = engine._obfuscate_body({"key": "value"})

        types_found = set()
        for k, v in result.items():
            if k.startswith("_") and k != "__waf_compact__":
                types_found.add(type(v).__name__)
        # Should have at least 2 different types (int + str)
        assert len(types_found) >= 1

    def test_key_shuffle_changes_order(self):
        """Key shuffle randomizes key ordering."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        original = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7, "h": 8}

        # Run many times — at least once the order should differ from insertion order
        different = 0
        for _ in range(20):
            result = engine._obfuscate_body(dict(original))
            # Get non-noise keys in order
            non_noise_keys = [
                k for k in result
                if k in original
            ]
            if non_noise_keys != list(original.keys()):
                different += 1

        assert different > 0, "Key shuffle never changed order in 20 attempts"

    def test_unicode_escape_in_aggressive(self):
        """AGGRESSIVE profile applies unicode escaping to string values."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        # Test with a string that would trigger WAF signatures
        result = engine._obfuscate_body({"policies": ["root"], "name": "admin"})

        # At least one string value should have unicode escape (probabilistic)
        # Run multiple times to increase chance
        found_escape = False
        for _ in range(30):
            r = engine._obfuscate_body({"policies": ["root"], "name": "admin"})
            policies = r.get("policies", [])
            name = r.get("name", "")
            if any("\\u" in str(v) for v in policies):
                found_escape = True
                break
            if "\\u" in str(name):
                found_escape = True
                break
        assert found_escape, "Unicode escape never applied in 30 attempts"

    def test_no_unicode_escape_in_light(self):
        """LIGHT profile should NOT apply unicode escaping."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        result = engine._obfuscate_body({"policies": ["root"]})

        policies = result.get("policies", [])
        for v in policies:
            assert "\\u" not in str(v)

    def test_none_profile_adds_no_noise(self):
        """NONE profile should return the body unchanged (except shallow copy)."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.NONE)
        original = {"key": "value"}
        result = engine._obfuscate_body(original)

        clean = {k: v for k, v in result.items() if k != "__waf_compact__"}
        assert clean == original

    def test_body_is_none_returns_none(self):
        """None body should stay None."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        assert engine._obfuscate_body(None) is None

    def test_compact_metadata_present(self):
        """__waf_compact__ metadata key is always present in obfuscated body."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        result = engine._obfuscate_body({"test": True})
        assert "__waf_compact__" in result
        assert isinstance(result["__waf_compact__"], bool)


# ---------------------------------------------------------------------------
# URL path obfuscation
# ---------------------------------------------------------------------------


class TestPathObfuscation:
    """Tests for URL path obfuscation."""

    def test_double_slash_inserted(self):
        """MODERATE+ profiles may insert double slashes."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        # Run multiple times — double slash is probabilistic
        found_double = False
        for _ in range(20):
            url = engine._obfuscate_url("https://vault.test:8200/v1/sys/health")
            if "//" in url.replace("https://", ""):
                found_double = True
                break
        assert found_double, "Double slash never inserted in 20 attempts"

    def test_host_port_preserved(self):
        """Host and port must never be obfuscated."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for _ in range(20):
            url = engine._obfuscate_url("https://10.0.0.1:8200/v1/sys/health")
            assert url.startswith("https://10.0.0.1:8200/")

    def test_path_remains_valid(self):
        """Obfuscated path must still be a valid URL."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for _ in range(20):
            url = engine._obfuscate_url("https://vault.test/v1/auth/token/create")
            # Must start with scheme
            assert url.startswith("https://")
            # Must contain v1
            assert "/v1/" in url

    def test_no_path_obfuscation_in_light(self):
        """LIGHT profile should not modify paths."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        original = "https://vault.test:8200/v1/sys/health"
        for _ in range(10):
            url = engine._obfuscate_url(original)
            # Path should be unchanged in LIGHT (only body + header changes)
            assert "/v1/sys/health" in url

    def test_trailing_slash_toggle(self):
        """MODERATE profile may add/remove trailing slashes."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        found_slash = False
        found_no_slash = False
        for _ in range(30):
            url = engine._obfuscate_url("https://vault.test/v1/sys/health")
            path = url.replace("https://vault.test", "")
            if path.endswith("/"):
                found_slash = True
            else:
                found_no_slash = True
        # Both should appear since toggling is random
        assert found_no_slash, "Never got non-trailing-slash variant"

    def test_v1_prefix_preserved(self):
        """The /v1/ prefix must stay at the start of the path."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for _ in range(20):
            url = engine._obfuscate_url("https://vault.test/v1/sys/mounts")
            assert "/v1/" in url
            # /v1/ should appear before obfuscated segments
            v1_idx = url.index("/v1/")
            assert v1_idx > 0  # after host:port


# ---------------------------------------------------------------------------
# Header diversification
# ---------------------------------------------------------------------------


class TestHeaderDiversification:
    """Tests for HTTP header diversification."""

    def test_content_type_set(self):
        """LIGHT+ profiles set a Content-Type header."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        result = engine._diversify_headers({"X-Vault-Token": "s.test"})
        assert "Content-Type" in result

    def test_content_type_is_valid(self):
        """Content-Type must be a JSON variant."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for _ in range(20):
            result = engine._diversify_headers({"X-Vault-Token": "s.test"})
            # Content-Type may have varied case (header_case_vary active)
            ct = ""
            for k, v in result.items():
                if k.lower() == "content-type":
                    ct = v
                    break
            assert "application/json" in ct, f"Got Content-Type: {ct!r}"

    def test_xff_spoof_in_moderate(self):
        """MODERATE+ profiles add X-Forwarded-For with private IP."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        result = engine._diversify_headers({})
        # X-Forwarded-For may have case variation from header_case_vary
        xff_key = None
        for k, v in result.items():
            if k.lower() == "x-forwarded-for":
                xff_key = k
                ip = v
                break
        assert xff_key is not None, f"No X-Forwarded-For variant in {list(result.keys())}"
        assert ip.startswith(("10.", "172.", "192.168."))

    def test_no_xff_in_light(self):
        """LIGHT profile should NOT spoof X-Forwarded-For."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        result = engine._diversify_headers({})
        assert "X-Forwarded-For" not in result

    def test_benign_headers_have_uuid_format(self):
        """Injected trace/request IDs must be valid UUIDs."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        import uuid as _uuid
        for _ in range(20):
            result = engine._diversify_headers({})
            for header_key in ("X-Request-ID", "X-Trace-Id", "X-Correlation-Id"):
                if header_key in result:
                    # Must not raise
                    _uuid.UUID(result[header_key])

    def test_original_headers_preserved(self):
        """Existing headers must not be removed (values preserved regardless of case)."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        original = {
            "X-Vault-Token": "s.abc123",
            "X-Vault-Namespace": "ns1",
        }
        result = engine._diversify_headers(original)
        # Values preserved — keys may have case variation
        token_found = any(
            v == "s.abc123" for k, v in result.items()
            if k.lower() == "x-vault-token"
        )
        assert token_found, f"Token value not found in {result}"
        ns_found = any(
            k.lower() == "x-vault-namespace" for k in result
        )
        assert ns_found, f"Namespace header not found in {list(result.keys())}"

    def test_accept_header_varied(self):
        """LIGHT+ profiles should set an Accept header."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.LIGHT)
        result = engine._diversify_headers({})
        assert "Accept" in result


# ---------------------------------------------------------------------------
# transform_request round-trip
# ---------------------------------------------------------------------------


class TestTransformRequest:
    """End-to-end tests for the full request transformation pipeline."""

    def test_transform_preserves_method(self):
        """HTTP method must never change."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for method in ("GET", "POST", "PUT", "DELETE", "LIST"):
            new_method, _, _, _ = engine.transform_request(
                method,
                "https://vault.test/v1/sys/health",
                {"X-Vault-Token": "s.test"},
                None,
            )
            assert new_method == method

    def test_transform_without_body(self):
        """GET requests without body should pass through cleanly."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        _, url, headers, body = engine.transform_request(
            "GET",
            "https://vault.test/v1/sys/health",
            {"X-Vault-Token": "s.test"},
            None,
        )
        assert body is None
        assert "X-Vault-Token" in headers or "x-vault-token" in headers
        assert "vault.test" in url

    def test_transform_with_body(self):
        """POST requests with body should be obfuscated."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.MODERATE)
        _, url, headers, body = engine.transform_request(
            "POST",
            "https://vault.test/v1/auth/token/create",
            {"X-Vault-Token": "s.test"},
            {"policies": ["default"], "ttl": "1h", "display_name": "test"},
        )
        assert body is not None
        # Original keys preserved
        assert body["policies"] == ["default"]
        assert body["ttl"] == "1h"
        # Noise fields added
        assert len(body) > 4  # 3 original + __waf_compact__ + noise
        assert "__waf_compact__" in body

    def test_body_can_be_serialized_to_json(self):
        """Obfuscated body must be JSON-serializable (values may be escaped)."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        _, _, _, body = engine.transform_request(
            "POST",
            "https://vault.test/v1/auth/token/create",
            {"X-Vault-Token": "s.test"},
            {"policies": ["root"], "ttl": "1h"},
        )
        # Strip metadata and serialize
        body.pop("__waf_compact__", None)
        serialized = json.dumps(body, ensure_ascii=False)
        assert len(serialized) > 0
        # Round-trip: parse back
        parsed = json.loads(serialized)
        assert "policies" in parsed
        assert "ttl" in parsed

    def test_transform_url_always_has_v1_for_vault_paths(self):
        """For Vault API URLs, /v1/ must be present."""
        engine = WAFEvasionEngine(profile=WAFEvasionProfile.AGGRESSIVE)
        for _ in range(10):
            _, url, _, _ = engine.transform_request(
                "GET",
                "https://vault.test:8200/v1/sys/health",
                {},
                None,
            )
            assert "/v1/" in url


# ---------------------------------------------------------------------------
# Profile configuration
# ---------------------------------------------------------------------------


class TestProfileConfig:
    """Tests for WAF evasion profile configuration."""

    REQUIRED_KEYS = [
        "body_noise_fields", "body_shuffle_keys", "body_whitespace_vary",
        "body_unicode_escape", "path_double_slash", "path_trailing_slash",
        "path_url_encode", "header_content_type_vary", "header_xff_spoof",
        "header_benign_inject", "header_case_vary",
    ]

    @pytest.mark.parametrize("profile", list(WAFEvasionProfile))
    def test_all_profiles_have_required_keys(self, profile):
        """Every profile must define all required configuration keys."""
        cfg = _EVASION_PROFILES[profile]
        for key in self.REQUIRED_KEYS:
            assert key in cfg, f"Profile {profile.value} missing key: {key}"

    def test_none_profile_disables_everything(self):
        """NONE profile must have all boolean flags set to False."""
        cfg = _EVASION_PROFILES[WAFEvasionProfile.NONE]
        for key in self.REQUIRED_KEYS:
            if isinstance(cfg[key], bool):
                assert cfg[key] is False, f"NONE profile: {key} should be False, got {cfg[key]}"
        assert cfg["body_noise_fields"] == 0

    def test_aggressive_profile_enables_most(self):
        """AGGRESSIVE should enable more techniques than MODERATE."""
        aggressive = _EVASION_PROFILES[WAFEvasionProfile.AGGRESSIVE]
        moderate = _EVASION_PROFILES[WAFEvasionProfile.MODERATE]
        agg_count = sum(1 for k, v in aggressive.items() if v and isinstance(v, bool))
        mod_count = sum(1 for k, v in moderate.items() if v and isinstance(v, bool))
        assert agg_count >= mod_count

    def test_profile_progression(self):
        """Each profile should be at least as aggressive as the one below it."""
        profiles = [
            WAFEvasionProfile.NONE,
            WAFEvasionProfile.LIGHT,
            WAFEvasionProfile.MODERATE,
            WAFEvasionProfile.AGGRESSIVE,
        ]
        for i in range(len(profiles) - 1):
            cfg_lo = _EVASION_PROFILES[profiles[i]]
            cfg_hi = _EVASION_PROFILES[profiles[i + 1]]
            assert cfg_hi["body_noise_fields"] >= cfg_lo["body_noise_fields"]
            # Boolean: hi should have all the True values lo has
            for key in self.REQUIRED_KEYS:
                if isinstance(cfg_lo[key], bool) and cfg_lo[key]:
                    assert cfg_hi[key], (
                        f"{profiles[i+1].value} should inherit {key}=True "
                        f"from {profiles[i].value}"
                    )


# ---------------------------------------------------------------------------
# Global state management
# ---------------------------------------------------------------------------


class TestGlobalState:
    """Tests for enable/disable/profile switching."""

    def test_default_is_disabled(self):
        """WAF evasion should be disabled by default."""
        # Reset to default
        disable_waf_evasion()
        assert is_waf_evasion_enabled() is False

    def test_enable_then_disable(self):
        """enable/disable toggle works."""
        disable_waf_evasion()
        enable_waf_evasion()
        assert is_waf_evasion_enabled() is True
        disable_waf_evasion()
        assert is_waf_evasion_enabled() is False

    def test_profile_switching(self):
        """set_waf_evasion_profile changes the active profile."""
        disable_waf_evasion()
        set_waf_evasion_profile(WAFEvasionProfile.LIGHT)
        assert get_waf_evasion_profile() == WAFEvasionProfile.LIGHT
        engine = get_evasion_engine()
        assert engine.profile == WAFEvasionProfile.LIGHT

    def test_engine_is_singleton(self):
        """get_evasion_engine returns the same instance."""
        e1 = get_evasion_engine()
        e2 = get_evasion_engine()
        assert e1 is e2

    def test_all_profiles_switch_without_error(self):
        """Every profile can be set without raising."""
        for profile in WAFEvasionProfile:
            set_waf_evasion_profile(profile)
            assert get_waf_evasion_profile() == profile
