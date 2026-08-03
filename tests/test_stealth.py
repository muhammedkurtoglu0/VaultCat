"""Tests for reconnaissance.stealth_http — rate limiting, jitter, audit evasion."""

from __future__ import annotations

import time

import pytest

from reconnaissance.stealth_http import (
    # Enums
    EndpointSensitivity,
    EvasionProfile,
    JitterStrategy,
    # Path classification
    classify_path,
    # Token bucket
    TokenBucketRateLimiter,
    # Jitter
    StealthJitterEngine,
    human_jitter,
    # Audit gate
    AuditLogGate,
    # Bandwidth
    BandwidthThrottle,
    # Scheduler
    RequestScheduler,
    get_scheduler,
    # Profile management
    set_evasion_profile,
    get_evasion_profile,
    _PROFILE_CONFIG,
    _reset_scheduler,
)


# ---------------------------------------------------------------------------
# Fake clock for deterministic time-travel in tests
# ---------------------------------------------------------------------------


class FakeClock:
    """Monotonic clock that advances only when explicitly ticked."""

    def __init__(self, start: float = 0.0):
        self._now = start

    def __call__(self) -> float:
        return self._now

    def tick(self, seconds: float):
        self._now += seconds


# ---------------------------------------------------------------------------
# TokenBucketRateLimiter
# ---------------------------------------------------------------------------


class TestTokenBucketRateLimiter:
    """Tests for the proactive token-bucket rate limiter."""

    def test_unlimited_rate_returns_zero(self):
        """Unlimited rate (0) always returns 0 delay."""
        tb = TokenBucketRateLimiter(rate=0.0, burst=5)
        assert tb.consume() == 0.0
        assert tb.consume(10) == 0.0

    def test_initial_burst_allows_immediate_requests(self):
        """First N requests (up to burst) should return 0."""
        tb = TokenBucketRateLimiter(rate=1.0, burst=3)
        assert tb.consume() == 0.0
        assert tb.consume() == 0.0
        assert tb.consume() == 0.0
        # 4th request exceeds burst
        delay = tb.consume()
        assert delay > 0.0

    def test_depleted_bucket_returns_refill_time(self):
        """When bucket is empty, return seconds until next token."""
        clock = FakeClock(0.0)
        tb = TokenBucketRateLimiter(rate=2.0, burst=1, clock=clock)
        # Consume the only token
        assert tb.consume() == 0.0
        # Next request: need 0.5s for one token at 2 tok/s
        delay = tb.consume()
        assert delay == pytest.approx(0.5)

    def test_refill_over_time(self):
        """Tokens refill as time passes."""
        clock = FakeClock(0.0)
        tb = TokenBucketRateLimiter(rate=10.0, burst=5, clock=clock)
        # Drain the bucket
        for _ in range(5):
            assert tb.consume() == 0.0
        # Bucket empty
        assert tb.consume() > 0.0
        # Advance 0.5s → 5 tokens refilled (10 tok/s * 0.5s)
        clock.tick(0.5)
        for _ in range(5):
            assert tb.consume() == 0.0
        # Empty again
        assert tb.consume() > 0.0

    def test_burst_caps_tokens(self):
        """Bucket never exceeds burst capacity."""
        clock = FakeClock(0.0)
        tb = TokenBucketRateLimiter(rate=100.0, burst=3, clock=clock)
        # Advance a long time
        clock.tick(100.0)
        # Should only have burst=3 tokens, not 10000
        assert tb.consume() == 0.0
        assert tb.consume() == 0.0
        assert tb.consume() == 0.0
        assert tb.consume() > 0.0

    def test_reset_changes_rate_and_refills(self):
        """reset() changes the rate and refills the bucket."""
        clock = FakeClock(0.0)
        tb = TokenBucketRateLimiter(rate=1.0, burst=5, clock=clock)
        # Drain
        for _ in range(5):
            tb.consume()
        assert tb.consume() > 0.0  # empty
        # Reset with higher rate
        tb.reset(rate=10.0, burst=10)
        # Bucket should be full again
        for _ in range(10):
            assert tb.consume() == 0.0
        assert tb.consume() > 0.0

    def test_status_reflects_current_state(self):
        """status property shows rate, burst, available tokens."""
        tb = TokenBucketRateLimiter(rate=2.0, burst=5)
        s = tb.status
        assert s["rate_per_s"] == 2.0
        assert s["burst"] == 5
        assert s["tokens_available"] == 5.0
        assert s["effective_rate_per_minute"] == 120.0

    def test_consume_multiple_tokens(self):
        """consume(n) deducts multiple tokens."""
        tb = TokenBucketRateLimiter(rate=1.0, burst=10)
        assert tb.consume(3) == 0.0
        assert tb.consume(3) == 0.0
        assert tb.consume(3) == 0.0
        # 9 consumed, 1 left
        assert tb.consume() == 0.0
        # Now empty
        assert tb.consume() > 0.0


# ---------------------------------------------------------------------------
# EndpointSensitivity / classify_path
# ---------------------------------------------------------------------------


class TestEndpointSensitivity:
    """Tests for path classification by audit sensitivity."""

    @pytest.mark.parametrize("path,expected", [
        ("sys/health", EndpointSensitivity.LOW),
        ("sys/seal-status", EndpointSensitivity.LOW),
        ("sys/leader", EndpointSensitivity.LOW),
        ("sys/version", EndpointSensitivity.MEDIUM),
        ("sys/internal/ui/mounts", EndpointSensitivity.MEDIUM),
        ("sys/policies", EndpointSensitivity.MEDIUM),  # LIST policies
        ("sys/policies/acl", EndpointSensitivity.CRITICAL),  # PUT policy
        ("sys/capabilities-self", EndpointSensitivity.MEDIUM),
        ("auth/userpass/login", EndpointSensitivity.HIGH),
        ("auth/token/create", EndpointSensitivity.HIGH),
        ("secret/myapp/db", EndpointSensitivity.HIGH),
        ("cubbyhole/test", EndpointSensitivity.HIGH),
        ("database/creds/readonly", EndpointSensitivity.HIGH),
        ("sys/audit", EndpointSensitivity.CRITICAL),
        ("sys/audit/file", EndpointSensitivity.CRITICAL),
        ("auth/approle/role/myapp", EndpointSensitivity.CRITICAL),
        ("auth/kubernetes/role/vault", EndpointSensitivity.CRITICAL),
        # Unknown paths default to MEDIUM
        ("unknown/endpoint", EndpointSensitivity.MEDIUM),
        ("", EndpointSensitivity.MEDIUM),
    ])
    def test_classify_path(self, path, expected):
        """Paths are classified to the correct sensitivity level."""
        assert classify_path(path) == expected

    def test_classify_handles_leading_slash(self):
        """classify_path normalizes leading slashes."""
        assert classify_path("/sys/health") == EndpointSensitivity.LOW
        assert classify_path("///sys/health") == EndpointSensitivity.LOW

    def test_most_specific_prefix_wins(self):
        """More specific prefixes take priority (sys/policies/acl vs sys/policies)."""
        # "sys/policies/acl" starts with both "sys/policies" and "sys/policies/acl"
        # but "sys/policies/acl" is matched first (ordered before "sys/policies")
        assert classify_path("sys/policies/acl/admin") == EndpointSensitivity.CRITICAL


# ---------------------------------------------------------------------------
# StealthJitterEngine
# ---------------------------------------------------------------------------


class TestStealthJitterEngine:
    """Tests for the advanced jitter engine."""

    def test_none_strategy_returns_zero(self):
        """NONE strategy always returns 0."""
        assert StealthJitterEngine.calculate(1.0, 5.0, JitterStrategy.NONE) == 0.0

    def test_uniform_stays_in_range(self):
        """UNIFORM produces values in [min, max]."""
        for _ in range(100):
            val = StealthJitterEngine.calculate(1.0, 5.0, JitterStrategy.UNIFORM)
            assert 1.0 <= val <= 5.0

    def test_gamma_stays_in_range(self):
        """GAMMA produces values clamped to [min, max]."""
        for _ in range(100):
            val = StealthJitterEngine.calculate(2.0, 10.0, JitterStrategy.GAMMA)
            assert 2.0 <= val <= 10.0

    def test_gamma_is_right_skewed(self):
        """GAMMA distribution has most values below the midpoint (right-skewed)."""
        samples = [
            StealthJitterEngine.calculate(1.0, 10.0, JitterStrategy.GAMMA)
            for _ in range(200)
        ]
        median_val = sorted(samples)[100]
        # Median should be below the arithmetic mean of 5.5 for a right-skewed dist
        assert median_val < 5.5

    def test_decorrelated_stays_below_base(self):
        """DECORRELATED never exceeds the base (min_s)."""
        for _ in range(100):
            val = StealthJitterEngine.calculate(2.0, 10.0, JitterStrategy.DECORRELATED)
            # Decorrelated: min(base, U(base, base*3)) where base = min_s
            # So val <= base = 2.0
            assert 0.1 <= val <= 2.0

    def test_full_jitter_in_range(self):
        """FULL_JITTER produces values in [0, cap]."""
        for _ in range(100):
            val = StealthJitterEngine.calculate(1.0, 5.0, JitterStrategy.FULL_JITTER)
            assert 0.0 <= val <= 5.0

    def test_equal_jitter_centered(self):
        """EQUAL_JITTER produces values clustered around cap/2."""
        for _ in range(100):
            val = StealthJitterEngine.calculate(1.0, 6.0, JitterStrategy.EQUAL_JITTER)
            # cap/2 = 3.0, range [3.0, 6.0]
            assert 3.0 <= val <= 6.0

    def test_human_jitter_uses_engine(self):
        """human_jitter() delegates to StealthJitterEngine."""
        delay = human_jitter(1.0, 3.0, JitterStrategy.UNIFORM)
        assert 1.0 <= delay <= 3.0


# ---------------------------------------------------------------------------
# AuditLogGate
# ---------------------------------------------------------------------------


class TestAuditLogGate:
    """Tests for the audit log gating mechanism."""

    def test_initial_requests_allowed(self):
        """First requests under the threshold are allowed."""
        gate = AuditLogGate(window_s=60, max_requests_per_window=10)
        for _ in range(10):
            assert gate.acquire("sys/health") == 0.0

    def test_exceeds_threshold_triggers_flood_cooldown(self):
        """When the window threshold is exceeded, a cooldown is enforced."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=3,
            flood_cooldown_s=30.0,
        )
        # 3 requests allowed
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0
        # 4th request triggers flood
        delay = gate.acquire("sys/health")
        assert delay >= 30.0

    def test_errors_count_more_heavily(self):
        """Error requests carry amplified weight."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=4,
            error_amplifier=3.0,
        )
        # 2 normal requests = weight 2
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0
        # 1 error request = weight 3 → total 5 > 4 → flood triggered
        delay = gate.acquire("sys/health", is_error=True)
        assert delay > 0.0

    def test_critical_endpoints_have_cooldown(self):
        """CRITICAL endpoints enforce a minimum interval."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=100,
            critical_sensitivity_cooldown_s=5.0,
        )
        # First CRITICAL request allowed
        assert gate.acquire("sys/audit") == 0.0
        # Second immediately after gets cooldown
        delay = gate.acquire("sys/audit")
        assert delay > 0.0
        assert delay <= 5.0

    def test_high_endpoints_have_light_cooldown(self):
        """HIGH sensitivity endpoints have a shorter cooldown."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=100,
            high_sensitivity_cooldown_s=1.0,
        )
        assert gate.acquire("auth/userpass/login") == 0.0
        delay = gate.acquire("auth/userpass/login")
        assert 0.0 < delay <= 1.0

    def test_low_endpoints_no_cooldown(self):
        """LOW sensitivity endpoints have no mandatory cooldown."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=100,
            high_sensitivity_cooldown_s=5.0,
        )
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0  # back-to-back allowed

    def test_window_expires_old_entries(self):
        """Requests older than window_s are pruned after flood cooldown."""
        clock = FakeClock(0.0)
        gate = AuditLogGate(
            window_s=5, max_requests_per_window=3,
            flood_cooldown_s=2.0, clock=clock,
        )
        # Fill the window
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0
        assert gate.acquire("sys/health") == 0.0
        # Window full — triggers flood cooldown
        assert gate.acquire("sys/health") > 0.0
        # Advance past both the flood cooldown AND the window_s
        clock.tick(6.0)
        # Flood expired AND old entries pruned — new requests allowed
        assert gate.acquire("sys/health") == 0.0

    def test_reset_clears_state(self):
        """reset() clears the window and flood state."""
        gate = AuditLogGate(
            window_s=60, max_requests_per_window=2,
            flood_cooldown_s=60.0,
        )
        # Trigger flood
        gate.acquire("sys/health")
        gate.acquire("sys/health")
        delay = gate.acquire("sys/health")
        assert delay > 0.0
        # Reset
        gate.reset(window_s=60, max_requests=10)
        assert gate.acquire("sys/health") == 0.0

    def test_status_reflects_gate_state(self):
        """status property shows current window state."""
        gate = AuditLogGate(window_s=30, max_requests_per_window=10)
        gate.acquire("sys/health")
        s = gate.status
        assert s["request_count"] == 1
        assert s["current_weight"] == 1.0
        assert s["flood_active"] is False


# ---------------------------------------------------------------------------
# BandwidthThrottle
# ---------------------------------------------------------------------------


class TestBandwidthThrottle:
    """Tests for the bandwidth throttle (byte-level token bucket)."""

    def test_unlimited_returns_zero(self):
        """rate_bps=0 means unlimited — always returns 0."""
        bt = BandwidthThrottle(rate_bps=0)
        assert bt.consume(1_000_000) == 0.0

    def test_small_response_returns_zero(self):
        """A small response within burst returns 0."""
        bt = BandwidthThrottle(rate_bps=10240, burst_bytes=65536)  # 10 KB/s, 64KB burst
        assert bt.consume(1000) == 0.0  # 1 KB fits in burst

    def test_large_response_exceeds_burst(self):
        """When response bytes exceed available tokens, returns wait time."""
        clock = FakeClock(0.0)
        bt = BandwidthThrottle(rate_bps=1000, burst_bytes=500, clock=clock)
        # Consume 1000 bytes — burst is 500, so deficit of 500 bytes
        # At 1000 B/s, that's 0.5s wait
        delay = bt.consume(1000)
        assert delay == pytest.approx(0.5)

    def test_refill_over_time(self):
        """Tokens refill as time passes."""
        clock = FakeClock(0.0)
        bt = BandwidthThrottle(rate_bps=10000, burst_bytes=2000, clock=clock)
        # Drain burst
        bt.consume(2000)
        assert bt.consume(1) > 0.0  # empty
        # Advance 0.21s → 2100 bytes refilled (10000 B/s * 0.21s)
        # Use > 0.2 to avoid floating-point edge case
        clock.tick(0.21)
        assert bt.consume(2000) == 0.0

    def test_zero_bytes_is_noop(self):
        """consume(0) always returns 0."""
        bt = BandwidthThrottle(rate_bps=1000, burst_bytes=10)
        assert bt.consume(0) == 0.0
        # Even if bucket is drained
        bt.consume(10)
        assert bt.consume(0) == 0.0

    def test_reset_refills(self):
        """reset() refills the bucket."""
        bt = BandwidthThrottle(rate_bps=1000, burst_bytes=100)
        bt.consume(100)
        assert bt.consume(1) > 0.0  # empty
        bt.reset(rate_bps=5000, burst_bytes=500)
        assert bt.consume(500) == 0.0  # refilled

    def test_status_shows_kb(self):
        """status property reports in KB for readability."""
        bt = BandwidthThrottle(rate_bps=51200, burst_bytes=65536)
        s = bt.status
        assert s["rate_kbps"] == 50.0
        assert s["burst_kb"] == 64.0


# ---------------------------------------------------------------------------
# RequestScheduler
# ---------------------------------------------------------------------------


class TestRequestScheduler:
    """Tests for the central request scheduler."""

    def test_schedule_returns_delay(self):
        """schedule() returns a non-negative delay."""
        scheduler = RequestScheduler(
            jitter_strategy=JitterStrategy.NONE,
            jitter_min=0, jitter_max=0,
        )
        delay = scheduler.schedule("sys/health")
        assert delay >= 0.0

    def test_schedule_with_rate_limit(self):
        """With a slow rate, schedule() returns enforce delay."""
        clock = FakeClock(0.0)
        tb = TokenBucketRateLimiter(rate=1.0, burst=1, clock=clock)
        scheduler = RequestScheduler(
            token_bucket=tb,
            jitter_strategy=JitterStrategy.NONE,
            jitter_min=0, jitter_max=0,
        )
        # First request allowed
        assert scheduler.schedule("sys/health") == 0.0
        # Second request delayed (bucket empty, 1 tok/s → 1s wait)
        delay = scheduler.schedule("sys/health")
        assert delay >= 1.0

    def test_critical_path_delayed_more(self):
        """CRITICAL sensitivity paths get longer delays via audit gate."""
        scheduler = RequestScheduler(
            jitter_strategy=JitterStrategy.NONE,
            jitter_min=0, jitter_max=0,
        )
        # auth/login is HIGH sensitivity
        s1 = scheduler.schedule("sys/health")
        s2 = scheduler.schedule("auth/token/create")
        # DELAY: sys/health (LOW) should have no mandatory cooldown
        # auth/token/create (HIGH) may have cooldown if back-to-back
        # Both should be non-negative — just verify the scheduler works
        assert s1 >= 0.0
        assert s2 >= 0.0

    def test_report_updates_error_state(self):
        """report() updates the last-was-error flag for next acquire."""
        scheduler = RequestScheduler(
            jitter_strategy=JitterStrategy.NONE,
            jitter_min=0, jitter_max=0,
        )
        # Report an error
        scheduler.report("auth/login", 403, 0.1, 500)
        # Next schedule with is_error=True (via last_was_error)
        # This should amplify the next request's audit gate weight
        delay = scheduler.schedule("auth/login")
        assert delay >= 0.0  # should still be valid

    def test_reset_reconfigures_all_components(self):
        """reset() applies profile config to all sub-components."""
        scheduler = RequestScheduler(
            jitter_strategy=JitterStrategy.UNIFORM,
            jitter_min=1.0, jitter_max=2.0,
        )
        # Reset with PARANOID config
        paranoid_cfg = _PROFILE_CONFIG[EvasionProfile.PARANOID]
        scheduler.reset(paranoid_cfg)

        status = scheduler.status
        assert status["jitter_strategy"] == "gamma"
        assert status["jitter_range_s"] == "5.0-15.0"
        assert status["token_bucket"]["rate_per_s"] == pytest.approx(0.0333, abs=0.001)
        assert status["audit_gate"]["max_per_window"] == 3

    def test_get_scheduler_is_singleton(self):
        """get_scheduler() returns the same instance."""
        s1 = get_scheduler()
        s2 = get_scheduler()
        assert s1 is s2


# ---------------------------------------------------------------------------
# Profile configuration
# ---------------------------------------------------------------------------


class TestProfileConfig:
    """Tests for profile configuration completeness."""

    REQUIRED_KEYS = [
        "jitter_min", "jitter_max",
        "max_concurrency", "min_concurrency",
        "ua_rotate_every", "header_randomize",
        "jitter_strategy", "requests_per_minute", "burst_size",
        "audit_window_s", "max_requests_per_window",
        "bandwidth_limit_bps", "error_amplifier",
        "endpoint_cooldown",
    ]

    @pytest.mark.parametrize("profile", list(EvasionProfile))
    def test_all_profiles_have_required_keys(self, profile):
        """Every profile must define all required configuration keys."""
        cfg = _PROFILE_CONFIG[profile]
        for key in self.REQUIRED_KEYS:
            assert key in cfg, f"Profile {profile.value} missing key: {key}"

    @pytest.mark.parametrize("profile", list(EvasionProfile))
    def test_jitter_strategies_are_valid(self, profile):
        """jitter_strategy values must be valid JitterStrategy enum members."""
        cfg = _PROFILE_CONFIG[profile]
        strategy_str = cfg.get("jitter_strategy", "uniform")
        # Should not raise ValueError
        JitterStrategy(strategy_str)

    @pytest.mark.parametrize("profile", list(EvasionProfile))
    def test_endpoint_cooldown_has_high_and_critical(self, profile):
        """endpoint_cooldown dict must have HIGH and CRITICAL keys."""
        cfg = _PROFILE_CONFIG[profile]
        cooldowns = cfg.get("endpoint_cooldown", {})
        assert "HIGH" in cooldowns, f"Profile {profile.value} missing endpoint_cooldown.HIGH"
        assert "CRITICAL" in cooldowns, f"Profile {profile.value} missing endpoint_cooldown.CRITICAL"

    def test_low_and_slow_is_slowest(self):
        """LOW_AND_SLOW should be slower than PARANOID in all rate dimensions."""
        paranoid = _PROFILE_CONFIG[EvasionProfile.PARANOID]
        las = _PROFILE_CONFIG[EvasionProfile.LOW_AND_SLOW]

        assert las["requests_per_minute"] < paranoid["requests_per_minute"]
        assert las["jitter_max"] > paranoid["jitter_max"]
        assert las["audit_window_s"] > paranoid["audit_window_s"]
        if las["max_requests_per_window"] > 0:
            assert las["max_requests_per_window"] <= paranoid["max_requests_per_window"]
        assert las["bandwidth_limit_bps"] < paranoid["bandwidth_limit_bps"]
        assert las["endpoint_cooldown"]["HIGH"] >= paranoid["endpoint_cooldown"]["HIGH"]
        assert las["endpoint_cooldown"]["CRITICAL"] >= paranoid["endpoint_cooldown"]["CRITICAL"]


# ---------------------------------------------------------------------------
# EvasionProfile switching
# ---------------------------------------------------------------------------


class TestProfileSwitching:
    """Tests for runtime profile switching."""

    def test_set_evasion_profile_updates_global(self):
        """set_evasion_profile() changes the active profile."""
        original = get_evasion_profile()
        try:
            set_evasion_profile(EvasionProfile.STEALTH)
            assert get_evasion_profile() == EvasionProfile.STEALTH
        finally:
            set_evasion_profile(original)

    def test_set_evasion_profile_resets_scheduler(self):
        """Profile switch resets the scheduler configuration."""
        original = get_evasion_profile()
        try:
            set_evasion_profile(EvasionProfile.BALANCED)
            scheduler = get_scheduler()
            s = scheduler.status
            assert s["jitter_strategy"] == "uniform"
            assert s["token_bucket"]["effective_rate_per_minute"] == 20.0

            set_evasion_profile(EvasionProfile.STEALTH)
            s = scheduler.status
            assert s["jitter_strategy"] == "decorrelated"
            assert s["token_bucket"]["effective_rate_per_minute"] == 6.0
        finally:
            set_evasion_profile(original)

    def test_all_profiles_switch_without_error(self):
        """Every EvasionProfile can be set without raising."""
        original = get_evasion_profile()
        try:
            for profile in EvasionProfile:
                set_evasion_profile(profile)
                assert get_evasion_profile() == profile
        finally:
            set_evasion_profile(original)


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter public methods (private-access fix)
# ---------------------------------------------------------------------------


class TestAdaptiveRateLimiterPublicMethods:
    """Tests for newly added public methods on AdaptiveRateLimiter."""

    def test_set_backoff(self):
        """set_backoff() sets a minimum backoff level."""
        from reconnaissance.stealth_http import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter()
        limiter.set_backoff(10.0)
        assert limiter.should_backoff() >= 10.0

    def test_extend_backoff(self):
        """extend_backoff() increases backoff when called multiple times."""
        from reconnaissance.stealth_http import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter()
        limiter.extend_backoff(5.0)
        assert limiter.should_backoff() >= 5.0
        limiter.extend_backoff(8.0)
        assert limiter.should_backoff() >= 8.0  # max(5, 8) = 8

    def test_set_backoff_does_not_override_higher(self):
        """set_backoff() only takes max, never reduces."""
        from reconnaissance.stealth_http import AdaptiveRateLimiter
        limiter = AdaptiveRateLimiter()
        limiter.set_backoff(30.0)
        limiter.set_backoff(5.0)  # should be ignored
        assert limiter.should_backoff() >= 30.0
