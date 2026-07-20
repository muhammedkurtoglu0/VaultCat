"""Tests for PoC sequencer — chain ordering, dependency detection, edge cases."""
import pytest
from ai_core.poc_parser import PoCAction, parse_poc_actions
from ai_core.poc_sequencer import (
    PoCChain,
    PoCSequencer,
    SequencedStep,
    StepRole,
    build_chains_from_pocs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action(method: str, path: str, confidence: str = "high") -> PoCAction:
    return PoCAction(method=method, path=path, description="test", confidence=confidence)


def _actions(*specs) -> list[PoCAction]:
    return [_action(m, p, c) for m, p, c in specs]


# ---------------------------------------------------------------------------
# Classification tests
# ---------------------------------------------------------------------------


class TestClassification:
    """Test that actions are correctly classified as PRODUCER / CONSUMER / STANDALONE."""

    def test_token_create_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("POST", "auth/token/create")])
        assert steps[0].role == StepRole.PRODUCER
        assert steps[0].produces == "vault_token"

    def test_token_create_orphan_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("POST", "auth/token/create-orphan")])
        assert steps[0].role == StepRole.PRODUCER
        assert steps[0].produces == "vault_token"

    def test_approle_login_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("POST", "auth/approle/login")])
        assert steps[0].role == StepRole.PRODUCER
        assert steps[0].produces == "vault_token"

    def test_userpass_login_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("POST", "auth/userpass/login/admin")])
        assert steps[0].role == StepRole.PRODUCER

    def test_db_creds_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("GET", "database/creds/readonly")])
        assert steps[0].role == StepRole.PRODUCER
        assert steps[0].produces == "db_credentials"

    def test_policy_create_is_producer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("PUT", "sys/policies/acl/admin")])
        assert steps[0].role == StepRole.PRODUCER
        assert steps[0].produces == "policy"

    def test_secret_read_is_consumer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("GET", "secret/data/admin")])
        assert steps[0].role == StepRole.CONSUMER
        assert steps[0].consumes == "vault_token"

    def test_sys_mounts_is_consumer(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("GET", "sys/mounts")])
        assert steps[0].role == StepRole.CONSUMER

    def test_sys_health_is_standalone(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("GET", "sys/health")])
        assert steps[0].role == StepRole.STANDALONE

    def test_sys_seal_status_is_standalone(self):
        seq = PoCSequencer()
        steps = seq._classify_actions([_action("GET", "sys/seal-status")])
        assert steps[0].role == StepRole.STANDALONE


# ---------------------------------------------------------------------------
# Dependency detection tests
# ---------------------------------------------------------------------------


class TestDependencyDetection:
    """Test that consumer-producer dependencies are correctly identified."""

    def test_consumer_depends_on_token_producer(self):
        producer = SequencedStep(action=_action("POST", "auth/token/create"),
                                 role=StepRole.PRODUCER, produces="vault_token")
        consumer = SequencedStep(action=_action("GET", "secret/data/admin"),
                                 role=StepRole.CONSUMER, consumes="vault_token")
        assert PoCSequencer._depends_on(consumer, producer) is True

    def test_consumer_no_depends_on_unrelated_producer(self):
        producer = SequencedStep(action=_action("GET", "database/creds/readonly"),
                                 role=StepRole.PRODUCER, produces="db_credentials")
        consumer = SequencedStep(action=_action("GET", "sys/mounts"),
                                 role=StepRole.CONSUMER, consumes="vault_token")
        # DB credentials producer does NOT satisfy vault_token consumer
        assert PoCSequencer._depends_on(consumer, producer) is False

    def test_standalone_no_dependency(self):
        producer = SequencedStep(action=_action("POST", "auth/token/create"),
                                 role=StepRole.PRODUCER, produces="vault_token")
        standalone = SequencedStep(action=_action("GET", "sys/health"),
                                   role=StepRole.STANDALONE)
        assert PoCSequencer._depends_on(standalone, producer) is False


# ---------------------------------------------------------------------------
# Chain building tests
# ---------------------------------------------------------------------------


class TestChainBuilding:
    """Test that actions are correctly sequenced into ordered chains."""

    def test_empty_actions_returns_empty(self):
        chains = PoCSequencer().build_chains([])
        assert chains == []

    def test_single_producer_becomes_chain(self):
        chains = PoCSequencer().build_chains([_action("POST", "auth/token/create")])
        assert len(chains) == 1
        assert len(chains[0].steps) == 1

    def test_single_consumer_becomes_chain(self):
        chains = PoCSequencer().build_chains([_action("GET", "secret/data/admin")])
        assert len(chains) == 1
        assert chains[0].steps[0].role == StepRole.CONSUMER

    def test_producer_consumer_are_chained(self):
        """Producer + consumer → single chain, consumer depends on step 1."""
        actions = [
            _action("POST", "auth/token/create"),
            _action("GET", "secret/data/admin"),
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) >= 1

        # Should have a chain with 2 steps: producer → consumer
        chain = chains[0]
        assert len(chain.steps) == 2
        assert chain.steps[0].role == StepRole.PRODUCER
        assert chain.steps[1].role == StepRole.CONSUMER
        assert chain.steps[1].depends_on == 1

    def test_multiple_consumers_depend_on_producer(self):
        """One producer, 3 consumers → all consumers depend on step 1."""
        actions = [
            _action("POST", "auth/token/create"),
            _action("GET", "secret/data/admin"),
            _action("GET", "sys/mounts"),
            _action("GET", "auth/token/lookup-self"),
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) >= 1

        chain = chains[0]
        producers = [s for s in chain.steps if s.role == StepRole.PRODUCER]
        consumers = [s for s in chain.steps if s.role == StepRole.CONSUMER]
        assert len(producers) == 1
        assert len(consumers) == 3
        for c in consumers:
            assert c.depends_on == 1, f"Consumer {c.action.path} should depend on step 1"

    def test_standalones_form_separate_chains(self):
        actions = [
            _action("GET", "sys/health"),
            _action("GET", "sys/seal-status"),
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) == 2  # each standalone gets its own chain

    def test_step_indices_are_sequential(self):
        actions = [
            _action("POST", "auth/token/create"),
            _action("GET", "secret/data/admin"),
            _action("GET", "sys/mounts"),
        ]
        chains = PoCSequencer().build_chains(actions)
        chain = chains[0]
        indices = [s.step_index for s in chain.steps]
        assert indices == sorted(indices), f"Step indices should be sequential: {indices}"
        assert indices[0] == 1  # first step is always 1

    def test_consumer_without_producer_gets_chained(self):
        """Consumer without matching producer still forms a chain (pending dep)."""
        actions = [_action("GET", "secret/data/admin")]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) == 1
        assert chains[0].steps[0].consumes == "vault_token"


# ---------------------------------------------------------------------------
# Full pipeline: parse → sequence
# ---------------------------------------------------------------------------


class TestParseAndSequence:
    """End-to-end: raw text → parse → sequence chains."""

    def test_curl_token_create_and_secret_read(self):
        snippets = [
            'curl -X POST https://vault:8200/v1/auth/token/create -d \'{"policies":["admin"]}\'',
            'curl -X GET https://vault:8200/v1/secret/data/admin -H "X-Vault-Token: TOKEN"',
        ]
        all_actions = []
        for s in snippets:
            all_actions.extend(parse_poc_actions(s))

        chains = PoCSequencer().build_chains(all_actions)
        assert len(chains) >= 1
        chain = chains[0]
        producers = [s for s in chain.steps if s.role == StepRole.PRODUCER]
        consumers = [s for s in chain.steps if s.role == StepRole.CONSUMER]
        assert len(producers) >= 1
        assert len(consumers) >= 1

    def test_full_vault_attack_scenario(self):
        """Realistic scenario: create token → read secret → list mounts → get DB creds."""
        snippets = [
            'curl -X POST https://vault:8200/v1/auth/token/create-orphan -d \'{"policies":["admin"]}\'',
            'curl https://vault:8200/v1/secret/data/admin -H "X-Vault-Token: X"',
            'requests.get("https://vault:8200/v1/sys/mounts")',
            'vault read database/creds/readonly',
        ]
        all_actions = []
        for s in snippets:
            all_actions.extend(parse_poc_actions(s))

        chains = PoCSequencer().build_chains(all_actions)
        assert len(chains) >= 1

        # Should have at least one multi-step chain
        multi_step = [c for c in chains if len(c.steps) >= 2]
        assert len(multi_step) >= 1, f"Expected at least 1 multi-step chain, got {len(chains)} chains"

        # Token producer should be step 1 in its chain
        for chain in chains:
            for step in chain.steps:
                if step.produces == "vault_token":
                    assert step.step_index == 1, (
                        f"Token producer should be step 1, got {step.step_index}"
                    )

    def test_build_chains_from_pocs_integration(self):
        """Test the convenience function build_chains_from_pocs."""
        actions = [
            _action("POST", "auth/token/create"),
            _action("GET", "secret/data/admin"),
        ]
        chains, prompt = build_chains_from_pocs(actions, "https://vault:8200")
        assert len(chains) >= 1
        assert "ATTACK CHAIN" in prompt
        assert "auth/token/create" in prompt
        assert "secret/data/admin" in prompt


# ---------------------------------------------------------------------------
# Plan conversion tests
# ---------------------------------------------------------------------------


class TestPlanConversion:
    """Test that chains correctly convert to agent plan steps."""

    def test_to_plan_steps_format(self):
        actions = [
            _action("POST", "auth/token/create"),
            _action("GET", "secret/data/admin"),
        ]
        chains = PoCSequencer().build_chains(actions)
        plan = chains[0].to_plan_steps("https://v:8200")

        assert len(plan) == 2
        assert plan[0]["step"] == 1
        assert plan[0]["tool"] == "run_raw_vault_request"
        assert plan[0]["role"] == "producer"
        assert plan[1]["step"] == 2
        assert plan[1]["depends_on"] == 1
        assert plan[1]["role"] == "consumer"

    def test_plan_includes_vault_addr(self):
        actions = [_action("POST", "auth/token/create")]
        chains = PoCSequencer().build_chains(actions)
        plan = chains[0].to_plan_steps("https://custom:8200")
        assert "vault_addr" in plan[0]["params"]


# ---------------------------------------------------------------------------
# Confidence propagation tests
# ---------------------------------------------------------------------------


class TestConfidence:
    """Test that chain confidence is correctly computed."""

    def test_all_high_actions_gives_high_chain(self):
        actions = _actions(
            ("POST", "auth/token/create", "high"),
            ("GET", "secret/data/admin", "high"),
        )
        chains = PoCSequencer().build_chains(actions)
        assert chains[0].total_confidence == "high"

    def test_mixed_confidence_gives_medium(self):
        actions = _actions(
            ("POST", "auth/token/create", "high"),
            ("GET", "secret/data/admin", "low"),
        )
        chains = PoCSequencer().build_chains(actions)
        assert chains[0].total_confidence == "medium"

    def test_all_low_gives_low(self):
        chains = PoCSequencer().build_chains(
            [_action("GET", "sys/health", "low")]
        )
        assert chains[0].total_confidence == "low"


# ---------------------------------------------------------------------------
# Robustness tests
# ---------------------------------------------------------------------------


class TestRobustness:
    """Edge cases that could cause crashes."""

    def test_all_standalone_produces_separate_chains(self):
        """Each standalone gets its own chain — no grouping errors."""
        actions = [
            _action("GET", "sys/health"),
            _action("GET", "sys/seal-status"),
            _action("GET", "sys/leader"),
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) == 3
        for c in chains:
            assert len(c.steps) == 1

    def test_duplicate_actions_dont_crash(self):
        """Same action twice should not crash the sequencer."""
        actions = [
            _action("POST", "auth/token/create"),
            _action("POST", "auth/token/create"),  # duplicate
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) >= 1  # should not crash

    def test_no_producer_only_consumers(self):
        """All consumers, no producer — each forms its own chain gracefully."""
        actions = [
            _action("GET", "secret/data/admin"),
            _action("GET", "sys/mounts"),
        ]
        chains = PoCSequencer().build_chains(actions)
        assert len(chains) >= 1  # doesn't crash
        # Each consumer gets its own chain since no producer to attach to
        consumer_chains = [c for c in chains if c.steps[0].role == StepRole.CONSUMER]
        assert len(consumer_chains) >= 1

    def test_many_actions_dont_explode(self):
        """20 mixed actions — should produce chains without error."""
        actions = []
        for i in range(5):
            actions.append(_action("POST", f"auth/token/create/{i}"))
        for i in range(10):
            actions.append(_action("GET", f"secret/data/path{i}"))
        for i in range(5):
            actions.append(_action("GET", "sys/health"))

        chains = PoCSequencer().build_chains(actions)
        total_steps = sum(len(c.steps) for c in chains)
        assert total_steps >= len(actions)  # all actions are accounted for
