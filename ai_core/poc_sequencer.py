"""PoC Sequencer — chains parsed actions into ordered attack plans.

Analyses the dependency graph between PoC actions and builds
auto-ordered execution chains.  If action A produces a token and
action B needs one, they are sequenced: A → B.

The sequencer recognises these Vault-specific data flows:

    token_create          → any_authenticated_request
    approle_login         → any_authenticated_request
    policy_create/update  → token_create (with that policy)
    database/creds/*      → direct DB connection
    transit/encrypt       → transit/decrypt (key reuse)

In auto-pilot mode the entire chain is executed without stopping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ai_core.poc_parser import PoCAction, _confidence_rank


# ---------------------------------------------------------------------------
# Chain data structures
# ---------------------------------------------------------------------------


class StepRole(str, Enum):
    PRODUCER = "producer"    # creates a resource (token, credential)
    CONSUMER = "consumer"    # uses a resource
    STANDALONE = "standalone"  # neither produces nor consumes


@dataclass
class SequencedStep:
    """A single step in a PoC execution chain."""

    action: PoCAction
    role: StepRole = StepRole.STANDALONE
    produces: str = ""       # what this step outputs (e.g. "token", "db_password")
    consumes: str = ""       # what this step needs from a previous step
    depends_on: int = -1     # index of prerequisite step (-1 = none)
    step_index: int = 0      # position in the chain


@dataclass
class PoCChain:
    """An ordered chain of PoC actions ready for execution."""

    chain_id: str
    steps: list[SequencedStep] = field(default_factory=list)
    description: str = ""
    total_confidence: str = "medium"

    def to_plan_steps(self, vault_addr: str = "") -> list[dict[str, Any]]:
        """Convert to plan step dicts for ``run_with_plan`` or agent display."""
        plan_steps: list[dict] = []
        for i, step in enumerate(self.steps, 1):
            params = step.action.to_tool_params(vault_addr)
            plan_steps.append({
                "step": i,
                "tool": "run_raw_vault_request",
                "reason": step.action.description,
                "params": params,
                "produces": step.produces,
                "consumes": step.consumes,
                "depends_on": step.depends_on,
                "role": step.role.value,
                "confidence": step.action.confidence,
            })
        return plan_steps

    def to_agent_prompt(self, vault_addr: str = "") -> str:
        """Format the chain as a readable prompt for the LLM agent."""
        if not self.steps:
            return ""

        lines = [
            f"\n[ATTACK CHAIN] {self.description}",
            f"  Confidence: {self.total_confidence} | Steps: {len(self.steps)}",
            "",
        ]
        for step in self.steps:
            icon = {StepRole.PRODUCER: "[+]", StepRole.CONSUMER: "[>]",
                    StepRole.STANDALONE: "[ ]"}.get(step.role, "[?]")
            dep = f"  ← depends on step {step.depends_on}" if step.depends_on >= 0 else ""
            produce = f"  → produces: {step.produces}" if step.produces else ""
            lines.append(
                f"  {icon} Step {step.step_index}: {step.action.method} {step.action.path}"
                f" [{step.action.confidence}]{dep}{produce}"
            )
            if step.action.body:
                body_str = str(step.action.body)[:100]
                lines.append(f"       body: {body_str}")

        lines.append("")
        lines.append(
            "Execute this chain in order using run_raw_vault_request. "
            "After step 1, capture the client_token from the response "
            "and pass it as the token parameter for subsequent steps."
        )
        lines.append(
            "In auto-pilot mode, execute ALL steps without asking for confirmation."
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Producer / consumer detection
# ---------------------------------------------------------------------------

# Paths that PRODUCE tokens or credentials
_PRODUCER_PATTERNS: list[tuple[str, str, str]] = [
    # (method, path_regex, produces)
    ("POST", r"auth/token/create", "vault_token"),
    ("POST", r"auth/token/create-orphan", "vault_token"),
    ("POST", r"auth/token/create/(.+)", "vault_token"),
    ("POST", r"auth/approle/login", "vault_token"),
    ("POST", r"auth/userpass/login/(.+)", "vault_token"),
    ("POST", r"auth/kubernetes/login", "vault_token"),
    ("POST", r"auth/aws/login", "vault_token"),
    ("POST", r"auth/ldap/login/(.+)", "vault_token"),
    ("POST", r"auth/gcp/login", "vault_token"),
    ("GET",  r"database/creds/(.+)", "db_credentials"),
    ("POST", r"database/static-creds/(.+)", "db_credentials"),
    ("PUT",  r"sys/policies/acl/(.+)", "policy"),
    ("POST", r"sys/policies/acl/(.+)", "policy"),
    ("POST", r"pki/issue/(.+)", "certificate"),
    ("POST", r"transit/encrypt/(.+)", "ciphertext"),
]

# Paths that CONSUME tokens (everything except auth/login and sys/health)
_CONSUMER_INDICATORS = [
    r"^secret/", r"^sys/(?!health|seal-status|leader)", r"^database/(?!creds)",
    r"^pki/(?!issue)", r"^transit/(?!encrypt)", r"^identity/",
    r"^auth/token/lookup", r"^auth/token/renew", r"^auth/token/revoke",
]


# ---------------------------------------------------------------------------
# Sequencer
# ---------------------------------------------------------------------------


class PoCSequencer:
    """Analyses PoC actions and builds ordered execution chains.

    1. Classifies each action as PRODUCER / CONSUMER / STANDALONE.
    2. Detects dependencies: if action A produces a token and action B
       needs authentication, B depends on A.
    3. Topologically sorts actions into ordered chains.
    4. Generates an agent-ready prompt or plan.
    """

    def build_chains(self, actions: list[PoCAction]) -> list[PoCChain]:
        """Build one or more ordered chains from parsed PoC actions.

        Actions that can be sequenced together are grouped.  Standalone
        actions form single-step chains.
        """
        if not actions:
            return []

        # ── 1. Classify each action ────────────────────────────────────
        classified = self._classify_actions(actions)

        # ── 2. Build dependency graph ──────────────────────────────────
        producers = [c for c in classified if c.role == StepRole.PRODUCER]
        consumers = [c for c in classified if c.role == StepRole.CONSUMER]
        standalones = [c for c in classified if c.role == StepRole.STANDALONE]

        chains: list[PoCChain] = []

        # ── 3. Chain: producer → consumers that need it ────────────────
        used_consumers: set[int] = set()

        for producer in producers:
            chain_steps = [producer]
            step_idx = 1
            producer.step_index = step_idx
            step_idx += 1

            for ci, consumer in enumerate(consumers):
                if ci in used_consumers:
                    continue

                # Consumer depends on this producer if:
                # - Producer makes a token and consumer needs auth
                # - Producer makes a policy and consumer creates a token with that policy
                if self._depends_on(consumer, producer):
                    consumer.depends_on = 1  # depends on step 1
                    consumer.step_index = step_idx
                    step_idx += 1
                    chain_steps.append(consumer)
                    used_consumers.add(ci)

            chain = PoCChain(
                chain_id=f"chain_{len(chains)+1}",
                steps=chain_steps,
                description=self._describe_chain(chain_steps),
                total_confidence=self._overall_confidence(chain_steps),
            )
            chains.append(chain)

        # ── 4. Remaining consumers → attach to existing chain or standalone ──
        unpaired = [c for ci, c in enumerate(consumers) if ci not in used_consumers]
        if unpaired:
            attached = False
            # Try attaching to a chain with a token producer
            for chain in chains:
                if any(s.produces == "vault_token" for s in chain.steps):
                    for consumer in unpaired:
                        consumer.depends_on = 1
                        consumer.step_index = len(chain.steps) + 1
                        chain.steps.append(consumer)
                    attached = True
                    break
            # If no chain to attach to, make each unpaired consumer its own chain
            if not attached:
                for consumer in unpaired:
                    consumer.step_index = 1
                    chains.append(PoCChain(
                        chain_id=f"chain_{len(chains)+1}",
                        steps=[consumer],
                        description=f"Unpaired consumer: {consumer.action.method} {consumer.action.path}",
                        total_confidence=consumer.action.confidence,
                    ))

        # ── 5. Standalone actions → single-step chains ─────────────────
        for standalone in standalones:
            standalone.step_index = 1
            chains.append(PoCChain(
                chain_id=f"chain_{len(chains)+1}",
                steps=[standalone],
                description=f"Standalone: {standalone.action.method} {standalone.action.path}",
                total_confidence=standalone.action.confidence,
            ))

        return chains

    def _classify_actions(self, actions: list[PoCAction]) -> list[SequencedStep]:
        """Classify each action as PRODUCER, CONSUMER, or STANDALONE."""
        steps: list[SequencedStep] = []
        for action in actions:
            role = StepRole.STANDALONE
            produces = ""

            # Check if producer
            for method, path_pattern, resource in _PRODUCER_PATTERNS:
                if action.method.upper() == method.upper():
                    if re.match(path_pattern, action.path, re.IGNORECASE):
                        role = StepRole.PRODUCER
                        produces = resource
                        break

            # Check if consumer (only if not already a producer)
            consumes = ""
            if role != StepRole.PRODUCER:
                for indicator in _CONSUMER_INDICATORS:
                    if re.match(indicator, action.path, re.IGNORECASE):
                        role = StepRole.CONSUMER
                        consumes = "vault_token"
                        break

            steps.append(SequencedStep(
                action=action,
                role=role,
                produces=produces,
                consumes=consumes,
            ))

        return steps

    @staticmethod
    def _depends_on(consumer: SequencedStep, producer: SequencedStep) -> bool:
        """Does *consumer* depend on the resource *producer* creates?"""
        if not producer.produces or not consumer.consumes:
            return False

        # Token producer → any consumer
        if producer.produces == "vault_token" and consumer.consumes == "vault_token":
            return True

        # Policy producer → token creation that might reference that policy
        if producer.produces == "policy" and "token/create" in consumer.action.path.lower():
            return True

        # DB credentials producer → any DB-related consumer
        if producer.produces == "db_credentials" and "database" in consumer.action.path.lower():
            return True

        return False

    @staticmethod
    def _describe_chain(steps: list[SequencedStep]) -> str:
        if not steps:
            return "Empty chain"
        if len(steps) == 1:
            return f"Single-step: {steps[0].action.method} {steps[0].action.path}"

        producers = [s for s in steps if s.role == StepRole.PRODUCER]
        consumers = [s for s in steps if s.role == StepRole.CONSUMER]
        parts = []
        if producers:
            parts.append(f"{len(producers)} producer(s)")
        if consumers:
            parts.append(f"{len(consumers)} consumer(s)")
        return " → ".join(parts) if parts else f"{len(steps)}-step chain"

    @staticmethod
    def _overall_confidence(steps: list[SequencedStep]) -> str:
        ranks = [_confidence_rank(s.action.confidence) for s in steps]
        if not ranks:
            return "low"
        # Weighted: producers count more
        avg = sum(ranks) / len(ranks)
        if avg >= 2.5:
            return "high"
        if avg >= 1.5:
            return "medium"
        return "low"


# ---------------------------------------------------------------------------
# Integration helper — use from agent web-search flow
# ---------------------------------------------------------------------------


def build_chains_from_pocs(
    actions: list[PoCAction],
    vault_addr: str = "",
) -> tuple[list[PoCChain], str]:
    """Build chains from PoC actions and produce an agent-ready prompt.

    Returns (chains, prompt_text).
    """
    sequencer = PoCSequencer()
    chains = sequencer.build_chains(actions)

    if not chains:
        return [], ""

    prompt_parts = []
    for chain in chains:
        prompt_parts.append(chain.to_agent_prompt(vault_addr))

    return chains, "\n".join(prompt_parts)
