"""Mutation Engine — LLM-driven dynamic attack-tree branching.

Replaces static if/else planning with creative, adaptive attack paths.
When a tool fails or returns partial access, the engine asks the LLM:

    "Given this failure and these available assets, what are 3 alternative
     attack paths — ranked from most aggressive to stealthiest?"

Each branch becomes a new node in the attack tree.  The tree grows
dynamically as the pentest progresses, always adapting to new
information (tokens found, policies discovered, privileges escalated).

Enhancements over the original:
- **Proactive path generation**: Uses the Vault Attack Technique KB
  (``attack_techniques.py``) to suggest paths based on current state,
  not just reacting to failures.
- **Technique scoring**: Tracks success/failure per technique to rank
  future suggestions by expected value.
- **Multi-step chain building**: Follows technique followup_techniques
  to build full attack chains autonomously.
- **Dynamic state awareness**: Captures live pentest state (tokens,
  credentials, findings, accessible paths) for informed mutations.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from ai_core.attack_techniques import (
    AttackTechnique,
    TechniqueDomain,
    TechniquePhase,
    TechniqueScorer,
    TokenPower,
    TECHNIQUE_REGISTRY,
    TECHNIQUES_BY_DOMAIN,
    TECHNIQUES_BY_PHASE,
    suggest_techniques,
    build_attack_chain,
    capture_pentest_state,
    _check_preconditions,
)


# ---------------------------------------------------------------------------
# Tree data structures
# ---------------------------------------------------------------------------


class BranchRisk(str, Enum):
    AGGRESSIVE = "aggressive"      # high impact, likely detected
    BALANCED = "balanced"          # medium impact, moderate stealth
    STEALTH = "stealth"            # low impact, hard to detect


class NodeStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AttackTreeNode:
    """A single node in the attack tree — one tool call attempt."""

    tool: str                              # MCP tool name
    reason: str                            # why this tool, in this context
    params: dict[str, Any] = field(default_factory=dict)
    risk: BranchRisk = BranchRisk.BALANCED
    phase: str = "audit"
    status: NodeStatus = NodeStatus.PENDING
    expected_outcome: str = ""             # what we hope to achieve
    failure_context: str = ""              # what failure triggered this branch
    result_summary: str = ""               # what actually happened
    children: list[AttackTreeNode] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    max_retries: int = 1


@dataclass
class MutationResult:
    """LLM response: alternative attack paths for a failure."""

    failure_summary: str
    current_state: dict[str, Any]
    branches: list[dict[str, Any]]  # each is a tool+params+rationale
    reasoning: str                  # LLM's strategic analysis
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ---------------------------------------------------------------------------
# Mutation Engine
# ---------------------------------------------------------------------------


class MutationEngine:
    """LLM-driven attack tree builder with Vault-specific technique knowledge.

    Instead of a linear plan, this engine grows a branching tree where
    each failure spawns new alternative paths ranked by risk/reward.

    New capabilities:
    - Proactive path generation from technique KB (not just reactive)
    - Technique scoring with success/failure tracking
    - Multi-step attack chain building
    - Dynamic state-aware mutations
    """

    def __init__(self, llm_client=None):
        self._llm = llm_client
        self._root: AttackTreeNode | None = None
        self._current_node: AttackTreeNode | None = None
        self._mutation_history: list[MutationResult] = []
        self._successful_paths: list[list[AttackTreeNode]] = []
        self._dead_ends: list[AttackTreeNode] = []
        self._scorer = TechniqueScorer()  # track technique success/failure
        self._tried_techniques: set[str] = set()  # prevent duplicate suggestions
        self._vault_addr: str = ""

    # ── tree building ────────────────────────────────────────────────────

    def start_tree(self, vault_addr: str, initial_assets: dict[str, Any]) -> AttackTreeNode:
        """Create the root node of a new attack tree."""
        self._vault_addr = vault_addr
        self._root = AttackTreeNode(
            tool="__root__",
            reason=f"Initial attack surface: {vault_addr}",
            params={"vault_addr": vault_addr, "assets": initial_assets},
            risk=BranchRisk.BALANCED,
            phase="recon",
            expected_outcome="Map the full attack surface and find first foothold",
        )
        self._current_node = self._root

        # ── Proactively generate initial branches from technique KB ──────
        proactive_count = self._seed_proactive_branches(self._root)
        if proactive_count > 0:
            import sys
            print(f"  [*] Seeded {proactive_count} proactive branches from attack technique KB",
                  file=sys.stderr)

        return self._root

    # ── proactive path generation ──────────────────────────────────────────

    def _seed_proactive_branches(self, parent: AttackTreeNode) -> int:
        """Generate initial attack branches based on current state.

        Uses the technique KB to suggest the best techniques for the
        current token power level, available credentials, and findings.
        Returns the number of branches added.
        """
        state = capture_pentest_state(self._vault_addr)

        # Determine token power enum
        token_power = TokenPower.NONE
        power_str = state.get("token_power", "none")
        try:
            token_power = TokenPower(power_str)
        except ValueError:
            token_power = TokenPower.NONE

        is_auth = state.get("is_authenticated", False)
        available_creds = state.get("available_credentials", [])
        findings = state.get("findings_summary", [])
        accessible_paths = state.get("accessible_paths", [])

        # Suggest techniques for the RECON phase first, then AUDIT
        suggestions = suggest_techniques(
            token_power=token_power,
            is_authenticated=is_auth,
            available_credentials=available_creds,
            findings=findings,
            accessible_paths=accessible_paths,
            phase=None,  # all phases
            scorer=self._scorer,
            max_suggestions=8,
        )

        added = 0
        for tech, score in suggestions:
            if tech.technique_id in self._tried_techniques:
                continue
            self._tried_techniques.add(tech.technique_id)

            risk_map = {1: BranchRisk.STEALTH, 2: BranchRisk.STEALTH,
                        3: BranchRisk.BALANCED, 4: BranchRisk.AGGRESSIVE,
                        5: BranchRisk.AGGRESSIVE}
            risk = risk_map.get(tech.stealth_cost, BranchRisk.BALANCED)

            self.add_branch(
                parent=parent,
                tool=tech.tool,
                reason=f"[{tech.technique_id}] {tech.name}: {tech.description}",
                params=dict(tech.params_template),
                risk=risk,
                phase=tech.phase.value,
                expected_outcome=(
                    f"Score {score:.1f} | "
                    + (tech.success_indicators[0] if tech.success_indicators else "discover assets")
                ),
            )
            added += 1

        return added

    def generate_proactive_branches(
        self,
        parent: AttackTreeNode | None = None,
        vault_addr: str = "",
        max_branches: int = 4,
    ) -> list[AttackTreeNode]:
        """Generate new attack branches proactively (not in response to failure).

        This is called when the pentest discovers new assets (tokens,
        credentials, paths) and should explore new attack avenues.

        Returns the newly created branch nodes.
        """
        if parent is None:
            parent = self._current_node or self._root
        if parent is None:
            return []

        if vault_addr:
            self._vault_addr = vault_addr

        state = capture_pentest_state(self._vault_addr)

        token_power = TokenPower.NONE
        try:
            token_power = TokenPower(state.get("token_power", "none"))
        except ValueError:
            pass

        suggestions = suggest_techniques(
            token_power=token_power,
            is_authenticated=state.get("is_authenticated", False),
            available_credentials=state.get("available_credentials", []),
            findings=state.get("findings_summary", []),
            accessible_paths=state.get("accessible_paths", []),
            exclude_techniques=self._tried_techniques,
            scorer=self._scorer,
            max_suggestions=max_branches,
        )

        new_nodes: list[AttackTreeNode] = []
        for tech, score in suggestions:
            if tech.technique_id in self._tried_techniques:
                continue
            self._tried_techniques.add(tech.technique_id)

            risk_map = {1: BranchRisk.STEALTH, 2: BranchRisk.STEALTH,
                        3: BranchRisk.BALANCED, 4: BranchRisk.AGGRESSIVE,
                        5: BranchRisk.AGGRESSIVE}
            risk = risk_map.get(tech.stealth_cost, BranchRisk.BALANCED)

            node = self.add_branch(
                parent=parent,
                tool=tech.tool,
                reason=f"[{tech.technique_id}] {tech.name}: {tech.description}",
                params=dict(tech.params_template),
                risk=risk,
                phase=tech.phase.value,
                expected_outcome=f"Score {score:.1f}",
            )
            new_nodes.append(node)

        return new_nodes

    def build_technique_chain(
        self,
        entry_technique_id: str,
        parent: AttackTreeNode | None = None,
    ) -> list[AttackTreeNode]:
        """Build a full multi-step attack chain from the technique KB.

        Follows followup_techniques links to create a chain of nodes
        that will be executed sequentially.  Returns all created nodes.
        """
        if parent is None:
            parent = self._current_node or self._root
        if parent is None:
            return []

        state = capture_pentest_state(self._vault_addr)

        token_power = TokenPower.NONE
        try:
            token_power = TokenPower(state.get("token_power", "none"))
        except ValueError:
            pass

        chain_techniques = build_attack_chain(
            entry_technique_id=entry_technique_id,
            token_power=token_power,
            is_authenticated=state.get("is_authenticated", False),
            available_credentials=state.get("available_credentials", []),
            findings=state.get("findings_summary", []),
            accessible_paths=state.get("accessible_paths", []),
            max_depth=5,
        )

        nodes: list[AttackTreeNode] = []
        current_parent = parent
        for i, tech in enumerate(chain_techniques):
            risk_map = {1: BranchRisk.STEALTH, 2: BranchRisk.STEALTH,
                        3: BranchRisk.BALANCED, 4: BranchRisk.AGGRESSIVE,
                        5: BranchRisk.AGGRESSIVE}
            risk = risk_map.get(tech.stealth_cost, BranchRisk.BALANCED)

            node = self.add_branch(
                parent=current_parent,
                tool=tech.tool,
                reason=f"Chain[{i+1}/{len(chain_techniques)}] {tech.name}: {tech.description}",
                params=dict(tech.params_template),
                risk=risk,
                phase=tech.phase.value,
                expected_outcome=(
                    tech.success_indicators[0] if tech.success_indicators else "advance chain"
                ),
            )
            nodes.append(node)
            self._tried_techniques.add(tech.technique_id)
            current_parent = node  # nest next step under this one

        return nodes

    def add_branch(
        self,
        parent: AttackTreeNode,
        tool: str,
        reason: str,
        params: dict[str, Any] | None = None,
        risk: BranchRisk = BranchRisk.BALANCED,
        phase: str = "audit",
        expected_outcome: str = "",
        failure_context: str = "",
    ) -> AttackTreeNode:
        """Add a child branch to an existing node."""
        node = AttackTreeNode(
            tool=tool,
            reason=reason,
            params=params or {},
            risk=risk,
            phase=phase,
            expected_outcome=expected_outcome,
            failure_context=failure_context,
        )
        parent.children.append(node)
        return node

    def record_result(self, node: AttackTreeNode, success: bool, summary: str):
        """Update a node with its execution result.

        Also updates the technique scorer for learning-based ranking.
        """
        node.status = NodeStatus.SUCCEEDED if success else NodeStatus.FAILED
        node.result_summary = summary

        # ── Track technique success/failure for learning ─────────────────
        tech_id = self._extract_technique_id(node.reason)
        if tech_id and tech_id in TECHNIQUE_REGISTRY:
            if success:
                self._scorer.record_success(tech_id)
            else:
                self._scorer.record_failure(tech_id)

        if success:
            self._successful_paths.append(self._path_to(node))
        else:
            self._dead_ends.append(node)

    @staticmethod
    def _extract_technique_id(reason: str) -> str | None:
        """Extract technique ID from a branch reason string.

        Branch reasons may contain [technique.id] markers.
        """
        import re
        match = re.search(r'\[([a-z_.]+\.[a-z_]+)\]', reason)
        if match:
            return match.group(1)
        return None

    # ── LLM-driven mutation ──────────────────────────────────────────────

    async def mutate(
        self,
        failed_node: AttackTreeNode,
        available_tokens: list[dict[str, Any]],
        available_credentials: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        vault_addr: str = "",
    ) -> MutationResult:
        """Ask the LLM to generate dynamic alternative attack paths (2-6).

        The LLM decides how many paths make sense — no hardcoded limit.
        Augmented with technique KB suggestions for hybrid intelligence.

        Parameters
        ----------
        failed_node:
            The node that just failed.
        available_tokens:
            All tokens currently known, with power levels and sources.
        available_credentials:
            Non-token creds (passwords, API keys, AppRole pairs, DB conns).
        findings:
            All pentest findings so far.
        vault_addr:
            Target Vault URL for context.
        """
        if vault_addr:
            self._vault_addr = vault_addr

        state = self._build_state_summary(
            failed_node, available_tokens, available_credentials, findings, vault_addr
        )

        # ── Get KB suggestions first (fallback if LLM fails) ─────────────
        token_power = TokenPower.NONE
        best_token = (
            available_tokens[0] if available_tokens else {}
        )
        try:
            token_power = TokenPower(best_token.get("power_level", "none"))
        except ValueError:
            pass

        is_auth = len(available_tokens) > 0
        kb_suggestions = suggest_techniques(
            token_power=token_power,
            is_authenticated=is_auth,
            available_credentials=[c.get("cred_type", "") for c in available_credentials],
            findings=findings,
            accessible_paths=state.get("accessible_paths_hint", []),
            exclude_techniques=self._tried_techniques,
            scorer=self._scorer,
            max_suggestions=6,
        )

        # Build technique context for the LLM prompt
        technique_context = self._build_technique_context(kb_suggestions, failed_node)

        prompt = self._build_mutation_prompt(state, technique_context)
        response = await self._call_llm(prompt)

        mutation = MutationResult(
            failure_summary=failed_node.result_summary or failed_node.reason,
            current_state=state,
            branches=response.get("branches", []),
            reasoning=response.get("reasoning", ""),
        )
        self._mutation_history.append(mutation)

        # ── Merge LLM branches + KB suggestions ──────────────────────────
        all_branches = list(mutation.branches)  # LLM-generated

        # Add KB suggestions that the LLM didn't already suggest
        llm_tools = {b.get("tool", "") for b in mutation.branches}
        for tech, score in kb_suggestions:
            if tech.tool not in llm_tools and tech.technique_id not in self._tried_techniques:
                all_branches.append({
                    "tool": tech.tool,
                    "reason": f"[{tech.technique_id}] {tech.name}: {tech.description}",
                    "params": dict(tech.params_template),
                    "risk": {1: "stealth", 2: "stealth", 3: "balanced",
                             4: "aggressive", 5: "aggressive"}.get(tech.stealth_cost, "balanced"),
                    "phase": tech.phase.value,
                    "expected_outcome": f"KB score {score:.1f} | "
                        + (tech.success_indicators[0] if tech.success_indicators else ""),
                })

        # Add branches as children of the failed node.
        for i, branch in enumerate(all_branches):
            risk_str = branch.get("risk", "").lower()
            if risk_str in ("aggressive", "high"):
                risk = BranchRisk.AGGRESSIVE
            elif risk_str in ("stealth", "low", "quiet"):
                risk = BranchRisk.STEALTH
            else:
                risk = BranchRisk.BALANCED

            reason = branch.get("reason", "")
            tech_id = self._extract_technique_id(reason)
            if tech_id:
                self._tried_techniques.add(tech_id)

            self.add_branch(
                parent=failed_node,
                tool=branch.get("tool", "run_raw_vault_request"),
                reason=reason,
                params=branch.get("params", {}),
                risk=risk,
                phase=branch.get("phase", "exploit"),
                expected_outcome=branch.get("expected_outcome", ""),
                failure_context=failed_node.result_summary[:200],
            )

        return mutation

    def _build_technique_context(
        self,
        kb_suggestions: list[tuple[AttackTechnique, float]],
        failed_node: AttackTreeNode,
    ) -> str:
        """Build technique KB context for the LLM mutation prompt."""
        if not kb_suggestions:
            return ""

        lines = [
            "\n=== TECHNIQUE KB SUGGESTIONS (Vault-specific attack patterns) ===",
            "The following techniques match the current state. Consider them",
            f"when generating alternative paths for the failed tool '{failed_node.tool}':\n",
        ]

        for tech, score in kb_suggestions[:6]:
            lines.append(
                f"  [{tech.technique_id}] {tech.name} (score: {score:.1f})\n"
                f"    {tech.description}\n"
                f"    Tool: {tech.tool} | Phase: {tech.phase.value} | "
                f"Risk: {tech.risk_level}"
            )
            if tech.fallback_chain:
                lines.append(f"    Fallback chain: {' → '.join(tech.fallback_chain[:3])}")
            if tech.followup_techniques:
                lines.append(f"    Follow-up: {' → '.join(tech.followup_techniques[:3])}")
            lines.append("")

        return "\n".join(lines)

    # ── tree navigation ──────────────────────────────────────────────────

    def get_next_pending(self) -> AttackTreeNode | None:
        """Depth-first search for the next pending node (aggressive first)."""
        if not self._root:
            return None
        return self._find_pending(self._root)

    def get_best_path(self) -> list[AttackTreeNode]:
        """Return the most promising path through the tree so far."""
        if self._successful_paths:
            return max(self._successful_paths, key=len)
        # Fall back to deepest pending path
        path = []
        node = self._root
        while node:
            path.append(node)
            pending = [c for c in node.children if c.status == NodeStatus.PENDING]
            if pending:
                # Prefer aggressive branches
                aggressive = [c for c in pending if c.risk == BranchRisk.AGGRESSIVE]
                balanced = [c for c in pending if c.risk == BranchRisk.BALANCED]
                node = (aggressive or balanced or pending)[0]
            else:
                break
        return path

    def tree_summary(self) -> dict[str, Any]:
        """Export the entire tree for display / logging."""
        return {
            "total_nodes": self._count_nodes(self._root),
            "pending": self._count_by_status(NodeStatus.PENDING),
            "succeeded": self._count_by_status(NodeStatus.SUCCEEDED),
            "failed": self._count_by_status(NodeStatus.FAILED),
            "successful_paths": len(self._successful_paths),
            "dead_ends": len(self._dead_ends),
            "mutations": len(self._mutation_history),
            "technique_stats": self._scorer.status_summary(),
            "tried_techniques": len(self._tried_techniques),
            "tree": self._serialize_node(self._root) if self._root else None,
        }

    # ── internal helpers ─────────────────────────────────────────────────

    def _build_state_summary(
        self,
        failed_node: AttackTreeNode,
        tokens: list[dict[str, Any]],
        credentials: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        vault_addr: str,
    ) -> dict[str, Any]:
        """Build a compact state snapshot for the LLM prompt."""
        # ── Capture live pentest state for richer context ─────────────────
        live_state = capture_pentest_state(vault_addr)

        return {
            "vault_addr": vault_addr,
            "failure": {
                "tool": failed_node.tool,
                "reason": failed_node.reason,
                "result": failed_node.result_summary[:300],
                "phase": failed_node.phase,
            },
            "available_tokens": [
                {
                    "preview": t.get("token", ""),
                    "power": t.get("power_level", "unknown"),
                    "source": t.get("source", "unknown"),
                    "policies": t.get("policies", []),
                    "capabilities": t.get("capabilities", []),
                }
                for t in tokens[:5]
            ],
            "available_credentials": [
                {
                    "type": c.get("cred_type", "unknown"),
                    "source": c.get("source", "unknown"),
                    "metadata": c.get("metadata", {}),
                }
                for c in credentials[:5]
            ],
            "findings_summary": [
                {
                    "severity": f.get("severity", "INFO"),
                    "title": f.get("title", ""),
                    "module": f.get("module", ""),
                }
                for f in findings[-20:]  # most recent 20
            ],
            "high_value_targets": live_state.get("high_value_targets", []),
            "accessible_paths_hint": live_state.get("accessible_paths", []),
            "previously_succeeded": [
                {"tool": n.tool, "reason": n.reason, "result": n.result_summary[:100]}
                for path in self._successful_paths
                for n in path
                if n.status == NodeStatus.SUCCEEDED
            ][-10:],
            "dead_ends": [
                {"tool": n.tool, "reason": n.reason, "result": n.result_summary[:100]}
                for n in self._dead_ends[-5:]
            ],
            "technique_stats": self._scorer.status_summary(),
        }

    def _build_mutation_prompt(
        self, state: dict[str, Any], technique_context: str = "",
    ) -> str:
        """Build the LLM prompt that generates creative attack alternatives."""
        state_json = json.dumps(state, indent=2, ensure_ascii=False)

        return f"""You are an expert red-team operator. A Vault pentest tool just FAILED.
Analyse the state and generate the BEST possible alternative attack paths.

=== CURRENT STATE ===
{state_json}

=== WEB INTEL (auto-searched for CVEs in findings) ===
{json.dumps(state.get("web_intel", []), indent=2, ensure_ascii=False)}
{technique_context}

=== YOUR TASK ===
Generate 2-6 alternative attack paths based on the failure context and
available assets.  Fewer HIGH-QUALITY paths are better than many weak ones.
Rank them from most aggressive/impactful to stealthiest/safest.

CRITICAL RULES:
1. Each path MUST use a REAL tool: run_unauthenticated_recon, run_capability_audit,
   run_priv_esc_scan, run_kv_enumeration, run_ttl_audit, run_auth_config_audit,
   read_single_policy, run_policy_auditor, run_raw_vault_request, run_env_scan,
   run_hijack_scan, list_active_modules, run_active_module, get_findings, get_risk_score,
   run_privilege_escalation, run_secret_exfiltration, run_database_credential_harvest,
   run_cloud_key_exfiltration, run_database_pivot, run_reverse_shell

2. Every path must be MEANINGFULLY DIFFERENT — no duplicates.
3. Think LATERALLY. Examples:
   - One token blocked → try another available token
   - KV denied → try database secrets engine
   - Audit blocked → try raw API with different paths
   - Vault locked down → pivot to backend (DB, cloud, K8s)
   - DB credentials available → direct database connection
   - AppRole pair found → generate new tokens
   - Policy read denied → try listing policies, then brute-force names
4. For each path, explain WHY it could bypass the specific failure.
5. Be SPECIFIC with params — real paths, real mount points, real policy names.
6. Set "risk" to "aggressive", "balanced", or "stealth" for each branch.
7. IF technique KB suggestions are provided, USE them as a starting point —
   they are Vault-specific patterns known to work in similar situations.

=== RESPONSE FORMAT (JSON only, no markdown) ===
{{
  "reasoning": "Strategic analysis: root cause of the failure and what attack surface remains...",
  "branches": [
    {{
      "tool": "run_priv_esc_scan",
      "reason": "Current token reads database/* but was denied secret/*. Try creating a child token with elevated policy via database engine config.",
      "params": {{"vault_addr": "https://target:8200", "token": "USE_BEST_TOKEN"}},
      "risk": "aggressive",
      "phase": "exploit",
      "expected_outcome": "Higher-privilege token that can read blocked paths."
    }}
  ]
}}

Generate as many branches as the situation warrants (2-6). Each one must have
a GENUINE chance of succeeding — no filler.  Respond with ONLY valid JSON."""

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        """Send prompt to LLM, parse JSON response. Returns dict with 'branches'."""
        if not self._llm:
            return self._fallback_branches()

        try:
            response = await asyncio.to_thread(
                self._llm.chat,
                system_prompt="You are a red-team attack-tree generator. Always respond with valid JSON only.",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.8,  # creative but not random
                max_tokens=2048,
            )

            content = response.get("content", "")
            # Extract JSON from response (LLM might wrap in markdown)
            return self._parse_mutation_response(content)

        except Exception as exc:
            print(f"[!] Mutation LLM call failed: {exc}")
            return self._fallback_branches()

    def _parse_mutation_response(self, content: str) -> dict[str, Any]:
        """Parse LLM response, handling markdown-wrapped JSON."""
        # Try direct parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code blocks
        import re
        match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding the outermost JSON object
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return self._fallback_branches()

    def _fallback_branches(self) -> dict[str, Any]:
        """Generate context-aware fallback branches using the technique KB.

        When the LLM is unavailable, the technique KB provides Vault-specific
        attack patterns ranked by expected value based on current state.
        """
        state = capture_pentest_state(self._vault_addr)

        token_power = TokenPower.NONE
        try:
            token_power = TokenPower(state.get("token_power", "none"))
        except ValueError:
            pass

        suggestions = suggest_techniques(
            token_power=token_power,
            is_authenticated=state.get("is_authenticated", False),
            available_credentials=state.get("available_credentials", []),
            findings=state.get("findings_summary", []),
            accessible_paths=state.get("accessible_paths", []),
            exclude_techniques=self._tried_techniques,
            scorer=self._scorer,
            max_suggestions=6,
        )

        branches: list[dict] = []
        for tech, score in suggestions:
            if tech.technique_id in self._tried_techniques:
                continue
            self._tried_techniques.add(tech.technique_id)

            branches.append({
                "tool": tech.tool,
                "reason": f"[{tech.technique_id}] {tech.name}: {tech.description}",
                "params": dict(tech.params_template),
                "risk": {1: "stealth", 2: "stealth", 3: "balanced",
                         4: "aggressive", 5: "aggressive"}.get(tech.stealth_cost, "balanced"),
                "phase": tech.phase.value,
                "expected_outcome": f"KB score {score:.1f} | "
                    + (tech.success_indicators[0] if tech.success_indicators else "discover assets"),
            })

        return {
            "reasoning": (
                f"LLM unavailable — technique KB generated {len(branches)} "
                f"context-aware fallback paths (token_power={token_power.value}, "
                f"auth={state.get('is_authenticated')}, "
                f"creds={len(state.get('available_credentials', []))})"
            ),
            "branches": branches,
        }

    # ── tree traversal helpers ───────────────────────────────────────────

    def _find_pending(self, node: AttackTreeNode) -> AttackTreeNode | None:
        """DFS for first pending node (aggressive priority)."""
        if node.status == NodeStatus.PENDING and node.tool != "__root__":
            return node

        # Sort children: aggressive > balanced > stealth
        risk_order = {BranchRisk.AGGRESSIVE: 0, BranchRisk.BALANCED: 1, BranchRisk.STEALTH: 2}
        sorted_children = sorted(
            node.children,
            key=lambda c: risk_order.get(c.risk, 1),
        )

        for child in sorted_children:
            found = self._find_pending(child)
            if found:
                return found
        return None

    def _path_to(self, node: AttackTreeNode) -> list[AttackTreeNode]:
        """Rebuild the path from root to *node*."""
        # Simple BFS to find path
        path = []
        if not self._root:
            return path

        def _dfs(current, target, current_path):
            nonlocal path
            if current is target:
                path = list(current_path)
                return True
            for child in current.children:
                if _dfs(child, target, current_path + [child]):
                    return True
            return False

        _dfs(self._root, node, [self._root])
        return path

    def _count_nodes(self, node: AttackTreeNode | None) -> int:
        if not node:
            return 0
        return 1 + sum(self._count_nodes(c) for c in node.children)

    def _count_by_status(self, status: NodeStatus) -> int:
        def _count(node):
            if not node:
                return 0
            return (1 if node.status == status else 0) + sum(
                _count(c) for c in node.children
            )
        return _count(self._root)

    def _serialize_node(self, node: AttackTreeNode | None) -> dict | None:
        if not node:
            return None
        return {
            "tool": node.tool,
            "reason": node.reason,
            "risk": node.risk.value,
            "status": node.status.value,
            "expected_outcome": node.expected_outcome,
            "result_summary": node.result_summary[:150],
            "failure_context": node.failure_context[:150],
            "children": [
                self._serialize_node(c) for c in node.children
            ],
        }


# ---------------------------------------------------------------------------
# Convenience — build state from global DynamicCredentialStore
# ---------------------------------------------------------------------------


def gather_attack_state() -> dict[str, Any]:
    """Collect all available assets from the global session for the mutation engine."""
    try:
        from ai_core.dynamic_session import global_store
        from core.report import get_default_report

        report = get_default_report()
        tokens = [
            {
                "token": t.token,
                "power_level": t.power_level,
                "source": t.source,
                "policies": t.policies,
                "capabilities": t.capabilities,
            }
            for t in global_store.tokens.values()
        ]
        credentials = [
            {
                "cred_type": c.cred_type,
                "value": c.value[:20] + "..." if len(c.value) > 20 else c.value,
                "source": c.source,
                "metadata": c.metadata,
            }
            for c in global_store.credentials.values()
        ]
        findings = report.get_findings_snapshot()

        # Collect web intel for CVEs found in findings (lightweight cache hit)
        web_intel = _gather_web_intel(findings)

        return {
            "tokens": tokens,
            "credentials": credentials,
            "findings": findings,
            "session_summary": global_store.status_summary(),
            "web_intel": web_intel,
        }
    except ImportError:
        return {"tokens": [], "credentials": [], "findings": []}


def _gather_web_intel(findings: list[dict]) -> list[dict]:
    """Lightweight web search for CVEs found in findings (cache hits only)."""
    import re
    intel: list[dict] = []
    seen_cves: set[str] = set()

    for f in findings[-20:]:
        title = f.get("title", "")
        desc = f.get("description", "")
        combined = f"{title} {desc}"

        for match in re.finditer(r'CVE-\d{4}-\d{4,}', combined, re.IGNORECASE):
            cve = match.group(0).upper()
            if cve in seen_cves:
                continue
            seen_cves.add(cve)

            try:
                from ai_core.web_search import search_web_sync
                results = search_web_sync(
                    f"HashiCorp Vault {cve} exploit", max_results=2,
                )
                if results:
                    intel.append({
                        "cve": cve,
                        "title": results[0]["title"],
                        "snippet": results[0]["snippet"][:200],
                        "url": results[0]["url"],
                    })
            except Exception:
                pass

    return intel
