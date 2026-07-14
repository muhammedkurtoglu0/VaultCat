"""Abstract base for AI pentest plan generators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ai_core.planning.plan_schema import PentestPlan


class BasePlanner(ABC):
    """Contract every planner must fulfil.

    Each concrete planner wraps a specific LLM provider (OpenAI, DeepSeek,
    Anthropic) but exposes the same ``create_plan`` interface so the rest of
    the system doesn't need to know which provider is being used.
    """

    @abstractmethod
    def create_plan(
        self,
        vault_addr: str,
        token_hint: str,
        enum_data: dict[str, Any],
    ) -> PentestPlan:
        """Analyse enumeration data and produce a prioritised attack plan.

        Parameters
        ----------
        vault_addr : str
            Target Vault URL.
        token_hint : str
            Obfuscated token preview for the prompt (e.g. ``"s.XXXX..."``).
        enum_data : dict
            Keys are scanner names (``"capabilities"``, ``"priv_esc"``,
            ``"kv_paths"``, ``"findings"``, …) and values are their JSON
            results (strings or dicts).

        Returns
        -------
        PentestPlan
            Filled-in plan ready for execution.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identify the LLM provider this planner targets."""
        ...
