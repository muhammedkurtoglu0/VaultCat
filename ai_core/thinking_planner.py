"""
AI Thinking Planner — DEPRECATED.

This module has been replaced by ``ai_core.planning``.  Imports still work
for backward compatibility, but new code should use the planning package
directly.

    from ai_core.planning import AnthropicPlanner, PentestPlan, create_planner
"""

from __future__ import annotations

import warnings

from ai_core.planning.anthropic_planner import (
    AnthropicPlanner as ThinkingPlanner,
    PentestPlan,
    PlannedStep,
    TokenAssessment,
)

warnings.warn(
    "ai_core.thinking_planner is deprecated — use ai_core.planning instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["ThinkingPlanner", "PentestPlan", "PlannedStep", "TokenAssessment"]
