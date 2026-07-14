"""DeepSeek planner — thin wrapper around OpenAI planner.

DeepSeek's API is OpenAI-compatible so we reuse the same implementation.
"""

from __future__ import annotations

from ai_core.llm_engine import LLMClient
from ai_core.planning.openai_planner import OpenAIPlanner


class DeepSeekPlanner(OpenAIPlanner):
    """Planner for DeepSeek's OpenAI-compatible chat completion API.

    Inherits the full ``create_plan`` implementation from ``OpenAIPlanner``.
    The only difference is the model name and the API endpoint, which
    ``LLMClient`` handles via provider routing.
    """

    def __init__(self, llm_client: LLMClient):
        super().__init__(llm_client, model="deepseek-chat")

    @property
    def provider_name(self) -> str:
        return "deepseek"
