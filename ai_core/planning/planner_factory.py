"""Planner factory — returns the right planner for a given LLM provider."""

from __future__ import annotations

from ai_core.llm_engine import LLMClient
from ai_core.planning.base_planner import BasePlanner
from ai_core.planning.openai_planner import OpenAIPlanner
from ai_core.planning.deepseek_planner import DeepSeekPlanner
from ai_core.planning.anthropic_planner import AnthropicPlanner


def create_planner(provider: str, **kwargs) -> BasePlanner:
    """Return a planner instance suitable for *provider*.

    Parameters
    ----------
    provider : str
        One of ``"openai"``, ``"deepseek"``, ``"anthropic"``, or ``"ollama"``.
        Ollama falls back to the OpenAI planner (most Ollama models support
        the OpenAI-compatible chat API).
    **kwargs
        Forwarded to the concrete planner constructor.  Common kwargs:
        - ``llm_client`` (LLMClient) for OpenAI/DeepSeek planners.
        - ``api_key`` (str), ``model`` (str), ``thinking_budget`` (int) for Anthropic.

    Returns
    -------
    BasePlanner
    """
    if provider == "openai":
        llm_client = kwargs.get("llm_client") or LLMClient(provider="openai")
        return OpenAIPlanner(llm_client, **{k: v for k, v in kwargs.items() if k != "llm_client"})

    if provider == "deepseek":
        llm_client = kwargs.get("llm_client") or LLMClient(provider="deepseek")
        return DeepSeekPlanner(llm_client)

    if provider == "anthropic":
        return AnthropicPlanner(
            api_key=kwargs.get("api_key"),
            model=kwargs.get("model", "claude-opus-4-8"),
            thinking_budget=kwargs.get("thinking_budget", 20_000),
        )

    if provider == "ollama":
        # Ollama models generally support OpenAI-compatible chat API
        llm_client = kwargs.get("llm_client") or LLMClient(provider="ollama")
        return OpenAIPlanner(llm_client)

    raise ValueError(
        f"No planner available for provider '{provider}'. "
        f"Supported providers: openai, deepseek, anthropic, ollama"
    )
