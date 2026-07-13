"""Multi-provider LLM engine with tool/function calling support.

Supports:
- Ollama (local) — with native tool calling for models that support it, ReAct fallback
- OpenAI API — native function calling
- Anthropic API — native tool use

Provider selection is automatic based on configuration or can be forced.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

import requests

# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def detect_provider() -> str:
    """Auto-detect the best available LLM provider."""
    if _env("ANTHROPIC_API_KEY"):
        return "anthropic"
    if _env("DEEPSEEK_API_KEY"):
        return "deepseek"
    if _env("OPENAI_API_KEY"):
        return "openai"
    # Check if Ollama is reachable
    try:
        r = requests.get(_env("OLLAMA_HOST", "http://localhost:11434") + "/api/tags", timeout=2)
        if r.status_code == 200:
            return "ollama"
    except Exception:
        pass
    return "ollama"  # default fallback


# ---------------------------------------------------------------------------
# LLM Client
# ---------------------------------------------------------------------------


class LLMClient:
    """Unified LLM client with tool calling across providers."""

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self.provider = provider or detect_provider()
        self.api_key = api_key or self._resolve_api_key()
        self.base_url = base_url or self._resolve_base_url()
        self.model = model or self._default_model()

    def _resolve_api_key(self) -> str:
        if self.provider == "openai":
            return _env("OPENAI_API_KEY")
        if self.provider == "anthropic":
            return _env("ANTHROPIC_API_KEY")
        if self.provider == "deepseek":
            return _env("DEEPSEEK_API_KEY")
        return ""

    def _resolve_base_url(self) -> str:
        if self.provider == "ollama":
            return _env("OLLAMA_HOST", "http://localhost:11434")
        if self.provider == "openai":
            return "https://api.openai.com/v1"
        if self.provider == "anthropic":
            return "https://api.anthropic.com"
        if self.provider == "deepseek":
            return "https://api.deepseek.com/v1"
        return "http://localhost:11434"

    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-sonnet-4-20250514",
            "deepseek": "deepseek-chat",
        }
        if self.provider in defaults:
            return defaults[self.provider]
        # Ollama — auto-detect best available model
        return self._detect_ollama_model()

    def _detect_ollama_model(self) -> str:
        """Find the best available Ollama model for tool calling.

        Preference order: llama3.1 → qwen2.5 → mistral → dolphin-llama3 →
        llama3 → phi3 → gemma2 → command-r → first available.
        """
        available = self._list_ollama_models()
        if not available:
            return "llama3.1:8b"  # fallback — will fail with clear error

        preferred = [
            "llama3.1", "qwen2.5", "mistral", "dolphin-llama3",
            "qwen2", "llama3", "phi3", "gemma2", "command-r",
            "mixtral", "deepseek-r1", "phi", "orca2", "llama2",
        ]
        for prefix in preferred:
            for model in available:
                if model.startswith(prefix):
                    return model
        return available[0]  # first available, whatever it is

    def _list_ollama_models(self) -> list[str]:
        """Return sorted list of available Ollama model names."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            if r.status_code != 200:
                return []
            models = r.json().get("models", [])
            return sorted(
                [m.get("name", "") for m in models if m.get("name")],
                reverse=True,  # newer versions tend to sort higher
            )
        except Exception:
            return []

    # ── public API ──────────────────────────────────────────────────────

    def chat(
        self,
        system_prompt: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> dict:
        """Send a chat completion request. Returns unified response dict.

        Response shape::

            {
                "role": "assistant",
                "content": str | None,
                "tool_calls": [{"name": str, "arguments": dict}] | None,
                "finish_reason": "stop" | "tool_calls" | "error",
                "raw": ...,
            }
        """
        if self.provider == "ollama":
            return self._ollama_chat(system_prompt, messages, tools, temperature, max_tokens)
        if self.provider in ("openai", "deepseek"):
            return self._openai_chat(system_prompt, messages, tools, temperature, max_tokens)
        if self.provider == "anthropic":
            return self._anthropic_chat(system_prompt, messages, tools, temperature, max_tokens)
        return {"role": "assistant", "content": None, "tool_calls": None,
                "finish_reason": "error", "raw": "unknown provider"}

    def is_available(self) -> bool:
        """Check if the configured provider is reachable."""
        try:
            if self.provider == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=2)
                return r.status_code == 200
            if self.provider in ("openai", "anthropic", "deepseek"):
                return bool(self.api_key)
        except Exception:
            pass
        return False

    # ── Ollama ──────────────────────────────────────────────────────────

    def _ollama_chat(self, system_prompt, messages, tools, temperature, max_tokens):
        """Ollama chat with native tool calling (v0.3+) and ReAct fallback."""
        # Try native tool calling first
        if tools:
            result = self._ollama_tool_call(system_prompt, messages, tools, temperature)
            if result:
                return result

        # Fallback: ReAct text parsing
        return self._ollama_react(system_prompt, messages, tools, temperature, max_tokens)

    def _ollama_tool_call(self, system_prompt, messages, tools, temperature):
        """Use Ollama's native tool calling API."""
        ollama_messages = [{"role": "system", "content": system_prompt}]
        ollama_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": ollama_messages,
            "stream": False,
            "temperature": temperature,
            "tools": tools,
        }
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=120)
            if r.status_code != 200:
                return None
            data = r.json()
            msg = data.get("message", {})
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                return {
                    "role": "assistant",
                    "content": msg.get("content", ""),
                    "tool_calls": [
                        {"name": tc["function"]["name"],
                         "arguments": tc["function"].get("arguments", {})}
                        for tc in tool_calls
                    ],
                    "finish_reason": "tool_calls",
                    "raw": data,
                }
            return {
                "role": "assistant",
                "content": msg.get("content", ""),
                "tool_calls": None,
                "finish_reason": "stop",
                "raw": data,
            }
        except Exception:
            return None

    def _ollama_react(self, system_prompt, messages, tools, temperature, max_tokens):
        """ReAct fallback: text-based tool calling via ACTION: JSON blocks."""
        tool_descriptions = self._format_tools_text(tools)
        react_instructions = (
            "\n\nYou have access to these TOOLS:\n"
            f"{tool_descriptions}\n\n"
            "RESPONSE FORMAT: If you need to use a tool, respond EXACTLY:\n"
            'ACTION: {"tool": "tool_name", "params": {"arg": "value"}}\n'
            "After the tool result comes back, continue reasoning.\n"
            "When your task is complete, respond normally without ACTION.\n"
            "THINK step by step before each action.\n"
        )

        prompt = system_prompt + react_instructions
        ollama_messages = [{"role": "system", "content": prompt}]
        ollama_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": ollama_messages,
            "stream": False,
            "temperature": temperature,
            "options": {"num_predict": max_tokens},
        }
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=120)
            if r.status_code != 200:
                return {"role": "assistant", "content": None, "tool_calls": None,
                        "finish_reason": "error", "raw": r.text}
            data = r.json()
            content = data.get("message", {}).get("content", "")

            # Parse ACTION blocks
            tool_calls = self._parse_react_actions(content)
            if tool_calls:
                # Remove ACTION blocks from displayed content
                clean_content = re.sub(
                    r'\n?ACTION:\s*\{[^}]+\}\s*\n?', '', content
                ).strip()
                return {
                    "role": "assistant",
                    "content": clean_content,
                    "tool_calls": tool_calls,
                    "finish_reason": "tool_calls",
                    "raw": data,
                }
            return {
                "role": "assistant",
                "content": content,
                "tool_calls": None,
                "finish_reason": "stop",
                "raw": data,
            }
        except Exception as e:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(e)}

    # ── OpenAI ──────────────────────────────────────────────────────────

    def _openai_chat(self, system_prompt, messages, tools, temperature, max_tokens):
        openai_messages = [{"role": "system", "content": system_prompt}]
        openai_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            r = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=120,
            )
            if r.status_code != 200:
                return {"role": "assistant", "content": None, "tool_calls": None,
                        "finish_reason": "error", "raw": r.text}
            data = r.json()
            choice = data["choices"][0]
            msg = choice["message"]
            tool_calls_raw = msg.get("tool_calls", [])
            return {
                "role": "assistant",
                "content": msg.get("content", ""),
                "tool_calls": [
                    {"name": tc["function"]["name"],
                     "arguments": json.loads(tc["function"]["arguments"])}
                    for tc in tool_calls_raw
                ] if tool_calls_raw else None,
                "finish_reason": "tool_calls" if tool_calls_raw else "stop",
                "raw": data,
            }
        except Exception as e:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(e)}

    # ── Anthropic ───────────────────────────────────────────────────────

    def _anthropic_chat(self, system_prompt, messages, tools, temperature, max_tokens):
        # Convert to Anthropic format
        anthropic_messages = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [{"type": "tool_result",
                                 "tool_use_id": m.get("tool_call_id", ""),
                                 "content": content}],
                })
            elif role == "assistant" and m.get("tool_calls"):
                tool_use_blocks = []
                for tc in m.get("tool_calls", []):
                    tool_use_blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", "tool_0"),
                        "name": tc.get("name", ""),
                        "input": tc.get("arguments", {}),
                    })
                anthropic_messages.append({"role": "assistant", "content": tool_use_blocks})
            else:
                anthropic_messages.append({"role": role, "content": content or ""})

        anthropic_tools = None
        if tools:
            anthropic_tools = []
            for t in tools:
                func = t.get("function", t)
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func["description"],
                    "input_schema": func["parameters"],
                })

        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if anthropic_tools:
            payload["tools"] = anthropic_tools

        try:
            r = requests.post(
                f"{self.base_url}/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=120,
            )
            if r.status_code != 200:
                return {"role": "assistant", "content": None, "tool_calls": None,
                        "finish_reason": "error", "raw": r.text}
            data = r.json()
            content_blocks = data.get("content", [])
            text = ""
            tool_calls = []
            for block in content_blocks:
                if block.get("type") == "text":
                    text += block.get("text", "")
                elif block.get("type") == "tool_use":
                    tool_calls.append({
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "arguments": block.get("input", {}),
                    })
            return {
                "role": "assistant",
                "content": text or None,
                "tool_calls": tool_calls if tool_calls else None,
                "finish_reason": "tool_calls" if tool_calls else "stop",
                "raw": data,
            }
        except Exception as e:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(e)}

    # ── helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _format_tools_text(tools: list[dict] | None) -> str:
        if not tools:
            return "(no tools available)"
        lines = []
        for t in tools:
            func = t.get("function", t)
            params_desc = ", ".join(
                f"{k}: {v.get('type', 'string')}"
                for k, v in func.get("parameters", {}).get("properties", {}).items()
            )
            lines.append(
                f"- {func['name']}({params_desc}): {func['description'][:200]}"
            )
        return "\n".join(lines)

    @staticmethod
    def _parse_react_actions(text: str) -> list[dict]:
        """Parse ACTION: {...} blocks from ReAct text output."""
        pattern = r'ACTION:\s*(\{[^}]+\})'
        tool_calls = []
        for match in re.finditer(pattern, text):
            try:
                action = json.loads(match.group(1))
                name = action.get("tool")
                params = action.get("params", {})
                if name and isinstance(params, dict):
                    tool_calls.append({"name": name, "arguments": params})
            except json.JSONDecodeError:
                pass
        return tool_calls
