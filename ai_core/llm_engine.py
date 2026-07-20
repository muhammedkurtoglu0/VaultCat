"""Multi-provider LLM engine with tool/function calling support.

Supports:
- Ollama (local) — with native tool calling for models that support it, ReAct fallback
- OpenAI API — native function calling
- Anthropic API — native tool use
- DeepSeek API — OpenAI-compatible function calling

Provider selection is automatic based on configuration or can be forced.
Features: retry with exponential backoff, circuit breaker, error classification.
"""

from __future__ import annotations

import json
import os
import re
import time
import threading
from typing import Any, Optional

import requests


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class LLMError(Exception):
    """Base exception for all LLM-related errors."""


class RetryableError(LLMError):
    """Transient error — safe to retry (429 rate limit, 5xx server error)."""


class FatalError(LLMError):
    """Non-retryable error — do NOT retry (401 auth, 402 payment, 403 forbidden)."""


class LLMTimeoutError(LLMError):
    """Request timed out."""


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Prevents repeated calls to a failing provider.

    After *failure_threshold* consecutive failures, the breaker opens for
    *recovery_timeout* seconds.  While open all calls fail fast with
    ``FatalError`` instead of waiting for a real timeout.
    """

    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            if self._failure_count < self._failure_threshold:
                return False
            elapsed = time.monotonic() - self._last_failure_time
            return elapsed < self._recovery_timeout

    def success(self) -> None:
        with self._lock:
            self._failure_count = 0

    def failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

    def reset(self) -> None:
        """Manually reset the breaker to closed state."""
        with self._lock:
            self._failure_count = 0
            self._last_failure_time = 0.0


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
):
    """Decorator / wrapper that retries on RetryableError with exponential backoff."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except RetryableError as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                        time.sleep(delay)
                    # else: fall through to re-raise
            raise last_exc  # type: ignore[misc]
            return None

        return wrapper

    return decorator

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
    """Unified LLM client with tool calling across providers.

    Features: retry with exponential backoff, circuit breaker, error classification.
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        request_timeout: float = 120.0,
    ):
        self.provider = provider or detect_provider()
        self.api_key = api_key or self._resolve_api_key()
        self.base_url = base_url or self._resolve_base_url()
        self.model = model or self._default_model()
        self.request_timeout = request_timeout
        self._circuit_breaker = CircuitBreaker()

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
            return _env("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if self.provider == "anthropic":
            return _env("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        if self.provider == "deepseek":
            return _env("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
        return "http://localhost:11434"

    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": os.getenv("ANTHROPIC_DEFAULT_MODEL", "claude-sonnet-5"),
            "deepseek": "deepseek-v4-flash",
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

        Automatically retries on transient errors (429, 5xx) with
        exponential backoff.  Fast-fails when the circuit breaker is open.
        """
        # Fast-fail when circuit breaker is open
        if self._circuit_breaker.is_open:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": None,
                "finish_reason": "error",
                "raw": f"Circuit breaker open for provider '{self.provider}'",
            }

        @retry_with_backoff(max_retries=3, base_delay=1.0)
        def _call():
            if self.provider == "ollama":
                return self._ollama_chat(system_prompt, messages, tools, temperature, max_tokens)
            if self.provider in ("openai", "deepseek"):
                return self._openai_chat(system_prompt, messages, tools, temperature, max_tokens)
            if self.provider == "anthropic":
                return self._anthropic_chat(system_prompt, messages, tools, temperature, max_tokens)
            raise FatalError(f"Unknown provider: {self.provider}")

        try:
            result = _call()
            self._circuit_breaker.success()
            return result
        except FatalError as exc:
            # Auth / client-side errors — do NOT trip the circuit breaker
            # because the provider itself is healthy; the request is bad.
            return {
                "role": "assistant", "content": None, "tool_calls": None,
                "finish_reason": "error",
                "raw": f"Fatal error from provider '{self.provider}': {exc}",
            }
        except (RetryableError, LLMTimeoutError) as exc:
            # Provider-side transient / timeout errors — trip the breaker.
            self._circuit_breaker.failure()
            return {
                "role": "assistant", "content": None, "tool_calls": None,
                "finish_reason": "error",
                "raw": f"Retryable error exhausted for provider '{self.provider}': {exc}",
            }
        except LLMError as exc:
            # Unknown LLM errors — trip conservatively.
            self._circuit_breaker.failure()
            return {
                "role": "assistant", "content": None, "tool_calls": None,
                "finish_reason": "error",
                "raw": str(exc),
            }

    def is_available(self) -> bool:
        """Check if the configured provider is reachable and healthy."""
        if self._circuit_breaker.is_open:
            return False
        try:
            if self.provider == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=5)
                return r.status_code == 200
            if self.provider in ("openai", "anthropic", "deepseek"):
                return bool(self.api_key)
        except Exception:
            pass
        return False

    def health(self) -> dict:
        """Return provider health status with detail."""
        status: dict = {
            "provider": self.provider,
            "model": self.model,
            "circuit_breaker_open": self._circuit_breaker.is_open,
            "has_api_key": bool(self.api_key),
        }
        try:
            if self.provider == "ollama":
                r = requests.get(f"{self.base_url}/api/tags", timeout=5)
                status["reachable"] = r.status_code == 200
                status["models_count"] = len(r.json().get("models", [])) if r.status_code == 200 else 0
            elif self.provider in ("openai", "anthropic", "deepseek"):
                status["reachable"] = bool(self.api_key)
            else:
                status["reachable"] = False
        except Exception as exc:
            status["reachable"] = False
            status["error"] = str(exc)
        return status

    def _classify_http_error(self, status_code: int, body: str = "") -> None:
        """Raise the appropriate exception for an HTTP error status."""
        if status_code == 429 or status_code >= 500:
            raise RetryableError(
                f"Provider '{self.provider}' returned {status_code}: {body[:300]}"
            )
        if status_code in (401, 402, 403):
            raise FatalError(
                f"Provider '{self.provider}' returned {status_code} (auth/payment): {body[:300]}"
            )
        raise FatalError(
            f"Provider '{self.provider}' returned {status_code}: {body[:300]}"
        )

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
            r = requests.post(
                f"{self.base_url}/api/chat", json=payload,
                timeout=self.request_timeout,
            )
            if r.status_code != 200:
                self._classify_http_error(r.status_code, r.text)
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
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(
                f"Ollama request timed out after {self.request_timeout}s"
            )
        except requests.exceptions.ConnectionError:
            raise RetryableError(
                f"Ollama unreachable at {self.base_url}"
            )
        except (RetryableError, FatalError, LLMTimeoutError):
            raise
        except Exception as exc:
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
            r = requests.post(
                f"{self.base_url}/api/chat", json=payload,
                timeout=self.request_timeout,
            )
            if r.status_code != 200:
                self._classify_http_error(r.status_code, r.text)
                return {"role": "assistant", "content": None, "tool_calls": None,
                        "finish_reason": "error", "raw": r.text}
            data = r.json()
            content = data.get("message", {}).get("content", "")

            # Parse ACTION blocks
            tool_calls = self._parse_react_actions(content)
            if tool_calls:
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
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(
                f"Ollama ReAct request timed out after {self.request_timeout}s"
            )
        except requests.exceptions.ConnectionError:
            raise RetryableError(
                f"Ollama unreachable at {self.base_url}"
            )
        except (RetryableError, FatalError, LLMTimeoutError):
            raise
        except Exception as exc:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(exc)}

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
                timeout=self.request_timeout,
            )
            if r.status_code != 200:
                self._classify_http_error(r.status_code, r.text)
                return {"role": "assistant", "content": None, "tool_calls": None,
                        "finish_reason": "error", "raw": r.text}
            data = r.json()
            choice = data["choices"][0]
            msg = choice["message"]
            tool_calls_raw = msg.get("tool_calls", [])
            tool_calls = None
            if tool_calls_raw:
                tool_calls = []
                for tc in tool_calls_raw:
                    args = tc["function"].get("arguments", "{}")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    tool_calls.append({
                        "name": tc["function"]["name"],
                        "arguments": args,
                    })
            return {
                "role": "assistant",
                "content": msg.get("content", ""),
                "tool_calls": tool_calls,
                "finish_reason": "tool_calls" if tool_calls_raw else "stop",
                "raw": data,
            }
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(
                f"OpenAI/DeepSeek request timed out after {self.request_timeout}s"
            )
        except requests.exceptions.ConnectionError:
            raise RetryableError(
                f"OpenAI/DeepSeek unreachable at {self.base_url}"
            )
        except (RetryableError, FatalError, LLMTimeoutError):
            raise
        except Exception as exc:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(exc)}

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
                timeout=self.request_timeout,
            )
            if r.status_code != 200:
                self._classify_http_error(r.status_code, r.text)
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
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(
                f"Anthropic request timed out after {self.request_timeout}s"
            )
        except requests.exceptions.ConnectionError:
            raise RetryableError(
                f"Anthropic API unreachable at {self.base_url}"
            )
        except (RetryableError, FatalError, LLMTimeoutError):
            raise
        except Exception as exc:
            return {"role": "assistant", "content": None, "tool_calls": None,
                    "finish_reason": "error", "raw": str(exc)}

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
