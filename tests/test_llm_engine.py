"""Tests for ai_core.llm_engine — LLM client, retry, circuit breaker."""

import time

import pytest

from ai_core.llm_engine import (
    CircuitBreaker,
    FatalError,
    LLMClient,
    LLMError,
    LLMTimeoutError,
    RetryableError,
    detect_provider,
    retry_with_backoff,
)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        assert not cb.is_open

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=30)
        cb.failure()
        assert not cb.is_open
        cb.failure()
        assert cb.is_open

    def test_recovery_after_timeout(self, monkeypatch):
        import ai_core.llm_engine as engine_mod

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        cb.failure()
        assert cb.is_open
        # Advance time past recovery — move clock forward 60 seconds
        real_monotonic = engine_mod.time.monotonic
        monkeypatch.setattr(engine_mod.time, "monotonic",
                           lambda: real_monotonic() + 60.0)
        assert not cb.is_open

    def test_success_resets_counter(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        cb.failure()
        cb.failure()
        assert not cb.is_open
        cb.success()
        assert not cb.is_open
        cb.failure()
        assert not cb.is_open  # reset to 1


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


class TestRetry:
    def test_retry_on_retryable(self):
        call_count = [0]

        @retry_with_backoff(max_retries=3, base_delay=0.001)
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise RetryableError("transient")
            return "ok"

        result = flaky()
        assert result == "ok"
        assert call_count[0] == 3

    def test_no_retry_on_fatal(self):
        call_count = [0]

        @retry_with_backoff(max_retries=3, base_delay=0.001)
        def fatal():
            call_count[0] += 1
            raise FatalError("auth")

        with pytest.raises(FatalError):
            fatal()
        assert call_count[0] == 1  # no retries

    def test_exhausted_retries_raises(self):
        call_count = [0]

        @retry_with_backoff(max_retries=2, base_delay=0.001)
        def always_fails():
            call_count[0] += 1
            raise RetryableError("still failing")

        with pytest.raises(RetryableError):
            always_fails()
        assert call_count[0] == 3  # initial + 2 retries


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------


class TestErrorClassification:
    def test_classify_429_is_retryable(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        with pytest.raises(RetryableError):
            client._classify_http_error(429, "rate limited")

    def test_classify_500_is_retryable(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        with pytest.raises(RetryableError):
            client._classify_http_error(503, "server error")

    def test_classify_401_is_fatal(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        with pytest.raises(FatalError):
            client._classify_http_error(401, "unauthorized")

    def test_classify_403_is_fatal(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        with pytest.raises(FatalError):
            client._classify_http_error(403, "forbidden")


# ---------------------------------------------------------------------------
# LLMClient initialization
# ---------------------------------------------------------------------------


class TestLLMClientInit:
    def test_default_model_openai(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        assert client.provider == "openai"
        assert client.model == "gpt-4o-mini"

    def test_default_model_deepseek(self):
        client = LLMClient(provider="deepseek", api_key="sk-test")
        assert client.provider == "deepseek"
        assert client.model == "deepseek-v4-flash"

    def test_custom_model(self):
        client = LLMClient(provider="openai", model="gpt-4o", api_key="sk-test")
        assert client.model == "gpt-4o"

    def test_request_timeout_default(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        assert client.request_timeout == 120.0

    def test_request_timeout_custom(self):
        client = LLMClient(provider="openai", api_key="sk-test", request_timeout=60)
        assert client.request_timeout == 60.0

    def test_circuit_breaker_initialized(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        assert not client._circuit_breaker.is_open


# ---------------------------------------------------------------------------
# Chat — tool calling
# ---------------------------------------------------------------------------


class TestOpenAIChat:
    def test_normal_response(self, monkeypatch):
        """Normal text response is parsed correctly."""
        from tests.conftest import fake_openai_response

        def _post(url, **kwargs):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return fake_openai_response(content="Hello, world!")
            return R

        monkeypatch.setattr("requests.post", _post)
        monkeypatch.setattr("requests.get", lambda url, **kw: type("R", (), {"status_code": 200})())

        client = LLMClient(provider="openai", api_key="sk-test")
        result = client.chat("You are helpful.", [{"role": "user", "content": "Hi"}])
        assert result["finish_reason"] == "stop"
        assert result["content"] == "Hello, world!"
        assert result["tool_calls"] is None

    def test_tool_call_response(self, monkeypatch):
        """Tool call response is parsed into tool_calls list."""
        from tests.conftest import fake_openai_response

        def _post(url, **kwargs):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return fake_openai_response(
                        content=None,
                        tool_calls=[{
                            "name": "run_unauthenticated_recon",
                            "arguments": {"vault_addr": "http://test:8200"},
                        }],
                    )
            return R

        monkeypatch.setattr("requests.post", _post)
        monkeypatch.setattr("requests.get", lambda url, **kw: type("R", (), {"status_code": 200})())

        client = LLMClient(provider="openai", api_key="sk-test")
        result = client.chat("You are helpful.", [{"role": "user", "content": "Scan"}])
        assert result["finish_reason"] == "tool_calls"
        assert result["tool_calls"] is not None
        assert result["tool_calls"][0]["name"] == "run_unauthenticated_recon"
        assert result["tool_calls"][0]["arguments"]["vault_addr"] == "http://test:8200"


# ---------------------------------------------------------------------------
# Health / availability
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_returns_dict(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        health = client.health()
        assert health["provider"] == "openai"
        assert health["model"] == "gpt-4o-mini"
        assert "circuit_breaker_open" in health
        assert "reachable" in health

    def test_is_available_with_api_key(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        assert client.is_available()

    def test_is_available_without_api_key(self):
        client = LLMClient(provider="openai", api_key="")
        assert not client.is_available()

    def test_health_when_circuit_open(self):
        client = LLMClient(provider="openai", api_key="sk-test")
        # Force circuit open
        for _ in range(3):
            client._circuit_breaker.failure()
        assert not client.is_available()
        health = client.health()
        assert health["circuit_breaker_open"]


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


class TestOllama:
    def test_provider_detection_fallback(self, monkeypatch):
        """Without any env vars, detect_provider falls back to ollama if reachable."""
        monkeypatch.setattr("requests.get", lambda url, **kw: type("R", (), {"status_code": 200})())
        provider = detect_provider()
        assert provider == "ollama"

    def test_ollama_tool_call(self, monkeypatch):
        """Ollama native tool calling path — checks the response format."""
        from tests.conftest import fake_ollama_response

        # Mock Ollama's /api/tags for provider detection
        monkeypatch.setattr(
            "requests.get",
            lambda url, **kw: type("R", (), {
                "status_code": 200,
                "json": lambda s=None: {"models": [{"name": "llama3.1:8b"}]},
            })(),
        )

        import requests as req_mod

        def _post(url, **kwargs):
            resp = type("R", (), {
                "status_code": 200,
                "json": lambda s=None: fake_ollama_response(
                    content="",
                    tool_calls=[{
                        "name": "run_unauthenticated_recon",
                        "arguments": {"vault_addr": "http://test:8200"},
                    }],
                ),
            })()
            return resp

        monkeypatch.setattr(req_mod, "post", _post)

        client = LLMClient(provider="ollama")
        # Pass a minimal tool definition so the native tool-calling path is used
        dummy_tools = [{
            "type": "function",
            "function": {
                "name": "run_unauthenticated_recon",
                "description": "Run recon scan",
                "parameters": {"type": "object", "properties": {}},
            },
        }]
        result = client.chat(
            "You are helpful.",
            [{"role": "user", "content": "Scan"}],
            tools=dummy_tools,
        )
        assert result["finish_reason"] == "tool_calls"
        assert result["tool_calls"][0]["name"] == "run_unauthenticated_recon"
