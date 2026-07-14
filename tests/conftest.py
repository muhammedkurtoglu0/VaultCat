"""Shared fixtures for AI component tests."""

import json

import pytest

# ---------------------------------------------------------------------------
# Fake constants
# ---------------------------------------------------------------------------

FAKE_VAULT_ADDR = "http://192.0.2.1:8200"  # TEST-NET-1 (safe)
FAKE_TOKEN = "hvs.test-token-unit-test-abc123"


# ---------------------------------------------------------------------------
# Fake HTTP responses
# ---------------------------------------------------------------------------


class FakeResponse:
    """Minimal requests.Response stub."""

    def __init__(self, status_code: int, json_data: dict | None = None,
                 text: str = ""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body")
        return self._json_data


def fake_openai_response(content: str | None = None,
                          tool_calls: list[dict] | None = None) -> dict:
    """Build a fake OpenAI chat completion response dict."""
    msg: dict = {"role": "assistant", "content": content or ""}
    if tool_calls:
        msg["tool_calls"] = [
            {
                "id": f"call_{i}",
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": json.dumps(tc.get("arguments", {})),
                },
            }
            for i, tc in enumerate(tool_calls)
        ]
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": msg, "finish_reason": "tool_calls" if tool_calls else "stop"}
        ],
    }


def fake_anthropic_response(content: str = "",
                             tool_use_blocks: list[dict] | None = None) -> dict:
    """Build a fake Anthropic messages response dict."""
    blocks: list[dict] = []
    if content:
        blocks.append({"type": "text", "text": content})
    if tool_use_blocks:
        for tb in tool_use_blocks:
            blocks.append({
                "type": "tool_use",
                "id": tb.get("id", "tool_0"),
                "name": tb.get("name", ""),
                "input": tb.get("input", {}),
            })
    return {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "content": blocks,
        "model": "claude-sonnet-5",
        "stop_reason": "tool_use" if tool_use_blocks else "end_turn",
    }


def fake_ollama_response(content: str = "",
                          tool_calls: list[dict] | None = None) -> dict:
    """Build a fake Ollama /api/chat response dict."""
    msg: dict = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = [
            {"function": {"name": tc["name"],
                          "arguments": tc.get("arguments", {})}}
            for tc in tool_calls
        ]
    return {"model": "llama3.1:8b", "message": msg, "done": True}


# ---------------------------------------------------------------------------
# Enumeration data fixture
# ---------------------------------------------------------------------------


def sample_enum_data() -> dict:
    return {
        "capabilities": json.dumps({
            "status": "completed",
            "findings": [
                {"severity": "HIGH", "title": "Token has sys/mounts read access",
                 "description": "Can list all secret engines"},
                {"severity": "CRITICAL", "title": "Token can create new tokens",
                 "description": "auth/token/create is permitted"},
            ],
        }),
        "priv_esc": json.dumps({
            "status": "completed",
            "findings": [
                {"severity": "HIGH",
                 "title": "Token can escalate via token creation"},
            ],
        }),
        "kv_paths": json.dumps({
            "status": "completed",
            "paths": ["secret/", "secret/database", "kv/app"],
        }),
        "findings": [
            {"severity": "HIGH", "title": "Vault running on HTTP",
             "module": "tls_scanner"},
            {"severity": "MEDIUM", "title": "Vault version 1.15.6 has 3 CVEs",
             "module": "version_risk_scanner"},
            {"severity": "HIGH",
             "title": "Token can create new tokens",
             "module": "capability_scanner"},
        ],
    }


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_token() -> str:
    return FAKE_TOKEN


@pytest.fixture
def fake_vault_addr() -> str:
    return FAKE_VAULT_ADDR


@pytest.fixture
def enum_data() -> dict:
    return sample_enum_data()


@pytest.fixture
def mock_openai(monkeypatch):
    """Patch requests.post for OpenAI-compatible endpoints."""
    original_post = __import__("requests").post

    def _mock(url: str, **kwargs):
        r = FakeResponse(200, json_data=fake_openai_response(
            content="This is a mocked response from the AI.",
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    return _mock


@pytest.fixture
def mock_openai_tool_call(monkeypatch):
    """Patch requests.post to return a tool_calls response."""
    def _mock(url: str, **kwargs):
        r = FakeResponse(200, json_data=fake_openai_response(
            content="Let me run that tool.",
            tool_calls=[{"name": "run_unauthenticated_recon",
                         "arguments": {"vault_addr": FAKE_VAULT_ADDR}}],
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    return _mock


@pytest.fixture
def mock_openai_error_429(monkeypatch):
    """Patch requests.post to return a 429 rate-limit."""
    call_count = [0]

    def _mock(url: str, **kwargs):
        call_count[0] += 1
        if call_count[0] <= 2:
            r = FakeResponse(429, text="Rate limit exceeded")
            return r
        r = FakeResponse(200, json_data=fake_openai_response(
            content="Finally succeeded after retries.",
        ))
        return r

    monkeypatch.setattr("requests.post", _mock)
    monkeypatch.setattr("time.sleep", lambda s: None)  # speed up retries
    return _mock
