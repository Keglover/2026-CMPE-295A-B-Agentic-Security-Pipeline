import json

import httpx
import pytest

from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.model_client import ModelClient


def checkpoint(**changes):
    return ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", tools=["summarize"], prompt="Summarize the report",
        model_url="http://127.0.0.1:11434/v1", model_name="primary-model",
        fallback_url="http://127.0.0.1:11435/v1", fallback_model="fallback-model", **changes)


def reply():
    return {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "Safe reply"}}]}


@pytest.mark.parametrize("failure", ["connect", "disconnect", "timeout", "server"])
def test_unavailable_primary_fails_over_once_without_sending_gateway_credential(monkeypatch, failure):
    monkeypatch.setenv("JEV_AUTH_TOKEN", "private-gateway-token")
    seen = []
    def handle(request):
        seen.append(request)
        if request.url.port == 11434:
            if failure == "connect": raise httpx.ConnectError("unreachable", request=request)
            if failure == "disconnect": raise httpx.ReadError("disconnected", request=request)
            if failure == "timeout": raise httpx.ReadTimeout("timeout", request=request)
            return httpx.Response(503, json={"private_detail": "must not print"})
        return httpx.Response(200, json=reply())
    with ModelClient(checkpoint(), transport=httpx.MockTransport(handle)) as client:
        result = client.complete([{"role": "user", "content": "Hello"}], [])
        assert result.content == "Safe reply" and client.last_endpoint == "fallback"
    assert [r.url.port for r in seen] == [11434, 11435]
    assert all("private-gateway-token" not in str(r.headers) + r.content.decode() for r in seen)


@pytest.mark.parametrize("status", [302, 400, 401, 403, 429])
def test_request_denial_does_not_trigger_fallback(status):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(status, headers={"Location": "https://evil.example/"}, json={"error": "private error"})
    with ModelClient(checkpoint(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="MODEL_REQUEST_REJECTED"):
            client.complete([], [])
    assert len(seen) == 1


@pytest.mark.parametrize("data", [
    {"choices": []}, {"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": "partial"}}]},
    {"choices": [{"finish_reason": "stop", "message": {"role": "system", "content": "bad"}}]},
    {"choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "tool_calls": [
        {"id": "call", "type": "function", "function": {"name": "summarize", "arguments": "{}", "approved": True}}]}}]},
])
def test_invalid_or_incomplete_model_response_never_fails_over(data):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=data)
    with ModelClient(checkpoint(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="INVALID_MODEL_RESPONSE"):
            client.complete([], [])
    assert len(seen) == 1


def test_separate_provider_keys_and_token_limits(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-primary-key")
    monkeypatch.setenv("OPENAI_API_KEY", "private-fallback-key")
    cp = checkpoint().model_copy(update={"model_url": "https://primary.example/v1", "fallback_url": "https://fallback.example/v1"})
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(503 if request.url.host == "primary.example" else 200, json=reply())
    with ModelClient(cp, transport=httpx.MockTransport(handle)) as client:
        client.complete([], [])
    assert seen[0].headers["Authorization"] == "Bearer private-primary-key"
    assert seen[1].headers["Authorization"] == "Bearer private-fallback-key"
    assert json.loads(seen[0].content)["max_tokens"] == 2048
    assert json.loads(seen[1].content)["max_completion_tokens"] == 2048
    assert "tool_choice" not in json.loads(seen[0].content)
    assert not client.keys


def test_same_url_different_credentials_remain_separate(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-primary-key")
    monkeypatch.setenv("OPENAI_API_KEY", "private-fallback-key")
    cp = checkpoint().model_copy(update={"fallback_url": "http://127.0.0.1:11434/v1"})
    seen = []
    def handle(request):
        seen.append(request.headers["Authorization"])
        return httpx.Response(503 if len(seen) == 1 else 200, json=reply())
    with ModelClient(cp, transport=httpx.MockTransport(handle)) as client:
        client.complete([], [])
    assert seen == ["Bearer private-primary-key", "Bearer private-fallback-key"]


def test_oversized_response_is_denied_without_fallback():
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, content=b"A" * 1048577)
    with ModelClient(checkpoint(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="INVALID_MODEL_RESPONSE"):
            client.complete([], [])
    assert len(seen) == 1


def test_remote_provider_requires_explicit_model_credential(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    cp = checkpoint().model_copy(update={"model_url": "https://primary.example/v1"})
    with pytest.raises(SecurityException, match="MODEL_CREDENTIAL_REQUIRED"):
        ModelClient(cp)


def test_both_providers_unreachable_stops_without_retry():
    seen = []
    def handle(request):
        seen.append(request)
        raise httpx.ConnectError("private details", request=request)
    with ModelClient(checkpoint(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="ALL_MODELS_UNAVAILABLE"):
            client.complete([], [])
    assert len(seen) == 2


def test_gateway_token_variable_cannot_be_selected_for_model_authentication():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        checkpoint(model_key_env="JEV_AUTH_TOKEN")
