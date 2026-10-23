import json

import httpx
import pytest

from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.model_client import ModelClient
from promptrail.agent.model_config import model_values


def profile(**changes):
    return ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", tools=["summarize"], prompt="Summarize a report",
        model_protocol="ollama", model_url="https://ollama.com", model_name="deepseek-v4.1-flash",
        fallback_url="https://api.openai.com/v1", **changes)


def native_reply(content="Hello", calls=None):
    return {"done": True, "done_reason": "stop", "message": {"role": "assistant", "content": content,
                                                               "tool_calls": calls or []}}


def test_native_request_uses_selected_model_and_credentials_from_private_file(tmp_path):
    path = tmp_path / ".env.models"
    path.write_text("OLLAMA_API_KEY=private-ollama-key\nOPENAI_API_KEY=\nJEV_FALLBACK_MODEL_NAME=\n")
    path.chmod(0o600)
    cp = profile(model_env_file=str(path))
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=native_reply())
    with ModelClient(cp, transport=httpx.MockTransport(handle)) as client:
        assert client.complete([{"role": "user", "content": "Hello!"}], []).content == "Hello"
    assert len(seen) == 1 and str(seen[0].url) == "https://ollama.com/api/chat"
    assert seen[0].headers["Authorization"] == "Bearer private-ollama-key"
    body = json.loads(seen[0].content)
    assert body["model"] == "deepseek-v4.1-flash" and body["stream"] is False
    assert body["options"]["num_predict"] == 2048 and "tool_choice" not in body
    assert "private-ollama-key" not in cp.model_dump_json()


def test_missing_openai_fallback_only_stops_when_primary_is_unavailable(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-ollama-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("JEV_FALLBACK_MODEL_NAME", raising=False)
    seen = []
    def handle(request):
        seen.append(request)
        raise httpx.ConnectError("unreachable", request=request)
    with ModelClient(profile(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="FALLBACK_CONFIGURATION_REQUIRED"):
            client.complete([], [])
    assert len(seen) == 1 and seen[0].url.host == "ollama.com"


def test_adding_openai_key_and_model_enables_saved_fallback_scaffold(tmp_path):
    path = tmp_path / ".env.models"
    path.write_text("OLLAMA_API_KEY=private-ollama-key\nOPENAI_API_KEY=private-openai-key\nJEV_FALLBACK_MODEL_NAME=chosen-model\n")
    path.chmod(0o600)
    seen = []
    def handle(request):
        seen.append(request)
        if request.url.host == "ollama.com":
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "Fallback reply"}}]})
    with ModelClient(profile(model_env_file=str(path)), transport=httpx.MockTransport(handle)) as client:
        assert client.complete([], []).content == "Fallback reply"
        assert client.last_endpoint == "fallback"
    assert str(seen[1].url) == "https://api.openai.com/v1/chat/completions"
    assert seen[1].headers["Authorization"] == "Bearer private-openai-key"
    assert "private-ollama-key" not in str(seen[1].headers) + seen[1].content.decode()
    assert json.loads(seen[1].content)["model"] == "chosen-model"
    assert json.loads(seen[1].content)["max_completion_tokens"] == 2048


def test_native_tool_calls_get_unique_saved_ids_and_object_args(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-key")
    calls = [{"function": {"name": "summarize", "arguments": {"text": "Hello"}}}] * 2
    with ModelClient(profile(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json=native_reply("", calls)))) as client:
        reply = client.complete([], [])
    assert len(reply.tool_calls) == 2 and reply.tool_calls[0].id != reply.tool_calls[1].id
    assert json.loads(reply.tool_calls[0].function.arguments) == {"text": "Hello"}


def test_saved_tool_history_translates_to_native_name_protocol(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-key")
    messages = [{"role": "assistant", "tool_calls": [{"id": "call-1", "type": "function",
        "function": {"name": "summarize", "arguments": '{"text":"Hello"}'}}]},
                {"role": "tool", "tool_call_id": "call-1", "content": "Safe summary"}]
    seen = []
    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=native_reply())
    with ModelClient(profile(), transport=httpx.MockTransport(handle)) as client:
        client.complete(messages, [])
    assert seen[0]["messages"][0]["tool_calls"][0]["function"]["arguments"] == {"text": "Hello"}
    assert seen[0]["messages"][1] == {"role": "tool", "tool_name": "summarize", "content": "Safe summary"}


@pytest.mark.parametrize("reply", [
    native_reply() | {"done": False}, native_reply() | {"done_reason": "length"},
    native_reply(calls=[{"function": {"name": "summarize", "arguments": []}}]),
])
def test_incomplete_or_malformed_native_reply_never_triggers_fallback(monkeypatch, reply):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-key")
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=reply)
    with ModelClient(profile(), transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(SecurityException, match="INVALID_MODEL_RESPONSE"):
            client.complete([], [])
    assert len(seen) == 1


def test_environment_file_does_not_expand_or_execute_values(tmp_path, monkeypatch):
    path = tmp_path / ".env.models"
    monkeypatch.setenv("SECRET_OTHER_SETTING", "must-not-expand")
    path.write_text('OLLAMA_API_KEY=${SECRET_OTHER_SETTING}\nOTHER=$(touch marker)\n')
    path.chmod(0o600)
    values = model_values(path)
    assert values["OLLAMA_API_KEY"] == "${SECRET_OTHER_SETTING}"
    assert values["OTHER"] == "$(touch marker)" and not (tmp_path / "marker").exists()


def test_environment_file_requires_private_permissions_and_no_symlink(tmp_path):
    path = tmp_path / ".env.models"
    path.write_text("OLLAMA_API_KEY=private\n")
    with pytest.raises(ValueError):
        model_values(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        model_values(link)
