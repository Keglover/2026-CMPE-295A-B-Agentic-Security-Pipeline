import json

import httpx
import pytest
import typer
from pydantic import SecretStr
from typer.testing import CliRunner

from promptrail.agent import commands as agent_commands, engine
from promptrail.agent.conversation import ConversationCheckpoint, Message, ModelToolCall, SYSTEM_PROMPT
from promptrail.agent.models import ToolCallRequest, ToolCallResponse
from promptrail.agent.model_client import ModelClient
from promptrail.agent.state import load, save
from promptrail.approvals import commands
from promptrail.client import unavailable
from promptrail.config import Settings
from promptrail.main import app
from promptrail.models import PolicyAction, ExecutionRequirement


def paused(path):
    prompt = "Summarize the report and print a greeting."
    functions = [{"name": "summarize", "arguments": '{"text":"Hello"}'},
                 {"name": "execute_command", "arguments": '{"command":"echo hello"}'}]
    calls = [ModelToolCall(id=f"call-{i}", function=function) for i, function in enumerate(functions)]
    requests = [ToolCallRequest(request_id=f"request-{i}", content=prompt, proposed_tool=function["name"],
                                tool_args=json.loads(function["arguments"])) for i, function in enumerate(functions)]
    cp = ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", agent_id="agent:stable", tools=["summarize", "execute_command"],
        prompt=prompt, model_url="http://127.0.0.1:11434/v1", model_name="test-model", iteration=1,
        requests=requests, tool_call_ids=[c.id for c in calls], next_index=1, status="approval_required",
        messages=[Message(role="system", content=SYSTEM_PROMPT), Message(role="user", content=prompt),
                  Message(role="assistant", tool_calls=calls), Message(role="tool", tool_call_id="call-0", content="Safe summary")])
    save(path, cp)
    return cp


def evaluated(request):
    return unavailable(request, "POLICY_ALLOW").model_copy(update={"status": "evaluated", "policy_action": PolicyAction.ALLOW,
        "risk_score": 0, "execution_requirement": ExecutionRequirement.NONE})


@pytest.mark.parametrize("answer", ["y\n", "n\n"])
def test_paired_review_immediately_continues_conversation_without_repeating_prefix(tmp_path, monkeypatch, answer):
    path = tmp_path / "conversation.json"
    cp = paused(path)
    events = []
    item = {"request_id": "request-1", "requester": "agent:stable", "proposed_tool": "execute_command", "action_hash": "a" * 64,
            "action_details": {"content": cp.prompt, "source_type": "direct_prompt", "tool_args": {"command": "echo hello"}}}
    class Session:
        def __init__(self, settings, token): assert token == "private-caller-token"
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent_id): return agent_id
        def approval_status(self, rid): return "approved" if "approve" in events else "pending"
        def evaluate(self, request): return evaluated(request)
        def call(self, request):
            assert request.request_id == "request-1" and load(path).status == "uncertain"
            events.append("dispatch:" + request.request_id)
            return ToolCallResponse(evaluation=evaluated(request), outcome="EXECUTED", reason_code="EXECUTED",
                                    executor_mode="MOCK", tool_output="Safe greeting")
    class Client:
        last_endpoint = "primary"
        def __init__(self, cp): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def complete(self, messages, tools):
            events.append("model")
            assert [m["tool_call_id"] for m in messages if m["role"] == "tool"] == ["call-0", "call-1"]
            return Message(role="assistant", content="Done")
    def handle(request):
        assert request.headers["Authorization"] == "Bearer private-reviewer-token"
        if request.url.path == "/pending": return httpx.Response(200, json={"pending": [item]})
        events.append("approve" if request.url.path.startswith("/approve") else "reject")
        return httpx.Response(200, json={"status": "approved" if events[-1] == "approve" else "rejected"})
    original = httpx.Client
    monkeypatch.setattr(commands.httpx, "Client", lambda **kw: original(**kw, transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(commands, "AgentSession", Session)
    monkeypatch.setattr(commands, "ModelClient", Client)
    monkeypatch.setattr(commands, "_paired_login", lambda *a: (SecretStr("private-caller-token"), SecretStr("private-reviewer-token")))
    monkeypatch.setattr(engine, "append_event", lambda *a, **kw: None)
    result = CliRunner().invoke(app, ["approvals", "review", "--login", "--resume-checkpoint", str(path),
        "--request-id", "request-1", "--expected-hash", "a" * 64], input=answer)
    assert result.exit_code == 0, result.output
    assert events == (["approve", "dispatch:request-1", "model"] if answer.startswith("y") else ["reject"])
    assert load(path).status == ("complete" if answer.startswith("y") else "approval_required")
    assert "private-caller-token" not in result.output + path.read_text()
    assert "private-reviewer-token" not in result.output + path.read_text()


def test_conversation_expired_review_renewal_keeps_tool_call_ids_and_prefix(tmp_path, monkeypatch):
    path = tmp_path / "conversation.json"
    cp = paused(path)
    proposed = []
    class Session:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent_id): return agent_id
        def approval_status(self, rid):
            assert rid == "request-1"
            return "timed_out"
        def evaluate(self, request): return evaluated(request)
        def call(self, request):
            proposed.append(request.request_id)
            return ToolCallResponse(evaluation=evaluated(request), outcome="REQUIRE_APPROVAL",
                                    reason_code="APPROVAL_REQUIRED", executor_mode="MOCK")
    class Client:
        def __init__(self, cp): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def complete(self, *a): pytest.fail("Do not regenerate a paused tool call")
    monkeypatch.setattr(agent_commands, "AgentSession", Session)
    monkeypatch.setattr(agent_commands, "ModelClient", Client)
    monkeypatch.setattr(agent_commands, "_credential", lambda *a: "private-caller-token")
    monkeypatch.setattr(engine, "append_event", lambda *a, **kw: None)
    with pytest.raises(typer.Exit):
        agent_commands._run(cp, path, Settings(), False, renew_review=True)
    new = load(path)
    assert new.tool_call_ids == ["call-0", "call-1"] and new.next_index == 1
    assert new.requests[0].request_id == "request-0"
    assert new.requests[1].request_id != "request-1" and proposed == [new.requests[1].request_id]


def test_generation_failover_does_not_replay_completed_tool_calls(tmp_path, monkeypatch):
    path = tmp_path / "conversation.json"
    cp = ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", tools=["summarize"], prompt="Summarize the report",
        model_url="http://127.0.0.1:11434/v1", model_name="primary", fallback_url="http://127.0.0.1:11435/v1", fallback_model="fallback")
    save(path, cp)
    model_requests, dispatched = [], []
    def handle(request):
        model_requests.append(request.url.port)
        if request.url.port == 11434:
            raise httpx.ConnectError("unreachable", request=request)
        if model_requests.count(11435) == 1:
            message = {"role": "assistant", "tool_calls": [{"id": "call-1", "type": "function",
                "function": {"name": "summarize", "arguments": '{"text":"Hello"}'}}]}
            return httpx.Response(200, json={"choices": [{"finish_reason": "tool_calls", "message": message}]})
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "Done"}}]})
    class Session:
        def evaluate(self, request): return evaluated(request)
        def call(self, request):
            dispatched.append(request.request_id)
            return ToolCallResponse(evaluation=evaluated(request), outcome="EXECUTED", reason_code="EXECUTED",
                                    executor_mode="MOCK", tool_output="Safe summary")
    monkeypatch.setattr(engine, "append_event", lambda *a, **kw: None)
    with ModelClient(cp, transport=httpx.MockTransport(handle)) as model:
        engine.run(cp, path, Settings(), Session(), model)
    assert model_requests == [11434, 11435, 11434, 11435]
    assert len(dispatched) == 1 and load(path).status == "complete"
    assert load(path).last_model_endpoint == "fallback"
