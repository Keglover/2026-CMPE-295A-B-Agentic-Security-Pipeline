import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from promptrail.agent import commands
from promptrail.agent.client import AgentSession, SecurityException
from promptrail.agent.models import Checkpoint, ToolCallRequest, ToolCallResponse
from promptrail.agent.state import load, save
from promptrail.client import request_hash, unavailable
from promptrail.config import Settings
from promptrail.main import app
from promptrail.models import PolicyAction, ExecutionRequirement

runner = CliRunner()


def proposal():
    return ToolCallRequest(request_id="agent-step-1", content="Summarize the report",
                           proposed_tool="summarize", tool_args={"text": "Hello"})


def response(request, outcome="EXECUTED"):
    result = unavailable(request, "POLICY_ALLOW").model_copy(update={
        "status": "evaluated", "policy_action": PolicyAction.ALLOW,
        "execution_requirement": ExecutionRequirement.NONE, "risk_score": 0})
    # Validate JSON so enum instances match strict model fields.
    return ToolCallResponse.model_validate_json(json.dumps({"schema_version": "1", "evaluation": json.loads(result.model_dump_json()),
        "outcome": outcome, "reason_code": "APPROVAL_REQUIRED" if outcome == "REQUIRE_APPROVAL" else "EXECUTED",
        "executor_mode": "MOCK", "tool_output": "Hello" if outcome == "EXECUTED" else None}))


def grant(**changes):
    return {"access_token": "private-agent-token", "token_type": "Bearer", "expires_in": 300,
            "agent_id": "agent:1", "tools": ["summarize"], "permissions": ["jev:evaluate", "jev:tools:call"]} | changes


def test_exchange_and_dispatch_never_send_user_credential_to_tools():
    seen = []
    def handle(request):
        seen.append((request.url.path, request.headers["Authorization"]))
        return httpx.Response(200, json=grant() if request.url.path == "/auth/agent-token" else response(proposal()).model_dump(mode="json"))
    with AgentSession(Settings(), "private-user-token", transport=httpx.MockTransport(handle)) as session:
        session.exchange(["summarize"])
        assert session.user_token is None
        assert session.call(proposal()).outcome == "EXECUTED"
    assert seen == [("/auth/agent-token", "Bearer private-user-token"), ("/tools/call", "Bearer private-agent-token")]
    assert session.credential is None


@pytest.mark.parametrize("changes", [{"tools": ["execute_command"]}, {"expires_in": 301},
                                  {"permissions": ["jev:approvals:write"]}, {"token_type": "Basic"}])
def test_overbroad_or_invalid_agent_grant_denied(changes):
    with AgentSession(Settings(), "user", transport=httpx.MockTransport(lambda _: httpx.Response(200, json=grant(**changes)))) as session:
        with pytest.raises(SecurityException):
            session.exchange(["summarize"])


def test_mismatched_tool_result_denied():
    def handle(request):
        if request.url.path == "/auth/agent-token":
            return httpx.Response(200, json=grant())
        result = response(proposal()).model_dump(mode="json")
        result["evaluation"]["content_hash"] = "0" * 64
        return httpx.Response(200, json=result)
    with AgentSession(Settings(), "user", transport=httpx.MockTransport(handle)) as session:
        session.exchange(["summarize"])
        with pytest.raises(SecurityException, match="INVALID_GATEWAY_RESPONSE"):
            session.call(proposal())


def test_checkpoint_is_owner_only_and_contains_no_credential(tmp_path):
    checkpoint = Checkpoint(gateway_url="http://localhost:8000", tools=["summarize"], requests=[proposal()], next_index=0)
    path = tmp_path / "state.json"
    save(path, checkpoint)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load(path) == checkpoint
    assert "token" not in path.read_text()


def test_checkpoint_symlink_denied(tmp_path):
    target = tmp_path / "target"
    target.write_text("preserve")
    link = tmp_path / "state.json"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        save(link, Checkpoint(gateway_url="http://localhost:8000", tools=["summarize"], requests=[proposal()], next_index=0))
    assert target.read_text() == "preserve"


def test_cli_pauses_and_resumes_exact_request(tmp_path, monkeypatch):
    plan, state = tmp_path / "plan.json", tmp_path / "state.json"
    plan.write_text(json.dumps([proposal().model_dump(mode="json")]))
    calls, agents = [], []
    class Session:
        approved = False
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent_id):
            agents.append(agent_id)
            return "agent:1"
        def call(self, request):
            calls.append(request.model_dump())
            return response(request, "EXECUTED" if self.approved else "REQUIRE_APPROVAL")
    monkeypatch.setattr(commands, "AgentSession", Session)
    monkeypatch.setattr(commands, "_credential", lambda *a: "never-persist-this-token")
    monkeypatch.setattr(commands, "append_event", lambda *a, **k: None)
    first = runner.invoke(app, ["agent", "start", "--plan", str(plan), "--checkpoint", str(state)])
    assert first.exit_code == 1 and "Human intervention required" in first.output
    assert load(state).status == "approval_required" and load(state).next_index == 0
    assert "never-persist" not in state.read_text() + first.output
    Session.approved = True
    resumed = runner.invoke(app, ["agent", "resume", str(state)])
    assert resumed.exit_code == 0 and "MOCK" in resumed.output
    assert calls[0] == calls[1] and agents == [None, "agent:1"]
    assert load(state).status == "complete"


def test_transport_loss_saves_uncertainty_and_prevents_automatic_resume(tmp_path, monkeypatch):
    checkpoint = Checkpoint(gateway_url="http://localhost:8000", tools=["summarize"], requests=[proposal()], next_index=0,
                            status="uncertain")
    state = tmp_path / "state.json"
    save(state, checkpoint)
    monkeypatch.setattr(commands, "_credential", lambda *a: pytest.fail("Must not log in or redispatch"))
    result = runner.invoke(app, ["agent", "resume", str(state)])
    assert result.exit_code == 2 and "MANUAL_RECONCILIATION_REQUIRED" in result.output
