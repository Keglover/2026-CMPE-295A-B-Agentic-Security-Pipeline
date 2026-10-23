import pytest

from promptrail.agent import commands
from promptrail.agent.client import SecurityException
from promptrail.agent.models import Checkpoint, ToolCallRequest
from promptrail.agent.state import save, load


def checkpoint():
    return Checkpoint(gateway_url="http://127.0.0.1:8003", agent_id="agent:stable", tools=["summarize", "execute_command"],
        requests=[ToolCallRequest(request_id="completed-summary", content="Summarize", proposed_tool="summarize", tool_args={"text": "hello"}),
                  ToolCallRequest(request_id="expired-command", content="Print a greeting", proposed_tool="execute_command", tool_args={"command": "echo hello"})],
        next_index=1, status="approval_required")


@pytest.mark.parametrize("status", ["consumed", "not_found", "rejected", "approved", "pending"])
def test_review_renewal_does_not_retry_uncertain_or_live_review(tmp_path, monkeypatch, status):
    state = checkpoint()
    path = tmp_path / "state.json"
    save(path, state)
    class Session:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent): return agent
        def approval_status(self, rid): return status
        def call(self, request): pytest.fail("Must not dispatch or queue a new request")
    monkeypatch.setattr(commands, "AgentSession", Session)
    monkeypatch.setattr(commands, "_credential", lambda *a: "in-memory-token")
    with pytest.raises(SecurityException):
        commands._run(state, path, commands.load_settings(state.gateway_url), False, renew_review=True)
    assert load(path).requests[1].request_id == "expired-command"
    assert load(path).next_index == 1


def test_expired_review_gets_new_id_and_keeps_completed_prefix(tmp_path, monkeypatch):
    from promptrail.client import unavailable
    from promptrail.agent.models import ToolCallResponse
    from promptrail.models import PolicyAction, ExecutionRequirement
    import typer
    state = checkpoint()
    path = tmp_path / "state.json"
    save(path, state)
    called = []
    class Session:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent): return agent
        def approval_status(self, rid):
            assert rid == "expired-command"
            return "timed_out"
        def call(self, request):
            called.append(request)
            evaluation = unavailable(request, "COMMAND_APPROVAL_REQUIRED").model_copy(update={
                "status": "evaluated", "policy_action": PolicyAction.ALLOW, "risk_score": 0,
                "execution_requirement": ExecutionRequirement.REQUIRE_APPROVAL})
            return ToolCallResponse(evaluation=evaluation, outcome="REQUIRE_APPROVAL",
                                    reason_code="APPROVAL_REQUIRED", executor_mode="MOCK")
    monkeypatch.setattr(commands, "AgentSession", Session)
    monkeypatch.setattr(commands, "_credential", lambda *a: "in-memory-token")
    monkeypatch.setattr(commands, "append_event", lambda *a, **k: None)
    with pytest.raises(typer.Exit):
        commands._run(state, path, commands.load_settings(state.gateway_url), False, renew_review=True)
    stored = load(path)
    assert stored.requests[0].request_id == "completed-summary" and stored.next_index == 1
    assert stored.requests[1].request_id != "expired-command"
    assert stored.requests[1].tool_args == {"command": "echo hello"}
    assert len(called) == 1 and stored.status == "approval_required"
    assert stored.agent_id == "agent:stable" and "in-memory-token" not in path.read_text()
