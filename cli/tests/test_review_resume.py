import json

import httpx
import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from promptrail.agent import commands as agent_commands
from promptrail.agent.client import SecurityException
from promptrail.agent.models import Checkpoint, ToolCallRequest, ToolCallResponse
from promptrail.agent.state import load, save
from promptrail.approvals import commands
from promptrail.auth.device import LoginError
from promptrail.client import unavailable
from promptrail.main import app
from promptrail.models import ExecutionRequirement, PolicyAction


runner = CliRunner()


def setup(tmp_path, monkeypatch, *, change=None, state_status="approval_required", approval_status="pending",
          review_status="approved", lost_response=False):
    requests = [ToolCallRequest(request_id="already-done", content="Summarize", proposed_tool="summarize", tool_args={"text": "Hello"}),
                ToolCallRequest(request_id="command-1", content="Print a greeting", proposed_tool="execute_command", tool_args={"command": "echo hello"})]
    state = Checkpoint(gateway_url="http://127.0.0.1:8003", agent_id="agent:stable", tools=["execute_command", "summarize"],
                       requests=requests, next_index=1, status=state_status)
    path = tmp_path / "state.json"
    save(path, state)
    item = {"request_id": "command-1", "requester": "agent:stable", "proposed_tool": "execute_command",
            "action_hash": "a" * 64, "action_details": {"content": "Print a greeting", "source_type": "direct_prompt",
                                                        "tool_args": {"command": "echo hello"}}}
    item.update(change or {})
    events = []
    class Session:
        def __init__(self, settings, token):
            assert token == "private-caller-token"
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, agent):
            assert agent == "agent:stable"
            events.append("exchange")
            return agent
        def approval_status(self, rid):
            events.append("status")
            return "approved" if "/approve/command-1" in events else approval_status
        def call(self, request):
            events.append("dispatch:" + request.request_id)
            if lost_response:
                raise SecurityException("GATEWAY_UNAVAILABLE")
            evaluation = unavailable(request, "POLICY_ALLOW").model_copy(update={"status": "evaluated",
                "policy_action": PolicyAction.ALLOW, "execution_requirement": ExecutionRequirement.NONE, "risk_score": 0})
            return ToolCallResponse(evaluation=evaluation, outcome="EXECUTED", reason_code="EXECUTED", executor_mode="MOCK")
    def handle(request):
        assert request.headers["Authorization"] == "Bearer private-reviewer-token"
        events.append(request.url.path)
        if request.url.path == "/pending":
            return httpx.Response(200, json={"pending": [item]})
        return httpx.Response(200, json={"status": review_status if request.url.path.startswith("/approve") else "rejected"})
    original = httpx.Client
    monkeypatch.setattr(commands.httpx, "Client", lambda **kw: original(**kw, transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(commands, "AgentSession", Session)
    monkeypatch.setattr(commands, "_paired_login", lambda *a: (SecretStr("private-caller-token"), SecretStr("private-reviewer-token")))
    monkeypatch.setattr(agent_commands, "append_event", lambda *a, **kw: None)
    return path, events


def invoke(path, input="y\n", extra=()):
    return runner.invoke(app, ["approvals", "review", "--resume-checkpoint", str(path), "--login", *extra], input=input)


def test_approved_exact_action_resumes_without_repeating_completed_prefix(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    result = invoke(path)
    assert result.exit_code == 0, result.output
    assert events == ["exchange", "status", "/pending", "status", "/approve/command-1", "status", "dispatch:command-1"]
    assert load(path).status == "complete" and load(path).next_index == 2
    assert "private-caller-token" not in result.output + path.read_text()
    assert "private-reviewer-token" not in result.output + path.read_text()


def test_rejection_does_not_resume(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    result = invoke(path, input="\n")
    assert result.exit_code == 0 and "/reject/command-1" in events
    assert not any(event.startswith("dispatch") for event in events)
    assert load(path).status == "approval_required" and load(path).next_index == 1


def test_queued_confirmation_cannot_approve_a_different_fingerprint(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    result = invoke(path, extra=("--request-id", "command-1", "--expected-hash", "b" * 64))
    assert result.exit_code == 2 and "REVIEW_HASH_MISMATCH" in result.output
    assert "/approve/command-1" not in events and "dispatch:command-1" not in events


def test_matching_fingerprint_still_requires_explicit_confirmation(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    result = invoke(path, input="\n", extra=("--request-id", "command-1", "--expected-hash", "a" * 64))
    assert result.exit_code == 0 and "/reject/command-1" in events
    assert "dispatch:command-1" not in events


@pytest.mark.parametrize("extra", [("--expected-hash", "a" * 64), ("--request-id", "command-1", "--expected-hash", "bad")])
def test_invalid_hash_option_refused_before_login(tmp_path, monkeypatch, extra):
    path, events = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(commands, "_paired_login", lambda *a: pytest.fail("Do not log in"))
    result = invoke(path, extra=extra)
    assert result.exit_code == 2 and not events


@pytest.mark.parametrize("change", [
    {"requester": "agent:another"}, {"proposed_tool": "fetch_url"},
    {"action_details": {"content": "Print a greeting", "source_type": "direct_prompt", "tool_args": {"command": "another command"}}},
    {"action_hash": "not-a-hash"}, {"request_id": "other-id"},
])
def test_mismatch_never_approves_or_dispatches(tmp_path, monkeypatch, change):
    path, events = setup(tmp_path, monkeypatch, change=change)
    result = invoke(path)
    assert result.exit_code == 2
    assert not any(event.startswith(("/approve", "/reject", "dispatch")) for event in events)


@pytest.mark.parametrize("status", ["consumed", "timed_out", "not_found", "rejected", "approved"])
def test_non_pending_record_never_approved_or_retried(tmp_path, monkeypatch, status):
    path, events = setup(tmp_path, monkeypatch, approval_status=status)
    result = invoke(path)
    assert result.exit_code == 2 and events == ["exchange", "status"]


def test_invalid_approval_reply_never_dispatches(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch, review_status="timed_out")
    result = invoke(path)
    assert result.exit_code == 2 and "/approve/command-1" in events
    assert not any(event.startswith("dispatch") for event in events)
    assert load(path).status == "approval_required"


def test_changed_checkpoint_before_confirmation_never_approves(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    def confirm(*a, **kw):
        state = load(path)
        state.requests[1].tool_args = {"command": "changed"}
        save(path, state)
        return True
    monkeypatch.setattr(commands.typer, "confirm", confirm)
    result = invoke(path)
    assert result.exit_code == 2 and "CHECKPOINT_CHANGED" in result.output
    assert "/approve/command-1" not in events


def test_dispatch_loss_keeps_uncertainty_for_manual_reconciliation(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch, lost_response=True)
    result = invoke(path)
    assert result.exit_code == 2 and events.count("dispatch:command-1") == 1
    assert load(path).status == "uncertain" and load(path).next_index == 1


def test_expired_login_does_not_approve(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    def login(*a): raise LoginError("TOKEN_EXPIRED")
    monkeypatch.setattr(commands, "_paired_login", login)
    result = invoke(path)
    assert result.exit_code == 2 and not events


@pytest.mark.parametrize("status", ["uncertain", "complete", "ready"])
def test_only_approval_checkpoint_can_start_combined_login(tmp_path, monkeypatch, status):
    path, events = setup(tmp_path, monkeypatch, state_status=status)
    monkeypatch.setattr(commands, "_paired_login", lambda *a: pytest.fail("Do not log in"))
    result = invoke(path)
    assert result.exit_code == 2 and not events


def test_gateway_override_and_other_request_rejected_before_login(tmp_path, monkeypatch):
    path, events = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(commands, "_paired_login", lambda *a: pytest.fail("Do not log in"))
    for extra in [("--gateway-url", "http://127.0.0.1:9999"), ("--request-id", "other-id")]:
        result = invoke(path, extra=extra)
        assert result.exit_code == 2 and not events


def test_both_device_challenges_started_before_poll_and_verified_after_both(monkeypatch):
    from types import SimpleNamespace
    events = []
    class Flow:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def begin(self, scopes):
            self.role = "reviewer" if "jev:approvals:write" in scopes else "caller"
            events.append("begin:" + self.role)
            return SimpleNamespace(verification_uri_complete=None, verification_uri="http://localhost/device", user_code="TEST-CODE")
        def poll(self, challenge):
            events.append("poll:" + self.role)
            return SecretStr("private-" + self.role)
        def verify(self, token):
            events.append("verify:" + self.role)
            return SimpleNamespace(subject=self.role, issuer="issuer")
    monkeypatch.setattr(commands, "DeviceLogin", Flow)
    commands._paired_login(None)
    assert events == ["begin:caller", "begin:reviewer", "poll:caller", "poll:reviewer", "verify:caller", "verify:reviewer"]


def test_same_reviewer_and_caller_identity_refused(monkeypatch):
    from types import SimpleNamespace
    class Flow:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def begin(self, scopes):
            return SimpleNamespace(verification_uri_complete=None, verification_uri="http://localhost/device", user_code="TEST-CODE")
        def poll(self, challenge): return SecretStr("private-token")
        def verify(self, token): return SimpleNamespace(subject="same-person", issuer="issuer")
    monkeypatch.setattr(commands, "DeviceLogin", Flow)
    with pytest.raises(LoginError, match="SEPARATE_REVIEWER_REQUIRED"):
        commands._paired_login(None)
