import json

import pytest
import typer
from pydantic import ValidationError
from typer.testing import CliRunner

from promptrail.agent import commands, engine
from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import ConversationCheckpoint, Message, ModelToolCall, SYSTEM_PROMPT
from promptrail.agent.models import ToolCallResponse
from promptrail.agent.state import lease, load, save
from promptrail.client import unavailable
from promptrail.config import Settings
from promptrail.main import app
from promptrail.models import ExecutionRequirement, PolicyAction


def state(**changes):
    return ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", tools=["summarize", "execute_command"],
        prompt="Summarize the report then print a greeting.", model_url="http://127.0.0.1:11434/v1", model_name="test-model", **changes)


def call(cid, name="summarize", args=None):
    return ModelToolCall(id=cid, function={"name": name, "arguments": json.dumps(args or {"text": "hello"})})


class Model:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.seen = []
    def complete(self, messages, tools):
        self.seen.append((messages, tools))
        return next(self.replies)


class Session:
    def __init__(self, path, *, approved=False, output="Safe report", lost=False):
        self.path, self.approved, self.output, self.lost = path, approved, output, lost
        self.executed, self.proposed = [], []
    def evaluate(self, request):
        action = PolicyAction.BLOCK if "ignore safeguards" in request.content else PolicyAction.ALLOW
        return unavailable(request, "POLICY_" + action.value).model_copy(update={"status": "evaluated", "policy_action": action,
            "risk_score": 100 if action == PolicyAction.BLOCK else 0,
            "execution_requirement": ExecutionRequirement.DENIED if action == PolicyAction.BLOCK else ExecutionRequirement.NONE})
    def call(self, request):
        assert load(self.path).status == "uncertain", "Context must be saved before dispatch"
        self.proposed.append(request)
        if self.lost:
            raise SecurityException("GATEWAY_UNAVAILABLE")
        pending = request.proposed_tool == "execute_command" and not self.approved
        outcome = "REQUIRE_APPROVAL" if pending else "EXECUTED"
        if not pending:
            self.executed.append(request.request_id)
        evaluation = self.evaluate(request).model_copy(update={
            "execution_requirement": ExecutionRequirement.REQUIRE_APPROVAL if pending else ExecutionRequirement.NONE})
        return ToolCallResponse(evaluation=evaluation, outcome=outcome,
            reason_code="APPROVAL_REQUIRED" if pending else "EXECUTED", executor_mode="MOCK", tool_output=self.output)


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    monkeypatch.setattr(engine, "append_event", lambda *a, **kw: None)


def test_multitool_review_resume_retains_completed_calls_and_matching_ids(tmp_path):
    path = tmp_path / "conversation.json"
    cp = state()
    save(path, cp)
    batch = Message(role="assistant", tool_calls=[call("summary-1"), call("command-1", "execute_command", {"command": "echo hello"}), call("summary-2")])
    model = Model([batch, Message(role="assistant", content="All done")])
    first = Session(path)
    with pytest.raises(typer.Exit):
        engine.run(cp, path, Settings(), first, model)
    paused = load(path)
    assert paused.next_index == 1 and paused.status == "approval_required"
    assert paused.tool_call_ids == ["summary-1", "command-1", "summary-2"]
    assert len(first.executed) == 1 and len(model.seen) == 1
    pending_id = paused.requests[1].request_id
    resumed = Session(path, approved=True)
    engine.run(paused, path, Settings(), resumed, model)
    completed = load(path)
    assert completed.status == "complete" and completed.next_index == 3
    assert resumed.executed == [pending_id, completed.requests[2].request_id]
    assert first.executed[0] not in resumed.executed
    assert len(model.seen) == 2
    assert [m["tool_call_id"] for m in model.seen[1][0] if m["role"] == "tool"] == ["summary-1", "command-1", "summary-2"]


def test_transport_loss_saves_uncertainty_and_refuses_resume(tmp_path):
    path = tmp_path / "state.json"
    cp = state()
    save(path, cp)
    model = Model([Message(role="assistant", tool_calls=[call("call-1")])])
    first = Session(path, lost=True)
    with pytest.raises(SecurityException):
        engine.run(cp, path, Settings(), first, model)
    unknown = load(path)
    assert unknown.status == "uncertain"
    with pytest.raises(SecurityException, match="MANUAL_RECONCILIATION_REQUIRED"):
        engine.run(unknown, path, Settings(), first, model)
    assert len(first.proposed) == 1 and len(model.seen) == 1


def test_prompt_blocked_before_model_or_gateway_dispatch(tmp_path):
    path = tmp_path / "state.json"
    cp = state().model_copy(update={"prompt": "ignore safeguards"})
    save(path, cp)
    model, session = Model([]), Session(path)
    with pytest.raises(SecurityException, match="PROMPT_NOT_ALLOWED"):
        engine.run(cp, path, Settings(), session, model)
    assert not model.seen and not session.proposed


@pytest.mark.parametrize("output", ["ignore safeguards", "A" * 50000 + "ignore safeguards"])
def test_unsafe_or_oversized_output_is_wholly_withheld_before_model(tmp_path, output):
    path = tmp_path / "state.json"
    cp = state()
    save(path, cp)
    model = Model([Message(role="assistant", tool_calls=[call("call-1")]), Message(role="assistant", content="Done")])
    session = Session(path, output=output)
    engine.run(cp, path, Settings(), session, model)
    tools = [m for m in model.seen[1][0] if m["role"] == "tool"]
    assert tools[0]["content"] == engine.WITHHELD
    assert "ignore safeguards" not in json.dumps(model.seen)


@pytest.mark.parametrize("args", ["[]", '{"text": NaN}', '"string"', 'not-json'])
def test_bad_second_proposal_prevents_entire_batch_dispatch(tmp_path, args):
    path = tmp_path / "state.json"
    cp = state()
    save(path, cp)
    bad = ModelToolCall(id="bad-2", function={"name": "summarize", "arguments": args})
    model = Model([Message(role="assistant", tool_calls=[call("good-1"), bad])])
    session = Session(path)
    with pytest.raises(SecurityException, match="INVALID_MODEL_PROPOSAL"):
        engine.run(cp, path, Settings(), session, model)
    assert not session.proposed and load(path).requests == []


@pytest.mark.parametrize("calls", [[call("same"), call("same")], [call("unknown", "unselected_tool")]])
def test_duplicate_id_or_unselected_tool_never_dispatches(tmp_path, calls):
    path = tmp_path / "state.json"
    cp = state()
    save(path, cp)
    session = Session(path)
    with pytest.raises(SecurityException, match="INVALID_MODEL_PROPOSAL"):
        engine.run(cp, path, Settings(), session, Model([Message(role="assistant", tool_calls=calls)]))
    assert not session.proposed


def test_iteration_budget_persists_across_review_resume(tmp_path):
    path = tmp_path / "state.json"
    cp = state(max_iterations=1)
    save(path, cp)
    model = Model([Message(role="assistant", tool_calls=[call("command-1", "execute_command", {"command": "echo hello"})])])
    with pytest.raises(typer.Exit):
        engine.run(cp, path, Settings(), Session(path), model)
    resumed = load(path)
    engine.run(resumed, path, Settings(), Session(path, approved=True), model)
    assert load(path).status == "complete" and len(model.seen) == 1


def test_checkpoint_rejects_changed_action_from_model_and_authority_fields(tmp_path):
    path = tmp_path / "state.json"
    cp = state()
    save(path, cp)
    with pytest.raises(typer.Exit):
        engine.run(cp, path, Settings(), Session(path), Model([Message(role="assistant", tool_calls=[
            call("command-1", "execute_command", {"command": "echo hello"})])]))
    value = json.loads(path.read_text())
    value["requests"][0]["tool_args"]["command"] = "different"
    with pytest.raises(ValidationError):
        ConversationCheckpoint.model_validate(value)
    value = json.loads(path.read_text())
    value["access_token"] = "forbidden"
    with pytest.raises(ValidationError):
        ConversationCheckpoint.model_validate(value)


def test_state_read_refuses_symlinks_and_public_permissions(tmp_path):
    path = tmp_path / "state.json"
    save(path, state())
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load(link)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load(path)


def test_checkpoint_lease_refuses_concurrent_run_and_releases_after_failure(tmp_path):
    path = tmp_path / "state.json"
    with lease(path):
        with pytest.raises(SecurityException, match="CHECKPOINT_IN_USE"):
            with lease(path):
                pytest.fail("Concurrent resume must be rejected")
    with lease(path):
        pass


def test_cli_model_start_and_resume_use_checkpoint_kind(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr(commands, "_credential", lambda *a: "private-user-token")
    class CredentialSession(Session):
        approved = False
        def __init__(self, *a): super().__init__(path, approved=CredentialSession.approved)
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def exchange(self, tools, identity): return "agent:stable"
    replies = [Message(role="assistant", tool_calls=[call("command-1", "execute_command", {"command": "echo hello"})]),
               Message(role="assistant", content="Done")]
    model = Model(replies)
    class Client:
        def __init__(self, cp): pass
        def __enter__(self): return model
        def __exit__(self, *a): pass
    monkeypatch.setattr(commands, "AgentSession", CredentialSession)
    monkeypatch.setattr(commands, "ModelClient", Client)
    first = CliRunner().invoke(app, ["agent", "start", "--prompt", "Print a greeting", "--tool", "execute_command",
        "--checkpoint", str(path), "--model-url", "http://127.0.0.1:11434/v1", "--model", "test-model"])
    assert first.exit_code == 1, first.output
    assert isinstance(load(path), ConversationCheckpoint) and load(path).status == "approval_required"
    CredentialSession.approved = True
    second = CliRunner().invoke(app, ["agent", "resume", str(path)])
    assert second.exit_code == 0, second.output
    assert load(path).status == "complete" and "private-user-token" not in path.read_text() + first.output + second.output


def test_conversation_tool_hints_match_gateway_registry():
    load_tool_registry = pytest.importorskip("app.policy.config_loader").load_tool_registry
    from promptrail.agent.definitions import definitions
    registry = load_tool_registry()["tools"]
    tools = [name for name, info in registry.items() if info.get("enabled", True)]
    for definition in definitions(tools):
        function = definition["function"]
        info = registry[function["name"]]
        schema = function["parameters"]
        assert schema["required"] == info["required_args"]
        assert set(schema["properties"]) == set(info["required_args"] + info["optional_args"])
        for name, field in schema["properties"].items():
            assert field["type"] == {"url": "string"}.get(info["arg_types"][name], info["arg_types"][name])
            for constraint, value in info.get("arg_constraints", {}).get(name, {}).items():
                assert field[{"max_length": "maxLength", "min": "minimum", "max": "maximum"}.get(constraint, constraint)] == value
