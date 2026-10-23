import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from promptrail import main
from promptrail.audit import append_event, read_events
from promptrail.models import EvaluationResponse, ExecutionRequirement, PolicyAction

runner = CliRunner()


def response(action="ALLOW", requirement="NONE", status="evaluated", **changes):
    return EvaluationResponse(schema_version="1", request_id="request-1", trace_id="trace-1",
        status=status, policy_action=PolicyAction(action), risk_score=None if status != "evaluated" else 0,
        execution_requirement=ExecutionRequirement(requirement), execution_authorized=False,
        reason_code="TEST_RESULT", reason="private reason must not be logged",
        content_hash="a" * 64, policy_version="1", registry_version="2", **changes)


@pytest.fixture
def fake_client(monkeypatch, tmp_path):
    monkeypatch.setenv("JEV_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(main, "get_token", lambda _: None)
    state = {"result": response(), "requests": []}
    class Client:
        def __init__(self, settings, **kwargs):
            state["settings"] = settings
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def evaluate(self, request):
            state["requests"].append(request)
            return state["result"]
    monkeypatch.setattr(main, "GatewayClient", Client)
    return state


def test_help():
    result = runner.invoke(main.app, ["--help"])
    assert result.exit_code == 0
    assert "eval" in result.stdout and "audit" in result.stdout


@pytest.mark.parametrize("action,requirement,status,expected", [
    ("ALLOW", "NONE", "evaluated", 0), ("SANITIZE", "NONE", "evaluated", 0),
    ("ALLOW", "REQUIRE_APPROVAL", "evaluated", 1),
    ("REQUIRE_APPROVAL", "REQUIRE_APPROVAL", "evaluated", 1),
    ("QUARANTINE", "DENIED", "evaluated", 1), ("BLOCK", "DENIED", "evaluated", 1),
    ("BLOCK", "DENIED", "rejected", 1), ("BLOCK", "DENIED", "unavailable", 2),
])
def test_policy_exit_codes(fake_client, action, requirement, status, expected):
    fake_client["result"] = response(action, requirement, status)
    result = runner.invoke(main.app, ["eval", "hello", "--json"])
    assert result.exit_code == expected, result.output
    assert json.loads(result.stdout)["execution_authorized"] is False


def test_human_review_message(fake_client):
    fake_client["result"] = response("ALLOW", "REQUIRE_APPROVAL")
    result = runner.invoke(main.app, ["eval", "hello"])
    assert result.exit_code == 1
    assert "Human review is required" in result.stdout
    assert "has not queued" in result.stdout


@pytest.mark.parametrize("args", [["eval"], ["eval", "hello", "--stdin"],
    ["eval", "hello", "--args-json", "[]"],
    ["eval", "hello", "--tool", "execute_command", "--args-json", '{"timeout_sec":NaN}'],
    ["eval", "hello", "--args-json", '{"command":"ls"}'],
    ["eval", "hello", "--gateway-url", "http://remote.example.com"]])
def test_invalid_input_never_calls_gateway(fake_client, args):
    result = runner.invoke(main.app, args + ["--json"])
    assert result.exit_code == 2
    assert not fake_client["requests"]
    assert json.loads(result.stdout)["execution_authorized"] is False


def test_stdin_and_optional_directory(fake_client):
    result = runner.invoke(main.app, ["eval", "--stdin", "--include-cwd", "--json"], input="private content")
    assert result.exit_code == 0
    request = fake_client["requests"][0]
    assert request.content == "private content"
    assert request.context.working_directory == os.getcwd()


def test_directory_not_sent_by_default(fake_client):
    assert runner.invoke(main.app, ["eval", "hello"]).exit_code == 0
    assert fake_client["requests"][0].context.working_directory is None


def test_local_audit_roundtrip_and_permissions(fake_client):
    assert runner.invoke(main.app, ["eval", "private content", "--json"]).exit_code == 0
    path = fake_client["settings"].audit_path
    assert "private" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    result = runner.invoke(main.app, ["audit", "--json"])
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)["entries"]) == 1


def test_missing_audit_file(fake_client):
    result = runner.invoke(main.app, ["audit"])
    assert result.exit_code == 0 and "No audit logs found" in result.stdout


def test_audit_failure_is_visible(fake_client, monkeypatch):
    monkeypatch.setattr(main, "append_event", Mock(side_effect=OSError("secret path")))
    result = runner.invoke(main.app, ["eval", "hello", "--json"])
    assert result.exit_code == 2
    assert "Local audit unavailable" in result.output
    assert "secret path" not in result.output


def test_audit_corruption_and_bounded_history(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_event(path, response())
    with path.open("a") as stream:
        stream.write("not JSON\n" + "x" * 9000 + "\n")
    append_event(path, response("BLOCK", "DENIED"))
    events, skipped = read_events(path, limit=1)
    assert len(events) == 1 and events[0].policy_action == "BLOCK"
    assert skipped == 2


def test_audit_will_not_follow_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("original")
    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)
    with pytest.raises(OSError):
        append_event(path, response())
    assert target.read_text() == "original"
