import httpx
from typer.testing import CliRunner

from promptrail.approvals import commands
from promptrail.main import app

runner = CliRunner()


def setup(monkeypatch, status=200):
    calls = []
    def handle(request):
        calls.append(request.url.path)
        if request.url.path == "/pending":
            return httpx.Response(status, json={"pending": [{"request_id": "exact-1", "action_hash": "a" * 64,
                "action_details": {"tool_args": {"command": "echo hello"}}, "requester": "agent:1"}]})
        return httpx.Response(200, json={"status": "approved" if request.url.path.startswith("/approve") else "rejected"})
    original = httpx.Client
    monkeypatch.setattr(commands.httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(commands, "get_token", lambda *a: "private-reviewer-token")
    return calls


def test_explicit_confirmation_is_required_to_approve(monkeypatch):
    calls = setup(monkeypatch)
    result = runner.invoke(app, ["approvals", "review"], input="y\n")
    assert result.exit_code == 0
    assert "echo hello" in result.output and "a" * 64 in result.output
    assert calls == ["/pending", "/approve/exact-1"]
    assert "private-reviewer-token" not in result.output


def test_default_response_rejects_action(monkeypatch):
    calls = setup(monkeypatch)
    result = runner.invoke(app, ["approvals", "review"], input="\n")
    assert result.exit_code == 0 and calls == ["/pending", "/reject/exact-1"]


def test_reviewer_auth_failure_never_sends_approval(monkeypatch):
    calls = setup(monkeypatch, status=403)
    result = runner.invoke(app, ["approvals", "review"], input="y\n")
    assert result.exit_code == 2 and calls == ["/pending"]
