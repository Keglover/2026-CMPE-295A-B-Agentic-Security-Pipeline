import json
from unittest.mock import Mock

import httpx
import pytest
from typer.testing import CliRunner

from promptrail import promptrail
from promptrail.agent.state import load
from promptrail.config import Settings
from promptrail.readiness import ReadinessError, inspect_gateway

runner = CliRunner()
PROFILE = {"mode": "required", "provider": "keycloak", "issuer": "http://127.0.0.1:8080/realms/jev",
           "client_id": "jev-cli", "audience": "jev-gateway", "scopes": ["openid", "jev:evaluate"]}


def test_bare_noninteractive_command_does_not_login_or_call_model(monkeypatch):
    monkeypatch.setattr(promptrail, "_interactive", lambda: False)
    result = runner.invoke(promptrail.app, [])
    assert result.exit_code == 2 and "promptrail run" in result.output


def test_guided_command_selects_tools_and_preserves_authentication(monkeypatch, tmp_path):
    monkeypatch.setattr(promptrail, "_interactive", lambda: True)
    monkeypatch.setenv("JEV_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(promptrail, "inspect_gateway", lambda _: {"executor_mode": "MOCK"})
    start = Mock()
    monkeypatch.setattr(promptrail.agent, "start", start)
    result = runner.invoke(promptrail.app, [], input="Summarize a public sample\nsummarize\n\n")
    assert result.exit_code == 0, result.output
    call = start.call_args.kwargs
    assert call["prompt"] == "Summarize a public sample" and call["tools"] == ["summarize"]
    assert call["login"] is True and call["gateway_url"] == "http://127.0.0.1:8003"
    assert call["checkpoint_path"].parent == tmp_path / "runs"
    assert "MOCK tools simulate" in result.output and "approvals review" in result.output


def test_explicit_prompt_requires_explicit_tool(monkeypatch):
    start = Mock()
    monkeypatch.setattr(promptrail.agent, "start", start)
    result = runner.invoke(promptrail.app, ["run", "Print hello"])
    assert result.exit_code == 2 and not start.called


def test_no_gateway_means_no_model_or_login(monkeypatch):
    def unavailable(_):
        raise ReadinessError("GATEWAY_NOT_READY")
    monkeypatch.setattr(promptrail, "inspect_gateway", unavailable)
    start = Mock()
    monkeypatch.setattr(promptrail.agent, "start", start)
    result = runner.invoke(promptrail.app, ["run", "Hello", "--tool", "summarize"])
    assert result.exit_code == 2 and "GATEWAY_NOT_READY" in result.output and not start.called


@pytest.mark.parametrize("mode", ["SANDBOX", "UNKNOWN"])
def test_builtin_test_refuses_real_or_unreported_execution(monkeypatch, tmp_path, mode):
    monkeypatch.setattr(promptrail, "inspect_gateway", lambda _: {"executor_mode": mode})
    run = Mock()
    monkeypatch.setattr(promptrail.agent, "_run", run)
    checkpoint = tmp_path / "state.json"
    result = runner.invoke(promptrail.app, ["test", "--checkpoint", str(checkpoint)])
    assert result.exit_code == 2 and "MOCK_GATEWAY_REQUIRED" in result.output
    assert not checkpoint.exists() and not run.called


def test_builtin_plan_is_private_and_saved_before_login(monkeypatch, tmp_path):
    monkeypatch.setattr(promptrail, "inspect_gateway", lambda _: {"executor_mode": "MOCK"})
    checkpoint = tmp_path / "state.json"
    def paused(context, path, settings, login):
        assert load(path) == context and path.stat().st_mode & 0o777 == 0o600
        assert login is True and len(context.requests) == 3
        assert context.requests[1].tool_args == {"command": "echo promptrail-approved-demo"}
        raise promptrail.typer.Exit(1)
    monkeypatch.setattr(promptrail.agent, "_run", paused)
    result = runner.invoke(promptrail.app, ["test", "--checkpoint", str(checkpoint)])
    assert result.exit_code == 1 and "No model call" in result.output


def test_readiness_is_bounded_read_only_and_never_transmits_credentials(monkeypatch):
    monkeypatch.setenv("JEV_AUTH_TOKEN", "secret-token")
    calls = []
    def handle(request):
        assert request.method == "GET" and "Authorization" not in request.headers
        calls.append(request.url.path)
        return httpx.Response(200, json={"status": "ok", "executor_mode": "MOCK"} if request.url.path == "/health" else PROFILE)
    report = inspect_gateway(Settings(), transport=httpx.MockTransport(handle))
    assert report["executor_mode"] == "MOCK" and report["execution_authorized"] is False
    assert calls == ["/health", "/auth/config"]


@pytest.mark.parametrize("failure", ["redirect", "oversized", "disabled", "garbage", "down", "mode", "insecure"])
def test_readiness_fails_closed(failure):
    def handle(request):
        if failure == "down":
            raise httpx.ConnectError("secret error body")
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://other.example"})
        if failure == "oversized":
            return httpx.Response(200, content=b"x" * 65537)
        if failure == "garbage":
            return httpx.Response(200, json=[])
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "executor_mode": "bogus" if failure == "mode" else "MOCK"})
        return httpx.Response(200, json=PROFILE | ({"mode": "disabled"} if failure == "disabled" else {}))
    with pytest.raises(ReadinessError) as exc:
        inspect_gateway(Settings(gateway_url="https://gateway.example") if failure == "insecure" else Settings(),
                        transport=httpx.MockTransport(handle))
    assert "secret" not in str(exc.value)


def test_doctor_json_never_claims_production_readiness(monkeypatch):
    monkeypatch.setattr(promptrail, "inspect_gateway", lambda _: {"executor_mode": "MOCK", "execution_authorized": False})
    result = runner.invoke(promptrail.app, ["doctor", "--json"])
    assert result.exit_code == 0 and json.loads(result.stdout)["execution_authorized"] is False
