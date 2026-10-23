import json

import httpx
import pytest
from typer.testing import CliRunner

from promptrail.config import Settings
from promptrail.main import app
from promptrail.readiness import ReadinessError, inspect_gateway

runner = CliRunner()
PROFILE = {"mode": "required", "provider": "keycloak", "issuer": "http://127.0.0.1:8080/realms/promptrail",
           "client_id": "promptrail-cli", "audience": "promptrail-gateway", "scopes": ["openid", "promptrail:access"]}


def test_version_is_available_without_a_subcommand():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and "0.1.0rc3" in result.stdout


def test_entry_point_exposes_only_authentication():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0 and "auth" in result.stdout and "doctor" in result.stdout
    for command in ["eval", "run", "agent", "test", "approvals", "audit"]:
        assert runner.invoke(app, [command]).exit_code == 2


def test_readiness_is_read_only_and_sends_no_credentials(monkeypatch):
    monkeypatch.setenv("PROMPTRAIL_AUTH_TOKEN", "private-token")
    calls = []
    def handle(request):
        assert request.method == "GET" and "Authorization" not in request.headers
        calls.append(request.url.path)
        return httpx.Response(200, json={"status": "ok", "service": "promptrail-auth"}
                              if request.url.path == "/health" else PROFILE)
    report = inspect_gateway(Settings(), transport=httpx.MockTransport(handle))
    assert report["capabilities"] == ["authentication"]
    assert calls == ["/health", "/auth/config"]


@pytest.mark.parametrize("failure", ["redirect", "oversized", "disabled", "garbage", "down", "service", "insecure"])
def test_readiness_fails_closed(failure):
    def handle(request):
        if failure == "down":
            raise httpx.ConnectError("private upstream details")
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://other.example"})
        if failure == "oversized":
            return httpx.Response(200, content=b"x" * 65537)
        if failure == "garbage":
            return httpx.Response(200, json=[])
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "service": "old-service" if failure == "service" else "promptrail-auth"})
        return httpx.Response(200, json=PROFILE | ({"mode": "disabled"} if failure == "disabled" else {}))
    with pytest.raises(ReadinessError) as error:
        inspect_gateway(Settings(gateway_url="https://gateway.example") if failure == "insecure" else Settings(),
                        transport=httpx.MockTransport(handle))
    assert "private" not in str(error.value)
