"""Run with PYTHONPATH=src/mvp to verify the real API/CLI contract together."""

import json
import sys

import httpx
import pytest
from typer.testing import CliRunner

main = pytest.importorskip("app.main")

from fastapi.testclient import TestClient
from app.evaluation.models import EvaluationRequest as ServerRequest
from app.evaluation.models import EvaluationResponse as ServerResponse
from promptrail import main as cli
from promptrail.client import GatewayClient
from promptrail.config import Settings
from promptrail.models import EvaluationRequest, EvaluationResponse


def normalized_schema(model):
    def normalize(value):
        if isinstance(value, dict):
            return {key: sorted(item) if key == "enum" else normalize(item)
                    for key, item in value.items() if key != "description"}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value
    return normalize(model.model_json_schema())


def test_independent_client_and_server_contracts_match():
    assert normalized_schema(EvaluationRequest) == normalized_schema(ServerRequest)
    assert normalized_schema(EvaluationResponse) == normalized_schema(ServerResponse)


@pytest.fixture
def integrated_client(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_JUDGE_ENABLED", "false")
    monkeypatch.setenv("EVALUATION_AUDIT_LOG_PATH", str(tmp_path / "server.ndjson"))
    monkeypatch.setenv("JEV_AUDIT_PATH", str(tmp_path / "client.jsonl"))
    monkeypatch.setattr(cli, "get_token", lambda _: None)
    backend = TestClient(main.app)
    def handle(request):
        response = backend.post("/evaluate", content=request.content,
                                headers={"Content-Type": "application/json"})
        return httpx.Response(response.status_code, content=response.content)
    factory = lambda settings, **kwargs: GatewayClient(settings, **kwargs,
                                                        transport=httpx.MockTransport(handle))
    monkeypatch.setattr(cli, "GatewayClient", factory)
    return CliRunner()


@pytest.mark.parametrize("args,code,requirement", [
    (["eval", "hello", "--json"], 0, "NONE"),
    (["eval", "List files", "--tool", "execute_command", "--args-json", '{"command":"ls -la"}', "--json"],
     1, "REQUIRE_APPROVAL"),
    (["eval", "Fetch page", "--tool", "fetch_url", "--args-json", '{"url":"http://127.0.0.1/secret"}', "--json"],
     1, "DENIED"),
])
def test_cli_against_real_endpoint(integrated_client, args, code, requirement):
    result = integrated_client.invoke(cli.app, args)
    assert result.exit_code == code, result.output
    parsed = EvaluationResponse.model_validate_json(result.stdout)
    assert parsed.execution_requirement.value == requirement
    assert parsed.execution_authorized is False


def test_live_installed_cli_smoke(tmp_path):
    """Real HTTP and installed console script, with mock tools and no external models."""
    import os
    import socket
    import subprocess
    import time
    from pathlib import Path

    env = os.environ | {"REAL_TOOLS": "false", "LLM_JUDGE_ENABLED": "false",
        "EVALUATION_AUDIT_LOG_PATH": str(tmp_path / "server.ndjson"),
        "JEV_AUDIT_PATH": str(tmp_path / "client.jsonl"), "JEV_AUTH_TOKEN": "local-smoke-token"}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        with (tmp_path / "server.log").open("w") as log:
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                "--fd", str(listener.fileno()), "--log-level", "warning"],
                env=env, pass_fds=(listener.fileno(),), stdout=log, stderr=log)
            try:
                with httpx.Client(timeout=1, trust_env=False) as http:
                    for _ in range(100):
                        if process.poll() is not None:
                            pytest.fail("API exited before startup: " + (tmp_path / "server.log").read_text())
                        try:
                            if http.get(url + "/health").status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        time.sleep(0.05)
                    else:
                        pytest.fail("API did not become ready")
                    command = subprocess.run([str(Path(sys.executable).parent / "jev"), "eval", "List files",
                        "--gateway-url", url, "--tool", "execute_command", "--args-json", '{"command":"ls -la"}',
                        "--json"], env=env, capture_output=True, text=True, timeout=15)
                    assert command.returncode == 1, command.stderr
                    result = json.loads(command.stdout)
                    assert result["execution_requirement"] == "REQUIRE_APPROVAL"
                    assert result["execution_authorized"] is False
                    assert http.get(url + "/pending").json()["count"] == 0
                    history = subprocess.run([str(Path(sys.executable).parent / "jev"), "audit", "--json"],
                        env=env, capture_output=True, text=True, timeout=5)
                    assert history.returncode == 0
                    assert len(json.loads(history.stdout)["entries"]) == 1
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
