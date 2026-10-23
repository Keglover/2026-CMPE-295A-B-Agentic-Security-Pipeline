"""Installed CLI over real HTTP; both gateway and model providers are local fakes."""
import json
import os
import subprocess
import sys
import threading
import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from promptrail.agent.models import ToolCallRequest
from promptrail.agent.state import load
from promptrail.client import unavailable
from promptrail.models import EvaluationRequest, ExecutionRequirement, PolicyAction


@pytest.mark.parametrize("entry_name", ["jev", "promptrail"])
def test_installed_cli_model_failover_review_pause_and_resume(tmp_path, entry_name):
    executed, provider_paths, approved = [], [], [False]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            response = ({"status": "ok", "executor_mode": "MOCK"} if self.path == "/health" else
                        {"mode": "required", "provider": "keycloak", "issuer": f"http://127.0.0.1:{self.server.server_port}/realms/jev",
                         "client_id": "jev-cli", "audience": "jev-gateway", "scopes": ["openid", "jev:evaluate"]})
            data = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            status = 200
            if self.path == "/auth/agent-token":
                assert self.headers["Authorization"] == "Bearer private-user-token"
                response = {"access_token": "private-agent-token", "token_type": "Bearer", "expires_in": 300,
                    "agent_id": "agent:stable", "tools": body["tools"], "permissions": ["jev:evaluate", "jev:tools:call"]}
            elif self.path in {"/evaluate", "/tools/call"}:
                assert self.headers["Authorization"] == "Bearer private-agent-token"
                request = (ToolCallRequest if self.path == "/tools/call" else EvaluationRequest).model_validate(body)
                evaluation = unavailable(request, "POLICY_ALLOW").model_copy(update={"status": "evaluated",
                    "risk_score": 0, "policy_action": PolicyAction.ALLOW, "execution_requirement": ExecutionRequirement.NONE})
                response = evaluation.model_dump(mode="json")
                if self.path == "/tools/call":
                    pending = request.proposed_tool == "execute_command" and not approved[0]
                    if not pending: executed.append(request.request_id)
                    response = {"schema_version": "1", "evaluation": response,
                        "outcome": "REQUIRE_APPROVAL" if pending else "EXECUTED",
                        "reason_code": "APPROVAL_REQUIRED" if pending else "EXECUTED",
                        "executor_mode": "MOCK", "tool_output": None if pending else "Safe mock output"}
            elif self.path == "/ollama/api/chat":
                assert self.headers["Authorization"] == "Bearer private-ollama-key"
                assert body["model"] == "deepseek-v4.1-flash" and body["stream"] is False
                assert "options" in body and "max_completion_tokens" not in body
                provider_paths.append(self.path)
                status, response = 503, {"error": "unavailable"}
            elif self.path == "/openai/v1/chat/completions":
                assert self.headers["Authorization"] == "Bearer private-openai-key"
                assert body["model"] == "fake-fallback" and body["max_completion_tokens"] == 2048
                provider_paths.append(self.path)
                if provider_paths.count(self.path) == 1:
                    calls = [{"id": "call-summary", "type": "function", "function": {"name": "summarize", "arguments": '{"text":"Hello"}'}},
                        {"id": "call-command", "type": "function", "function": {"name": "execute_command", "arguments": '{"command":"echo hello"}'}},
                        {"id": "call-summary-2", "type": "function", "function": {"name": "summarize", "arguments": '{"text":"Other report"}'}}]
                    message, finish = {"role": "assistant", "tool_calls": calls}, "tool_calls"
                else:
                    assert [m["tool_call_id"] for m in body["messages"] if m["role"] == "tool"] == ["call-summary", "call-command", "call-summary-2"]
                    message, finish = {"role": "assistant", "content": "All done"}, "stop"
                response = {"choices": [{"finish_reason": finish, "message": message}]}
            else:
                status, response = 404, {}
            data = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        env_file, checkpoint = tmp_path / ".env.models", tmp_path / "conversation.json"
        env_file.write_text(f"JEV_MODEL_PROTOCOL=ollama\nJEV_MODEL_URL={base}/ollama\nJEV_MODEL_NAME=deepseek-v4.1-flash\n"
            f"OLLAMA_API_KEY=private-ollama-key\nJEV_FALLBACK_MODEL_URL={base}/openai/v1\n"
            "JEV_FALLBACK_MODEL_NAME=fake-fallback\nOPENAI_API_KEY=private-openai-key\n")
        env_file.chmod(0o600)
        env = os.environ.copy()
        for name in ["OLLAMA_API_KEY", "OPENAI_API_KEY", "JEV_MODEL_URL", "JEV_MODEL_NAME", "JEV_MODEL_PROTOCOL",
                     "JEV_FALLBACK_MODEL_URL", "JEV_FALLBACK_MODEL_NAME"]:
            env.pop(name, None)
        env.update(JEV_AUTH_TOKEN="private-user-token", JEV_AUDIT_PATH=str(tmp_path / "audit.jsonl"))
        entrypoint = os.path.join(os.path.dirname(sys.executable), entry_name)
        start_args = (["run", "Summarize a report and print a greeting", "--stored-login"] if entry_name == "promptrail" else
                      ["agent", "start", "--prompt", "Summarize a report and print a greeting"])
        result = subprocess.run([entrypoint, *start_args,
            "--tool", "summarize", "--tool", "execute_command", "--checkpoint", str(checkpoint),
            "--gateway-url", base, "--model-env-file", str(env_file)], cwd=tmp_path, env=env,
            capture_output=True, text=True, timeout=20)
        assert result.returncode == 1, result.stdout + result.stderr
        paused = load(checkpoint)
        assert paused.status == "approval_required" and paused.next_index == 1 and len(executed) == 1
        held_id = paused.requests[1].request_id
        approved[0] = True  # Fake reviewer decision; actual Keycloak review has separate live verification.
        resumed = subprocess.run([entrypoint, "agent", "resume", str(checkpoint)], cwd=tmp_path, env=env,
                                 capture_output=True, text=True, timeout=20)
        assert resumed.returncode == 0, resumed.stdout + resumed.stderr
        complete = load(checkpoint)
        assert complete.status == "complete" and complete.next_index == 3
        assert executed == [r.request_id for r in complete.requests] and executed[1] == held_id
        assert len(set(executed)) == 3 and complete.last_model_endpoint == "fallback"
        assert provider_paths == ["/ollama/api/chat", "/openai/v1/chat/completions"] * 2
        output = result.stdout + result.stderr + resumed.stdout + resumed.stderr + checkpoint.read_text() + (tmp_path / "audit.jsonl").read_text()
        assert all(secret not in output for secret in ["private-user-token", "private-agent-token", "private-ollama-key", "private-openai-key"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
