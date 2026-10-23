"""Real signatures, exact payload binding, durable replay prevention and runner gate."""
from concurrent.futures import ThreadPoolExecutor
import time
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.auth.capabilities import authorize_runner, issue_runner, sign, RUNNER_AUDIENCE
from app.auth.oidc import AuthenticationError
from app.models import PipelineRequest, PolicyResult, PolicyAction


@pytest.fixture
def keys(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("JEV_GATEWAY_SIGNING_KEY", str(private))
    monkeypatch.setenv("JEV_GATEWAY_VERIFY_KEY", str(public))
    monkeypatch.setenv("JEV_RUNNER_VERIFY_KEY", str(public))
    monkeypatch.setenv("JEV_RUNNER_NONCE_DB", str(tmp_path / "nonces.sqlite3"))
    return key


def capability():
    req = PipelineRequest(request_id="dispatch-1", content="Save a note", agent_id="alice",
                          proposed_tool="write_note", tool_args={"title": "safe", "body": "hello"})
    policy = PolicyResult(request_id=req.request_id, policy_action=PolicyAction.ALLOW, policy_reason="Safe")
    return issue_runner(req, policy, "trace-1"), req


def test_capability_verified_and_consumed_once(keys):
    token, req = capability()
    assert authorize_runner(token, req.proposed_tool, req.tool_args)["sub"] == "alice"
    with pytest.raises(AuthenticationError, match="CAPABILITY_REPLAY"):
        authorize_runner(token, req.proposed_tool, req.tool_args)


def test_concurrent_nonce_consumption(keys):
    token, req = capability()
    def consume(_):
        try:
            authorize_runner(token, req.proposed_tool, req.tool_args)
            return True
        except AuthenticationError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(8))) == 1


@pytest.mark.parametrize("kind", ["tool", "args", "audience", "expired", "registry", "signature", "algorithm"])
def test_invalid_capabilities_cannot_dispatch(keys, kind):
    token, req = capability()
    tool, args = req.proposed_tool, req.tool_args
    claims = jwt.decode(token, options={"verify_signature": False})
    if kind == "tool":
        tool = "search_notes"
    elif kind == "args":
        args = args | {"body": "changed"}
    else:
        if kind == "audience": claims["aud"] = "jev-agent"
        elif kind == "expired": claims["exp"] = int(time.time()) - 1
        elif kind == "registry": claims["registry_version"] = "old"
        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048) if kind == "signature" else keys
        token = jwt.encode(claims, "x" * 32 if kind == "algorithm" else signer,
                           algorithm="HS256" if kind == "algorithm" else "RS256")
    with pytest.raises(AuthenticationError):
        authorize_runner(token, tool, args)


def test_runner_direct_call_does_not_touch_docker(keys, monkeypatch):
    from app.sandbox import service
    docker = Mock()
    monkeypatch.setattr(service, "_docker_client", docker)
    api = TestClient(service.app)
    args = {"tool_args": {"title": "safe", "body": "hello"}}
    assert api.post("/execute/write_note", json=args).status_code == 401
    assert api.post("/execute/write_note", json=args, headers={"Authorization": "Bearer forged"}).status_code == 401
    docker.containers.run.assert_not_called()


def test_missing_nonce_store_fails_closed(keys, monkeypatch):
    monkeypatch.delenv("JEV_RUNNER_NONCE_DB")
    token, req = capability()
    with pytest.raises(AuthenticationError, match="NONCE_STORE_UNAVAILABLE"):
        authorize_runner(token, req.proposed_tool, req.tool_args)


def test_real_gateway_dispatch_attaches_exact_runner_capability(keys, monkeypatch):
    import json
    import httpx
    from app.gateway import gateway
    captured = []
    original_client = httpx.Client
    def handle(request):
        args = json.loads(request.content)["tool_args"]
        token = request.headers["Authorization"].removeprefix("Bearer ")
        captured.append(authorize_runner(token, "write_note", args))
        return httpx.Response(200, json={"result": "Authorized runner result"})
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(gateway, "_USE_REAL_TOOLS", True)
    monkeypatch.setattr(gateway.rate_limiter, "check", lambda *a, **k: True)
    monkeypatch.setattr(gateway.circuit_registry.get("write_note"), "allow_request", lambda: True)
    req = PipelineRequest(content="Save a note", proposed_tool="write_note",
                          tool_args={"title": "safe", "body": "hello"}, agent_id="alice")
    policy = PolicyResult(request_id=req.request_id, policy_action=PolicyAction.ALLOW, policy_reason="Safe")
    result = gateway.mediate(req, policy)
    assert result.gateway_decision.value == "EXECUTED"
    assert result.tool_output == "Authorized runner result"
    assert captured[0]["request_id"] == req.request_id and captured[0]["sub"] == "alice"
