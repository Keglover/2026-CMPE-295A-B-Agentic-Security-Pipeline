"""Real RSA signatures, trusted metadata, scope/role checks, and HTTP enforcement."""

import json
import time
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.auth import middleware
from app.auth.oidc import AuthenticationError, OIDCSettings, TokenVerifier
from app.main import app


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def oidc(signing_key):
    settings = OIDCSettings("required", "keycloak", "http://127.0.0.1:8080/realms/jev", "jev-cli", "jev-gateway")
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key())) | {"kid": "key-1", "alg": "RS256", "use": "sig"}
    calls = []
    metadata = {"issuer": settings.issuer, "jwks_uri": settings.issuer + "/certs"}
    keys = {"keys": [jwk]}
    def handle(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=metadata if str(request.url).endswith("openid-configuration") else keys)
    clock = [0.0]
    verifier = TokenVerifier(settings, transport=httpx.MockTransport(handle), clock=lambda: clock[0])
    def token(**changes):
        now = int(time.time())
        claims = {"iss": settings.issuer, "aud": settings.audience, "azp": settings.client_id,
            "sub": "user-123", "exp": now + 300, "iat": now - 1,
            "scope": "openid jev:evaluate", "realm_access": {"roles": ["jev:evaluate"]}} | changes
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "key-1"})
    return settings, verifier, token, metadata, keys, calls, clock


def test_valid_token_and_cache(oidc):
    _, verifier, token, _, _, calls, _ = oidc
    identity = verifier.verify(token())
    assert identity.subject == "user-123" and identity.permissions == {"jev:evaluate"}
    verifier.verify(token())
    assert len(calls) == 2


@pytest.mark.parametrize("changes", [{"iss": "https://wrong.example"}, {"aud": "other-api"},
    {"azp": "other-client"}, {"sub": ""}, {"sub": 123}, {"exp": 0},
    {"iat": int(time.time()) + 1000}, {"scope": ["jev:evaluate"]},
    {"realm_access": {"roles": "jev:evaluate"}}, {"exp": "9999999999"}])
def test_invalid_claims_deny(oidc, changes):
    with pytest.raises(AuthenticationError):
        oidc[1].verify(oidc[2](**changes))


def test_requested_scope_alone_cannot_grant_approval(oidc):
    identity = oidc[1].verify(oidc[2](scope="openid jev:evaluate jev:approvals:write"))
    assert "jev:approvals:write" not in identity.permissions


def test_role_without_scope_cannot_grant_permission(oidc):
    identity = oidc[1].verify(oidc[2](scope="openid"))
    assert not identity.permissions


def test_algorithm_confusion_rejected_before_network(oidc):
    malicious = jwt.encode({"sub": "attacker"}, "x" * 32, algorithm="HS256", headers={"kid": "key-1"})
    with pytest.raises(AuthenticationError):
        oidc[1].verify(malicious)
    assert not oidc[5]


def test_wrong_signing_key_rejected(oidc):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = jwt.decode(oidc[2](), options={"verify_signature": False})
    malicious = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(AuthenticationError):
        oidc[1].verify(malicious)


def test_missing_subject_has_safe_diagnostic(oidc, signing_key):
    claims = jwt.decode(oidc[2](), options={"verify_signature": False})
    del claims["sub"]
    token = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(AuthenticationError) as error:
        oidc[1].verify(token)
    assert error.value.code == "TOKEN_SUBJECT_MISSING"


@pytest.mark.parametrize("change", ["wrong_issuer", "foreign_jwks", "no_keys", "private_key", "duplicate_key"])
def test_invalid_metadata_denies(oidc, change):
    _, verifier, token, metadata, keys, calls, _ = oidc
    if change == "wrong_issuer":
        metadata["issuer"] = "https://other.example"
    elif change == "foreign_jwks":
        metadata["jwks_uri"] = "http://169.254.169.254/secret"
    elif change == "no_keys":
        keys["keys"] = []
    elif change == "private_key":
        keys["keys"][0]["d"] = "private-value"
    else:
        keys["keys"].append(keys["keys"][0].copy())
    with pytest.raises(AuthenticationError):
        verifier.verify(token())
    assert not any("169.254.169.254" in url for url in calls)


def test_key_rotation_and_unknown_key_throttling(oidc, signing_key):
    _, verifier, token, _, keys, calls, clock = oidc
    verifier.verify(token())
    claims = jwt.decode(token(), options={"verify_signature": False})
    rotated = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "rotated"})
    with pytest.raises(AuthenticationError):
        verifier.verify(rotated)
    assert len(calls) == 2
    keys["keys"][0]["kid"] = "rotated"
    clock[0] = 11
    assert verifier.verify(rotated).subject == "user-123"
    assert len(calls) == 4


def test_identity_outage_fails_closed(oidc):
    def broken(request):
        raise httpx.ConnectError("private upstream exception", request=request)
    verifier = TokenVerifier(oidc[0], transport=httpx.MockTransport(broken))
    with pytest.raises(AuthenticationError) as error:
        verifier.verify(oidc[2]())
    assert error.value.code == "IDENTITY_UNAVAILABLE" and error.value.status == 503
    assert "private" not in str(error.value)


def test_auth0_permissions_scaffold(oidc):
    settings, _, token, metadata, keys, _, _ = oidc
    config = OIDCSettings(settings.mode, "auth0", settings.issuer, settings.client_id, settings.audience)
    def handle(request):
        return httpx.Response(200, json=metadata if str(request.url).endswith("openid-configuration") else keys)
    verifier = TokenVerifier(config, transport=httpx.MockTransport(handle))
    assert verifier.verify(token(permissions=["jev:evaluate"])).permissions == {"jev:evaluate"}
    assert not verifier.verify(token()).permissions


@pytest.fixture
def protected_api(monkeypatch, tmp_path, oidc):
    monkeypatch.setenv("JEV_AUTH_MODE", "required")
    monkeypatch.setenv("LLM_JUDGE_ENABLED", "false")
    monkeypatch.setenv("EVALUATION_AUDIT_LOG_PATH", str(tmp_path / "auth.ndjson"))
    monkeypatch.setattr(middleware, "get_verifier", lambda _: oidc[1])
    return TestClient(app), oidc[2]


@pytest.mark.parametrize("method,path", [("POST", "/evaluate"), ("POST", "/pipeline"),
    ("POST", "/approve/one"), ("POST", "/reject/one"), ("GET", "/pending"),
    ("GET", "/history"), ("GET", "/policy/stats"), ("GET", "/tools")])
def test_missing_token_never_reaches_handler(protected_api, method, path):
    response = protected_api[0].request(method, path, json={"content": "private content"})
    assert response.status_code == 401
    assert response.json()["execution_authorized"] is False
    assert "private content" not in response.text


def test_verified_identity_and_evaluation(protected_api):
    api, token = protected_api
    headers = {"Authorization": "Bearer " + token()}
    identity = api.get("/auth/whoami", headers=headers)
    assert identity.status_code == 200
    assert identity.json()["subject"] == "user-123"
    assert identity.json()["permissions"] == ["jev:evaluate"]
    assert api.post("/evaluate", headers=headers, json={"content": "hello"}).status_code == 200


def test_evaluator_cannot_self_approve(protected_api):
    api, token = protected_api
    response = api.post("/approve/one", headers={"Authorization": "Bearer " + token(
        scope="openid jev:evaluate jev:approvals:write")})
    assert response.status_code == 403
    assert response.json()["reason_code"] == "INSUFFICIENT_PERMISSION"


def test_execution_identity_cannot_be_forged(protected_api, monkeypatch):
    from app import main
    from app.models import GatewayDecision, GatewayResult
    captured = []
    def mediate(request, policy):
        captured.append(request)
        return GatewayResult(request_id=request.request_id, gateway_decision=GatewayDecision.DENIED,
                             decision_reason="test executor disabled")
    monkeypatch.setattr(main.gateway, "mediate", mediate)
    api, token = protected_api
    response = api.post("/pipeline", headers={"Authorization": "Bearer " + token(
        scope="jev:tools:call", realm_access={"roles": ["jev:tools:call"]})},
        json={"content": "Save a note", "agent_id": "forged-user", "approved_domains": ["evil.example"],
              "proposed_tool": "write_note", "tool_args": {"title": "safe", "body": "hello"}})
    assert response.status_code == 200
    assert captured[0].agent_id == "user-123"
    assert captured[0].approved_domains == []


def test_reviewer_identity_cannot_be_forged(protected_api, monkeypatch):
    from types import SimpleNamespace
    from app import main
    approve = Mock(return_value=SimpleNamespace(request_id="one", status=SimpleNamespace(value="APPROVED"),
        resolved_by="user-123", reason="test"))
    monkeypatch.setattr(main.approval_manager, "approve", approve)
    api, token = protected_api
    response = api.post("/approve/one", headers={"Authorization": "Bearer " + token(
        scope="jev:approvals:write", realm_access={"roles": ["jev:approvals:write"]})},
        json={"approved_by": "forged-reviewer", "reason": "test"})
    assert response.status_code == 200
    assert approve.call_args.kwargs["approved_by"] == "user-123"


def test_public_configuration_has_no_secrets(protected_api):
    response = protected_api[0].get("/auth/config")
    assert response.status_code == 200
    assert response.json()["client_id"] == "jev-cli"
    assert "secret" not in response.text and "token" not in response.text


def test_invalid_mode_never_disables_auth(monkeypatch):
    monkeypatch.setenv("JEV_AUTH_MODE", "typo")
    assert TestClient(app).post("/evaluate", json={"content": "hello"}).status_code == 503
