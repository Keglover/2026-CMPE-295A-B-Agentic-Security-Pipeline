"""Real RSA signatures, trusted metadata, scope/role checks, and HTTP enforcement."""

import json
import time
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from auth.oidc import AuthenticationError, OIDCSettings, TokenVerifier
from auth import gateway


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def oidc(signing_key):
    settings = OIDCSettings("required", "keycloak", "http://127.0.0.1:8080/realms/promptrail", "promptrail-cli", "promptrail-gateway")
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
            "scope": "openid promptrail:access", "realm_access": {"roles": ["promptrail:access"]}} | changes
        return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "key-1"})
    return settings, verifier, token, metadata, keys, calls, clock


def test_valid_token_and_cache(oidc):
    _, verifier, token, _, _, calls, _ = oidc
    identity = verifier.verify(token())
    assert identity.subject == "user-123" and identity.permissions == {"promptrail:access"}
    verifier.verify(token())
    assert len(calls) == 2


@pytest.mark.parametrize("changes", [{"iss": "https://wrong.example"}, {"aud": "other-api"},
    {"azp": "other-client"}, {"sub": ""}, {"sub": 123}, {"exp": 0},
    {"iat": int(time.time()) + 1000}, {"scope": ["promptrail:access"]},
    {"realm_access": {"roles": "promptrail:access"}}, {"exp": "9999999999"}])
def test_invalid_claims_deny(oidc, changes):
    with pytest.raises(AuthenticationError):
        oidc[1].verify(oidc[2](**changes))


def test_requested_scope_alone_cannot_grant_approval(oidc):
    identity = oidc[1].verify(oidc[2](scope="openid promptrail:access promptrail:review"))
    assert "promptrail:review" not in identity.permissions


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


@pytest.fixture
def protected_api(monkeypatch, oidc):
    monkeypatch.setattr(gateway, "get_verifier", lambda _: oidc[1])
    monkeypatch.setattr(gateway, "load_settings", lambda: oidc[0])
    with TestClient(gateway.app) as client:
        yield client, oidc[2]


def test_anonymous_request_is_rejected(protected_api):
    response = protected_api[0].get("/auth/whoami")
    assert response.status_code == 401
    assert response.json() == {"reason_code": "AUTHENTICATION_REQUIRED"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"


def test_valid_identity_and_basic_access(protected_api):
    client, token = protected_api
    response = client.get("/auth/whoami", headers={"Authorization": "Bearer " + token()})
    assert response.status_code == 200
    assert response.json()["subject"] == "user-123"
    assert response.json()["permissions"] == ["promptrail:access"]
    assert "Bearer" not in response.text


def test_valid_signature_without_assigned_access_is_denied(protected_api):
    client, token = protected_api
    response = client.get("/auth/whoami", headers={"Authorization": "Bearer " + token(realm_access={"roles": []})})
    assert response.status_code == 403
    assert response.json()["reason_code"] == "INSUFFICIENT_PERMISSION"


@pytest.mark.parametrize("value", ["Basic private", "Bearer private\tvalue", "Bearer " + "x"*16385])
def test_bad_authorization_never_echoes_credentials(protected_api, value):
    response = protected_api[0].get("/auth/whoami", headers={"Authorization": value})
    assert response.status_code == 401 and "private" not in response.text


@pytest.mark.parametrize("path", ["/evaluate", "/pipeline", "/tools/call", "/approve/one", "/auth/agent-token"])
def test_execution_and_policy_endpoints_do_not_exist(protected_api, path):
    assert protected_api[0].post(path, json={}).status_code == 404


def test_public_configuration_is_auth_only(protected_api, monkeypatch):
    client, _ = protected_api
    assert client.get("/health").json()["capabilities"] == ["authentication"]
    assert client.get("/auth/config").json()["scopes"] == ["openid", "promptrail:access"]
    assert client.get("/auth/registration").json() == {"signup_enabled": False}
    monkeypatch.setenv("PROMPTRAIL_SELF_REGISTRATION_ENABLED", "true")
    assert client.get("/auth/registration").json() == {"signup_enabled": True}


def test_disabled_authentication_is_never_allowed():
    with pytest.raises(ValueError):
        OIDCSettings("disabled", "keycloak", "http://127.0.0.1:8080/realms/promptrail", "promptrail-cli", "promptrail-gateway")
