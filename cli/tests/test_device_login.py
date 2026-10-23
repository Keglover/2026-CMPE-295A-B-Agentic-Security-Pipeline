import time
from urllib.parse import parse_qs

import httpx
import pytest

from promptrail.auth.device import DeviceLogin, LoginError
from promptrail.auth.providers import LoginProfile, provider_for
from promptrail.config import Settings


@pytest.fixture
def device_server():
    issuer = "http://127.0.0.1:8080/realms/promptrail"
    state = {"profile": {"mode": "required", "provider": "keycloak", "issuer": issuer,
        "client_id": "promptrail-cli", "audience": "promptrail-gateway", "scopes": ["openid", "promptrail:access"]},
        "metadata": {"issuer": issuer, "device_authorization_endpoint": issuer + "/device",
                     "token_endpoint": issuer + "/token"},
        "challenge": {"device_code": "private-device-code", "user_code": "ABCD-EFGH",
                      "verification_uri": issuer + "/verify", "expires_in": 100, "interval": 5},
        "tokens": [(200, {"access_token": "private-access-token", "token_type": "Bearer"})],
        "identity": {"subject": "user-1", "issuer": issuer, "audience": "promptrail-gateway", "provider": "keycloak",
                     "permissions": ["promptrail:access"], "expires_at": int(time.time()) + 300},
        "calls": [], "sleeps": [], "clock": 0.0, "identity_status": 200}
    def handle(request):
        state["calls"].append(request)
        url = str(request.url)
        if url.endswith("/auth/config"):
            return httpx.Response(200, json=state["profile"])
        if url.endswith("/auth/registration"):
            return httpx.Response(200, json={"signup_enabled": state.get("signup_enabled", False)})
        if url.endswith("openid-configuration"):
            return httpx.Response(200, json=state["metadata"])
        if url.endswith("/device"):
            return httpx.Response(200, json=state["challenge"])
        if url.endswith("/token"):
            status, body = state["tokens"].pop(0)
            if isinstance(body, Exception):
                raise body
            return httpx.Response(status, json=body)
        if url.endswith("/auth/whoami"):
            assert request.headers["Authorization"] == "Bearer private-access-token"
            return httpx.Response(state["identity_status"], json=state["identity"])
        pytest.fail("Unexpected destination: " + url)
    def sleep(duration):
        state["sleeps"].append(duration)
        state["clock"] += duration
    state["flow"] = lambda: DeviceLogin(Settings(), transport=httpx.MockTransport(handle),
                                       clock=lambda: state["clock"], sleep=sleep)
    return state


def test_keycloak_device_flow_and_gateway_verification(device_server):
    with device_server["flow"]() as flow:
        challenge = flow.begin()
        assert "private-device-code" not in repr(challenge)
        token = flow.poll(challenge)
        assert "private-access-token" not in repr(token)
        assert flow.verify(token).subject == "user-1"
    device = next(call for call in device_server["calls"] if str(call.url).endswith("/device"))
    assert parse_qs(device.content.decode()) == {"client_id": ["promptrail-cli"], "scope": ["openid promptrail:access"]}
    assert device_server["sleeps"] == [5]


def test_auth0_adapter_adds_audience(device_server):
    profile = LoginProfile.model_validate(device_server["profile"] | {"provider": "auth0"})
    assert provider_for(profile).device_parameters(profile)["audience"] == "promptrail-gateway"


def test_pending_and_slow_down_intervals(device_server):
    device_server["tokens"] = [(400, {"error": "authorization_pending"}),
        (429, {"error": "slow_down"}), (200, {"access_token": "private-access-token", "token_type": "bearer"})]
    with device_server["flow"]() as flow:
        flow.poll(flow.begin())
    assert device_server["sleeps"] == [5, 5, 10]


def test_timeout_uses_backoff(device_server):
    device_server["tokens"] = [(0, httpx.ReadTimeout("secret error")),
        (200, {"access_token": "private-access-token", "token_type": "Bearer"})]
    with device_server["flow"]() as flow:
        flow.poll(flow.begin())
    assert device_server["sleeps"] == [5, 10]


@pytest.mark.parametrize("error,expected", [("access_denied", "LOGIN_DENIED"),
    ("expired_token", "DEVICE_CODE_EXPIRED"), ("unknown", "TOKEN_REQUEST_FAILED")])
def test_terminal_oauth_errors(device_server, error, expected):
    device_server["tokens"] = [(400, {"error": error, "error_description": "secret upstream message"})]
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError) as raised:
            flow.poll(flow.begin())
    assert raised.value.code == expected
    assert "secret" not in str(raised.value)


def test_expiry_bounds_polling(device_server):
    device_server["challenge"]["expires_in"] = 11
    device_server["tokens"] = [(400, {"error": "authorization_pending"})] * 10
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError, match="DEVICE_CODE_EXPIRED"):
            flow.poll(flow.begin())
    assert device_server["sleeps"] == [5, 5]


@pytest.mark.parametrize("changes", [{"token_type": 42}, {"token_type": "Basic"},
    {"access_token": ""}, {"access_token": "token\nsecret"}, {"access_token": "x" * 16385}])
def test_invalid_token_response_never_reaches_gateway(device_server, changes):
    device_server["tokens"] = [(200, {"access_token": "private-access-token", "token_type": "Bearer"} | changes)]
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError, match="INVALID_TOKEN_RESPONSE"):
            flow.poll(flow.begin())
    assert not any(str(call.url).endswith("whoami") for call in device_server["calls"])


@pytest.mark.parametrize("field,value", [("issuer", "https://wrong.example"),
    ("device_authorization_endpoint", "http://169.254.169.254/secret"),
    ("token_endpoint", "https://other.example/token")])
def test_metadata_cannot_redirect_secrets(device_server, field, value):
    device_server["metadata"][field] = value
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError):
            flow.begin()
    assert not any("169.254" in str(call.url) or "other.example" in str(call.url) for call in device_server["calls"])


def test_browser_url_must_belong_to_issuer(device_server):
    device_server["challenge"]["verification_uri_complete"] = "https://evil.example/login"
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError):
            flow.begin()


def test_disabled_gateway_cannot_start_login(device_server):
    device_server["profile"]["mode"] = "disabled"
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError):
            flow.begin()
    assert len(device_server["calls"]) == 1


@pytest.mark.parametrize("changes", [{"issuer": "https://wrong.example"}, {"audience": "another-api"},
    {"provider": "auth0"}, {"permissions": []}, {"expires_at": 1}, {"token": "private"}])
def test_gateway_identity_must_match_profile(device_server, changes):
    device_server["identity"].update(changes)
    with device_server["flow"]() as flow:
        token = flow.poll(flow.begin())
        with pytest.raises(LoginError):
            flow.verify(token)


def test_gateway_rejection_prevents_login(device_server):
    device_server["identity_status"] = 401
    with device_server["flow"]() as flow:
        token = flow.poll(flow.begin())
        with pytest.raises(LoginError, match="GATEWAY_TOKEN_REJECTED"):
            flow.verify(token)


def test_safe_gateway_reason_code_is_reported(device_server):
    device_server["identity_status"] = 401
    device_server["identity"] = {"reason_code": "TOKEN_SUBJECT_MISSING", "reason": "private raw message"}
    with device_server["flow"]() as flow:
        token = flow.poll(flow.begin())
        with pytest.raises(LoginError, match="TOKEN_SUBJECT_MISSING") as error:
            flow.verify(token)
    assert "private raw message" not in str(error.value)


def test_signup_requires_server_advertisement_before_identity_requests(device_server):
    with device_server["flow"]() as flow:
        with pytest.raises(LoginError, match="SIGNUP_UNAVAILABLE"):
            flow.begin(signup=True)
    assert len(device_server["calls"]) == 2


def test_signup_runs_the_same_verified_device_flow(device_server):
    device_server["signup_enabled"] = True
    with device_server["flow"]() as flow:
        identity = flow.verify(flow.poll(flow.begin(signup=True)))
    assert identity.subject == "user-1"


def test_generic_oidc_scopes_are_supported(device_server):
    device_server["profile"].update(provider="oidc", scopes=["openid", "example:inspect"])
    device_server["identity"].update(provider="oidc", permissions=["example:inspect"])
    with device_server["flow"]() as flow:
        assert flow.verify(flow.poll(flow.begin())).permissions == ["example:inspect"]


@pytest.mark.parametrize("scopes", [["openid", "bad scope"], ["openid", "openid"], ["bad\nheader"], ["x"*129]])
def test_scope_validation_rejects_injection_and_ambiguity(device_server, scopes):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LoginProfile.model_validate(device_server["profile"] | {"scopes": scopes})


def test_existing_identity_inspection_matches_profile(device_server):
    from pydantic import SecretStr
    with device_server["flow"]() as flow:
        assert flow.inspect_identity(SecretStr("private-access-token")).subject == "user-1"
    assert len(device_server["calls"]) == 2
