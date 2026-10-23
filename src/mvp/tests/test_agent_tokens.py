import pytest

from tests.test_authentication import signing_key, oidc, protected_api
from tests.test_runner_capabilities import keys
from app.auth import agents
from app.auth.agents import verify_agent
from app.auth.oidc import AuthenticationError


def header(token, sub="owner", extra=""):
    permissions = ["jev:evaluate", "jev:tools:call"] + ([extra] if extra else [])
    return {"Authorization": "Bearer " + token(sub=sub, scope=" ".join(permissions),
                                              realm_access={"roles": permissions})}


def grant(api, token):
    response = api.post("/auth/agent-token", headers=header(token, extra="jev:approvals:write"),
                        json={"tools": ["summarize"]})
    assert response.status_code == 200
    return response.json()


def test_exchange_limits_tools_authority_and_expiry(protected_api, keys):
    api, token = protected_api
    result = grant(api, token)
    identity = verify_agent(result["access_token"])
    assert identity.kind == "agent" and identity.parent_subject == "owner"
    assert identity.allowed_tools == {"summarize"}
    assert identity.permissions == {"jev:evaluate", "jev:tools:call"}
    assert result["expires_in"] <= 300


def test_agent_cannot_review_or_exchange_again(protected_api, keys):
    api, token = protected_api
    grant_result = grant(api, token)
    headers = {"Authorization": "Bearer " + grant_result["access_token"]}
    assert api.get("/pending", headers=headers).status_code == 403
    assert api.post("/approve/one", headers=headers).status_code == 403
    assert api.post("/auth/agent-token", headers=headers, json={"tools": ["summarize"]}).status_code == 403
    assert api.post("/pipeline", headers=headers, json={"content": "Hi"}).status_code == 403


def test_agent_cannot_invoke_other_tool(protected_api, keys):
    api, token = protected_api
    result = grant(api, token)
    response = api.post("/tools/call", headers={"Authorization": "Bearer " + result["access_token"]},
                        json={"content": "Print a message", "proposed_tool": "execute_command",
                              "tool_args": {"command": "echo hello"}})
    assert response.status_code == 403 and response.json()["reason_code"] == "AGENT_TOOL_DENIED"


def test_resume_keeps_agent_identity_only_for_owner_and_same_tools(protected_api, keys):
    api, token = protected_api
    first = grant(api, token)
    payload = {"tools": first["tools"], "agent_id": first["agent_id"]}
    resumed = api.post("/auth/agent-token", headers=header(token), json=payload)
    assert resumed.status_code == 200 and resumed.json()["agent_id"] == first["agent_id"]
    assert api.post("/auth/agent-token", headers=header(token, "mallory"), json=payload).status_code == 403
    assert api.post("/auth/agent-token", headers=header(token), json=payload | {"tools": ["write_note"]}).status_code == 403


def test_lost_server_session_fails_closed(protected_api, keys, monkeypatch):
    api, token = protected_api
    first = grant(api, token)
    monkeypatch.setattr(agents, "_sessions", {})
    response = api.post("/auth/agent-token", headers=header(token),
                        json={"tools": first["tools"], "agent_id": first["agent_id"]})
    assert response.status_code == 403


def test_evaluation_user_cannot_exchange(protected_api, keys):
    api, token = protected_api
    assert api.post("/auth/agent-token", headers={"Authorization": "Bearer " + token()},
                    json={"tools": ["summarize"]}).status_code == 403


def test_agent_without_gateway_key_fails_closed(protected_api, monkeypatch):
    api, token = protected_api
    monkeypatch.delenv("JEV_GATEWAY_SIGNING_KEY", raising=False)
    assert api.post("/auth/agent-token", headers=header(token), json={"tools": ["summarize"]}).status_code == 503
