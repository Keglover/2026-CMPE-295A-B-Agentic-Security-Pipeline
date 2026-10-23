"""An agent gets a short-lived subset of its authenticated caller's authority."""
import time
import threading
import json
import os
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth.capabilities import AGENT_AUDIENCE, ISSUER, sign, verify
from app.auth.oidc import AuthenticationError, Identity
from app.auth.state_store import transaction

router = APIRouter()
_sessions = {}
_lock = threading.Lock()


def durable_identity(path, parent, tools, agent_id=None):
    """Identity survives a restart; every new JWT still requires fresh user authentication."""
    with transaction(path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY, parent TEXT NOT NULL, tools TEXT NOT NULL)")
        encoded = json.dumps(sorted(set(tools)))
        if agent_id:
            row = connection.execute("SELECT parent, tools FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if row != (parent, encoded):
                raise AuthenticationError("AGENT_SESSION_MISMATCH", 403)
            return agent_id
        if connection.execute("SELECT count(*) FROM agents").fetchone()[0] >= 1024:
            raise AuthenticationError("AGENT_SESSION_LIMIT", 503)
        agent_id = "agent:" + str(uuid4())
        connection.execute("INSERT INTO agents VALUES (?, ?, ?)", (agent_id, parent, encoded))
        return agent_id


class AgentTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tools: list[str] = Field(min_length=1, max_length=8)
    agent_id: str | None = Field(default=None, max_length=128)


def verify_agent(token):
    claims = verify(token, AGENT_AUDIENCE)
    tools, permissions, parent = claims.get("tools"), claims.get("permissions"), claims.get("parent_subject")
    allowed = {"jev:evaluate", "jev:tools:call"}
    if (not isinstance(tools, list) or not 1 <= len(tools) <= 8
            or any(not isinstance(tool, str) or not 0 < len(tool) <= 64 for tool in tools)
            or not isinstance(permissions, list) or not permissions
            or any(not isinstance(p, str) or p not in allowed for p in permissions)
            or not isinstance(parent, str) or not 0 < len(parent) <= 256):
        raise AuthenticationError("AGENT_TOKEN_INVALID")
    return Identity(claims["sub"], ISSUER, AGENT_AUDIENCE, "gateway", frozenset(permissions),
                    claims["exp"], "agent", frozenset(tools), parent)


@router.post("/auth/agent-token", tags=["authentication"])
def exchange(payload: AgentTokenRequest, request: Request):
    from app.gateway.gateway import TOOL_ALLOWLIST
    identity = getattr(request.state, "identity", None)
    if identity is None or identity.kind != "user":
        return JSONResponse(status_code=403, content={"reason_code": "USER_IDENTITY_REQUIRED"})
    if "jev:tools:call" not in identity.permissions or not set(payload.tools) <= TOOL_ALLOWLIST:
        return JSONResponse(status_code=403, content={"reason_code": "AGENT_SCOPE_DENIED"})
    lifetime = min(300, identity.expires_at - int(time.time()))
    if lifetime < 1:
        return JSONResponse(status_code=401, content={"reason_code": "TOKEN_EXPIRED"})
    # Internal evaluation is required for an agent. The user must possess that scope too.
    permissions = sorted(identity.permissions & {"jev:evaluate", "jev:tools:call"})
    if "jev:evaluate" not in permissions:
        return JSONResponse(status_code=403, content={"reason_code": "AGENT_SCOPE_DENIED"})
    now = time.time()
    tools = sorted(set(payload.tools))
    parent_binding = json.dumps([identity.issuer, identity.subject])
    state_path = os.getenv("JEV_GATEWAY_STATE_DB")
    if state_path:
        try:
            agent_id = durable_identity(state_path, parent_binding, tools, payload.agent_id)
        except AuthenticationError as exc:
            return JSONResponse(status_code=exc.status, content={"reason_code": exc.code})
        except Exception:
            return JSONResponse(status_code=503, content={"reason_code": "AGENT_STATE_UNAVAILABLE"})
    else:
        with _lock:
            for expired in [key for key, value in _sessions.items() if value[2] <= now]:
                del _sessions[expired]
            if payload.agent_id:
                existing = _sessions.get(payload.agent_id)
                if existing is None or existing[:2] != (parent_binding, tools):
                    return JSONResponse(status_code=403, content={"reason_code": "AGENT_SESSION_MISMATCH"})
                agent_id = payload.agent_id
            else:
                if len(_sessions) >= 1024:
                    return JSONResponse(status_code=503, content={"reason_code": "AGENT_SESSION_LIMIT"})
                agent_id = "agent:" + str(uuid4())
                _sessions[agent_id] = (parent_binding, tools, now + 3600)
    try:
        token = sign(AGENT_AUDIENCE, agent_id, lifetime, parent_subject=identity.subject,
                     permissions=permissions, tools=sorted(set(payload.tools)))
    except AuthenticationError as exc:
        return JSONResponse(status_code=exc.status, content={"reason_code": exc.code})
    return {"access_token": token, "token_type": "Bearer", "expires_in": lifetime,
            "agent_id": agent_id, "tools": sorted(set(payload.tools)), "permissions": permissions}
