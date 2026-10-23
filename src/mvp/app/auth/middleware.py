"""Authenticate before parsing sensitive request bodies or dispatching tools."""

from uuid import uuid4

from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.auth.oidc import AuthenticationError, get_verifier, load_settings
from app.auth.agents import verify_agent
from app.auth.capabilities import AGENT_AUDIENCE, ISSUER


def required_permission(path: str) -> str | None:
    path = path.rstrip("/")
    if path in {"/evaluate", "/validate-urls", "/tools"}:
        return "jev:evaluate"
    if path in {"/pipeline", "/tools/call", "/auth/agent-token"} or path.startswith("/tools/requests/"):
        return "jev:tools:call"
    if path == "/pending" or path.startswith(("/approve/", "/reject/")):
        return "jev:approvals:write"
    if path in {"/history", "/policy/stats"}:
        return "jev:audit:read"
    return None


async def authenticate(request, call_next):
    permission = required_permission(request.url.path)
    whoami = request.url.path.rstrip("/") == "/auth/whoami"
    try:
        settings = load_settings()
        if not permission and not whoami:
            return await call_next(request)
        if settings.mode == "disabled" and not whoami:
            return await call_next(request)
        if settings.mode == "disabled":
            raise AuthenticationError("AUTHENTICATION_NOT_CONFIGURED", 503)
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or " " in token:
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        if len(token) > 16384 or any(char.isspace() for char in token):
            raise AuthenticationError("TOKEN_INVALID")
        # Unverified issuer selects a verifier only; signature/audience checks still pin authority.
        import jwt
        try:
            hint = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            raise AuthenticationError("TOKEN_INVALID") from None
        if hint.get("iss") == ISSUER and hint.get("aud") == AGENT_AUDIENCE:
            identity = await run_in_threadpool(verify_agent, token)
            if (request.url.path.rstrip("/") not in {"/evaluate", "/tools/call"}
                    and not request.url.path.startswith("/tools/requests/")):
                raise AuthenticationError("AGENT_SCOPE_DENIED", 403)
        else:
            identity = await run_in_threadpool(get_verifier(settings).verify, token)
        if permission and permission not in identity.permissions:
            raise AuthenticationError("INSUFFICIENT_PERMISSION", 403)
        request.state.identity = identity
        return await call_next(request)
    except AuthenticationError as error:
        from app.evaluation.service import persist_result, unavailable
        result = await run_in_threadpool(persist_result, unavailable(str(uuid4()), error.code))
        status = 503 if result.reason_code == "AUDIT_UNAVAILABLE" else error.status
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else {}
        return JSONResponse(status_code=status, headers=headers, content=result.model_dump(mode="json"))
    except (ValueError, TypeError):
        return JSONResponse(status_code=503, content={"reason_code": "IDENTITY_CONFIGURATION_INVALID",
                                                    "execution_authorized": False})
