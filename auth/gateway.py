"""Authentication-only gateway: public configuration and verified caller identity."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from auth.oidc import AuthenticationError, get_verifier, load_settings

ACCESS_PERMISSION = "promptrail:access"


@asynccontextmanager
async def lifespan(app):
    """Reject unsupported authentication settings before serving requests."""
    load_settings()  # Invalid/disabled configuration prevents startup.
    yield


app = FastAPI(title="Promptrail authentication gateway", docs_url=None,
              redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware("http")
async def response_privacy(request, call_next):
    """Prevent caching of identity responses and browser content-type guessing."""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health")
def health():
    """Report process availability and the authentication-only service contract."""
    return {"status": "ok", "service": "promptrail-auth", "capabilities": ["authentication"]}


@app.get("/auth/config")
def configuration():
    """Publish non-secret issuer, public client, audience and requested scopes."""
    settings = load_settings()
    return {"mode": settings.mode, "provider": settings.provider, "issuer": settings.issuer,
            "client_id": settings.client_id, "audience": settings.audience,
            "scopes": ["openid", ACCESS_PERMISSION]}


@app.get("/auth/registration")
def registration():
    """Advertise the operator setting; this does not change the Keycloak realm."""
    return {"signup_enabled": load_settings().provider == "keycloak"
            and os.getenv("PROMPTRAIL_SELF_REGISTRATION_ENABLED", "false").lower() == "true"}


@app.get("/auth/whoami")
async def whoami(request: Request):
    """Verify the bearer token and basic access before returning bounded identity fields."""
    try:
        scheme, separator, token = request.headers.get("Authorization", "").partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("AUTHENTICATION_REQUIRED")
        # Signature verification may fetch signing keys; keep that blocking work off the event loop.
        identity = await run_in_threadpool(get_verifier(load_settings()).verify, token)
        # A valid signature proves identity, but access still requires an assigned/requested permission.
        if ACCESS_PERMISSION not in identity.permissions:
            raise AuthenticationError("INSUFFICIENT_PERMISSION", 403)
        return {"subject": identity.subject, "issuer": identity.issuer, "audience": identity.audience,
                "provider": identity.provider, "permissions": sorted(identity.permissions),
                "expires_at": identity.expires_at}
    except AuthenticationError as error:
        headers = {"WWW-Authenticate": "Bearer"} if error.status == 401 else {}
        return JSONResponse(status_code=error.status, headers=headers,
                            content={"reason_code": error.code})
    except (ValueError, TypeError):
        return JSONResponse(status_code=503, content={"reason_code": "IDENTITY_CONFIGURATION_INVALID"})
