"""Public login configuration and verified identity; no token echoing."""

from fastapi import APIRouter, Request
import os

from app.auth.oidc import load_settings

router = APIRouter()


@router.get("/auth/registration", tags=["authentication"])
def registration_config():
    """Advertise operator-configured browser signup without changing the login contract."""
    settings = load_settings()
    return {"signup_enabled": settings.mode == "required" and settings.provider == "keycloak"
            and os.getenv("JEV_SELF_REGISTRATION_ENABLED", "false").lower() == "true"}


@router.get("/auth/config", tags=["authentication"])
def auth_config():
    settings = load_settings()
    return {"mode": settings.mode, "provider": settings.provider, "issuer": settings.issuer,
        "client_id": settings.client_id, "audience": settings.audience,
        "scopes": ["openid", "jev:evaluate"]}


@router.get("/auth/whoami", tags=["authentication"])
def whoami(request: Request):
    identity = request.state.identity
    return {"subject": identity.subject, "issuer": identity.issuer, "audience": identity.audience,
        "provider": identity.provider, "permissions": sorted(identity.permissions),
        "expires_at": identity.expires_at}
