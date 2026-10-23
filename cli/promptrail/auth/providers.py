"""Keycloak first; Auth0 wire adapter ready for a separately configured tenant."""

from urllib.parse import urlsplit
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from promptrail.config import Settings


class LoginProfile(BaseModel):
    """Strict public login contract supplied by the selected gateway."""
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: str
    provider: str
    issuer: str
    client_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    scopes: list[str]

    @field_validator("issuer")
    @classmethod
    def valid_issuer(cls, value):
        """Apply the client URL security rules to the advertised issuer."""
        Settings(gateway_url=value)
        return value

    @field_validator("mode")
    @classmethod
    def required_auth(cls, value):
        """Reject login profiles that do not require authentication."""
        if value != "required":
            raise ValueError("Gateway must require authentication before login")
        return value

    @field_validator("provider")
    @classmethod
    def supported_provider(cls, value):
        """Allow the Keycloak protocol and optional compatible client adapters."""
        if value not in {"keycloak", "auth0", "oidc"}:
            raise ValueError("Unsupported identity provider")
        return value

    @field_validator("scopes")
    @classmethod
    def allowed_scopes(cls, values):
        """Bound and validate distinct OAuth scope strings without imposing policy vocabulary."""
        # OAuth scope tokens exclude whitespace, double quotes and backslashes; duplicates are ambiguous.
        if (not values or len(values) > 32 or len(set(values)) != len(values)
                or any(not 1 <= len(value) <= 128 or not re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]+', value)
                       for value in values)):
            raise ValueError("Invalid requested scope")
        return values


def origin(url: str):
    """Normalize an HTTP origin including its effective default port."""
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class KeycloakProvider:
    """Build a public-client device request without any client secret."""
    def device_parameters(self, profile: LoginProfile) -> dict:
        """Return the public client ID and requested scopes for device authorization."""
        return {"client_id": profile.client_id, "scope": " ".join(profile.scopes)}


class Auth0Provider(KeycloakProvider):
    """Scaffold: same device protocol, with API audience passed explicitly."""

    def device_parameters(self, profile: LoginProfile) -> dict:
        """Add the API audience required by the optional Auth0 client scaffold."""
        return super().device_parameters(profile) | {"audience": profile.audience}


def provider_for(profile: LoginProfile):
    """Choose the Auth0 scaffold or the standard Keycloak-compatible device request."""
    return Auth0Provider() if profile.provider == "auth0" else KeycloakProvider()
