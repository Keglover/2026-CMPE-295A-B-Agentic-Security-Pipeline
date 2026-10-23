"""Keycloak first; Auth0 wire adapter ready for a separately configured tenant."""

from urllib.parse import urlsplit
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from promptrail.config import Settings


class LoginProfile(BaseModel):
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
        Settings(gateway_url=value)
        return value

    @field_validator("mode")
    @classmethod
    def required_auth(cls, value):
        if value != "required":
            raise ValueError("Gateway must require authentication before login")
        return value

    @field_validator("provider")
    @classmethod
    def supported_provider(cls, value):
        if value not in {"keycloak", "auth0", "oidc"}:
            raise ValueError("Unsupported identity provider")
        return value

    @field_validator("scopes")
    @classmethod
    def allowed_scopes(cls, values):
        if (not values or len(values) > 32 or len(set(values)) != len(values)
                or any(not 1 <= len(value) <= 128 or not re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]+', value)
                       for value in values)):
            raise ValueError("Invalid requested scope")
        return values


def origin(url: str):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class KeycloakProvider:
    def device_parameters(self, profile: LoginProfile) -> dict:
        return {"client_id": profile.client_id, "scope": " ".join(profile.scopes)}


class Auth0Provider(KeycloakProvider):
    """Scaffold: same device protocol, with API audience passed explicitly."""

    def device_parameters(self, profile: LoginProfile) -> dict:
        return super().device_parameters(profile) | {"audience": profile.audience}


def provider_for(profile: LoginProfile):
    return Auth0Provider() if profile.provider == "auth0" else KeycloakProvider()
