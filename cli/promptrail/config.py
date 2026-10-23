"""Explicit gateway configuration and credentials scoped to that gateway."""

import os
from urllib.parse import urlsplit

import keyring
from pydantic import BaseModel, ConfigDict, Field, field_validator

# The gateway URL is the keyring account, so each gateway has a separate credential entry.
SERVICE = "promptrail-cli"


class Settings(BaseModel):
    """Validated client gateway URL and per-request timeout; contains no bearer token."""
    model_config = ConfigDict(extra="forbid", strict=True)
    gateway_url: str = "http://127.0.0.1:8003"
    timeout: float = Field(default=10.0, gt=0, le=120)

    @field_validator("gateway_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Reject ambiguous URLs and remote plaintext HTTP, then normalize a trailing slash."""
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or any(char.isspace() for char in value)):
            raise ValueError("Gateway URL must be an HTTP(S) origin or base path")
        parsed.port  # Access validates malformed/non-numeric ports before any network request.
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote gateways require HTTPS")
        return value.rstrip("/")


def load_settings(gateway_url: str | None = None, timeout: float = 10.0) -> Settings:
    """Resolve explicit gateway, then environment, then the loopback default."""
    return Settings(gateway_url=gateway_url or os.getenv("PROMPTRAIL_GATEWAY_URL", "http://127.0.0.1:8003"),
                    timeout=timeout)


def get_token(gateway_url: str) -> str | None:
    """Read an environment override or gateway-scoped keyring token and validate header safety."""
    # Explicit environment credentials take precedence; do not silently fall back if one is invalid.
    token = os.getenv("PROMPTRAIL_AUTH_TOKEN")
    if token is None:
        try:
            token = keyring.get_password(SERVICE, gateway_url)
        except keyring.errors.KeyringError:
            token = None
    if token is not None and (not token or len(token) > 16384
                              or not token.isascii() or any(char.isspace() for char in token)):
        raise ValueError("Stored credential is invalid")
    return token


def set_token(gateway_url: str, token: str) -> None:
    """Store a header-safe token in the OS keyring for this gateway only."""
    if not token or not token.isascii() or any(char.isspace() for char in token) or len(token) > 16384:
        raise ValueError("Credential is invalid")
    # There is deliberately no plaintext-file fallback when secure storage is unavailable.
    keyring.set_password(SERVICE, gateway_url, token)
