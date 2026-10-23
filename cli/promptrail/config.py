"""Explicit gateway configuration and credentials scoped to that gateway."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import keyring
from pydantic import BaseModel, ConfigDict, Field, field_validator

SERVICE = "promptrail-cli"
LEGACY_SERVICE = "jev-security-cli"


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    gateway_url: str = "http://127.0.0.1:8003"
    timeout: float = Field(default=10.0, gt=0, le=120)
    audit_path: Path = Field(default_factory=lambda: Path.home() / ".config" / "promptrail" / "audit.jsonl")

    @field_validator("gateway_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or any(char.isspace() for char in value)):
            raise ValueError("Gateway URL must be an HTTP(S) origin or base path")
        parsed.port
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote gateways require HTTPS")
        return value.rstrip("/")


def load_settings(gateway_url: str | None = None, timeout: float = 10.0,
                  audit_path: Path | None = None) -> Settings:
    values = dict(gateway_url=gateway_url or os.getenv("PROMPTRAIL_GATEWAY_URL") or os.getenv("JEV_GATEWAY_URL", "http://127.0.0.1:8003"),
                  timeout=timeout)
    configured_path = audit_path or os.getenv("PROMPTRAIL_AUDIT_PATH") or os.getenv("JEV_AUDIT_PATH")
    if configured_path:
        values["audit_path"] = Path(configured_path)
    return Settings(**values)


def get_token(gateway_url: str) -> str | None:
    token = os.getenv("PROMPTRAIL_AUTH_TOKEN")
    if token is None:
        token = os.getenv("JEV_AUTH_TOKEN")
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
    if not token or not token.isascii() or any(char.isspace() for char in token) or len(token) > 16384:
        raise ValueError("Credential is invalid")
    keyring.set_password(SERVICE, gateway_url, token)
