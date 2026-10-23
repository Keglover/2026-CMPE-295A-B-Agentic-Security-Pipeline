import keyring
import pytest
from pydantic import ValidationError

from promptrail import config


@pytest.mark.parametrize("url", ["http://example.com", "https://user:pass@example.com",
    "https://example.com?token=secret", "https://example.com#fragment", "file:///tmp/socket",
    "https://example.com:bad", "http://127.0.0.1.evil.com"])
def test_insecure_or_ambiguous_gateway_rejected(url):
    with pytest.raises(ValidationError):
        config.Settings(gateway_url=url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://[::1]:8000",
                                "https://gateway.example.com/api/"])
def test_allowed_gateway(url):
    assert config.Settings(gateway_url=url).gateway_url == url.rstrip("/")


def test_env_credential_precedes_keyring(monkeypatch):
    monkeypatch.setenv("JEV_AUTH_TOKEN", "environment-token")
    monkeypatch.setattr(config.keyring, "get_password", lambda *args: pytest.fail("Unexpected keyring access"))
    assert config.get_token("https://gateway.example.com") == "environment-token"


def test_headless_keyring_without_token(monkeypatch):
    monkeypatch.delenv("JEV_AUTH_TOKEN", raising=False)
    def unavailable(*args):
        raise keyring.errors.NoKeyringError("No secure backend")
    monkeypatch.setattr(config.keyring, "get_password", unavailable)
    assert config.get_token("http://127.0.0.1:8000") is None


def test_keyring_credential_scoped_by_gateway(monkeypatch):
    monkeypatch.delenv("JEV_AUTH_TOKEN", raising=False)
    received = []
    monkeypatch.setattr(config.keyring, "get_password", lambda *args: received.append(args) or "stored-token")
    assert config.get_token("https://gateway.example.com") == "stored-token"
    assert received == [(config.SERVICE, "https://gateway.example.com")]


def test_bad_credential_cannot_be_forwarded(monkeypatch):
    monkeypatch.setenv("JEV_AUTH_TOKEN", "secret\nAuthorization: other")
    with pytest.raises(ValueError):
        config.get_token("https://gateway.example.com")


def test_promptrail_settings_override_legacy_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("PROMPTRAIL_GATEWAY_URL", "https://gateway.example.com")
    monkeypatch.setenv("JEV_GATEWAY_URL", "https://legacy.example.com")
    monkeypatch.setenv("PROMPTRAIL_AUDIT_PATH", str(tmp_path / "new.jsonl"))
    settings = config.load_settings()
    assert settings.gateway_url == "https://gateway.example.com"
    assert settings.audit_path == tmp_path / "new.jsonl"


def test_promptrail_token_does_not_reuse_legacy_keyring(monkeypatch):
    monkeypatch.setenv("PROMPTRAIL_AUTH_TOKEN", "new-token")
    monkeypatch.setenv("JEV_AUTH_TOKEN", "old-token")
    monkeypatch.setattr(config.keyring, "get_password", lambda *a: pytest.fail("Unexpected keyring access"))
    assert config.get_token("https://gateway.example.com") == "new-token"
