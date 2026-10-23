from types import SimpleNamespace
from unittest.mock import Mock

import keyring
import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from promptrail.auth import commands
from promptrail.auth.device import LoginError
from promptrail.main import app

runner = CliRunner()


@pytest.fixture
def login(monkeypatch):
    state = {"token": SecretStr("private-access-token"), "order": []}
    class Flow:
        def __init__(self, settings):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def begin(self, *, signup=False):
            state["order"].append("begin")
            state["signup"] = signup
            if "begin_error" in state:
                raise state["begin_error"]
            return SimpleNamespace(verification_uri="http://127.0.0.1:8080/verify",
                verification_uri_complete=None, user_code="ABCD-EFGH", expires_in=600)
        def poll(self, challenge):
            state["order"].append("poll")
            return state["token"]
        def verify(self, token):
            state["order"].append("verify")
            if "error" in state:
                raise state["error"]
            return SimpleNamespace(permissions=["jev:evaluate"])
    monkeypatch.setattr(commands, "DeviceLogin", Flow)
    monkeypatch.setattr(commands.keyring, "get_keyring", lambda: SimpleNamespace(priority=1))
    def save(*args):
        state["order"].append("save")
    monkeypatch.setattr(commands, "set_token", save)
    return state


def test_login_verifies_before_storage(login):
    result = runner.invoke(app, ["auth", "login"])
    assert result.exit_code == 0, result.output
    assert login["order"] == ["begin", "poll", "verify", "save"]
    assert "Human intervention required" in result.output
    assert "private-access-token" not in result.output


def test_no_store_for_headless_verification(login, monkeypatch):
    monkeypatch.setattr(commands.keyring, "get_keyring", lambda: SimpleNamespace(priority=0))
    result = runner.invoke(app, ["auth", "login", "--no-store"])
    assert result.exit_code == 0
    assert "save" not in login["order"]
    assert "Credential was not stored" in result.stdout


def test_missing_secure_storage_is_actionable(login, monkeypatch):
    monkeypatch.setattr(commands.keyring, "get_keyring", lambda: SimpleNamespace(priority=0))
    result = runner.invoke(app, ["auth", "login"])
    assert result.exit_code == 2
    assert "SECURE_KEYRING_UNAVAILABLE" in result.output
    assert "--no-store" in result.output
    assert not login["order"]


def test_failed_verification_never_stores(login):
    login["error"] = LoginError("GATEWAY_TOKEN_REJECTED")
    result = runner.invoke(app, ["auth", "login"])
    assert result.exit_code == 2
    assert "save" not in login["order"]
    assert "private-access-token" not in result.output


def test_status_without_credential(monkeypatch):
    monkeypatch.setattr(commands, "get_token", lambda _: None)
    result = runner.invoke(app, ["auth", "status"])
    assert result.exit_code == 1 and "NO_CREDENTIAL" in result.stdout


def test_logout_removes_only_scoped_credential(monkeypatch):
    delete = Mock()
    monkeypatch.setattr(commands.keyring, "delete_password", delete)
    result = runner.invoke(app, ["auth", "logout", "--gateway-url", "http://127.0.0.1:8003"])
    assert result.exit_code == 0
    assert [call.args for call in delete.call_args_list] == [
        (commands.SERVICE, "http://127.0.0.1:8003"),
        (commands.LEGACY_SERVICE, "http://127.0.0.1:8003")]


def test_keyboard_interrupt_is_safe(login):
    login["error"] = KeyboardInterrupt()
    result = runner.invoke(app, ["auth", "login", "--no-store"])
    assert result.exit_code == 130
    assert "save" not in login["order"]


def test_no_store_can_verify_authenticated_evaluation(login, monkeypatch):
    class Client:
        def __init__(self, settings, token):
            assert token == "private-access-token"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def evaluate(self, request):
            return SimpleNamespace(status="evaluated", execution_requirement=SimpleNamespace(value="NONE"))
    monkeypatch.setattr(commands, "GatewayClient", Client)
    result = runner.invoke(app, ["auth", "login", "--no-store", "--verify-evaluation"])
    assert result.exit_code == 0
    assert "Authenticated evaluation succeeded" in result.output
    assert "save" not in login["order"]
    assert "private-access-token" not in result.output


def test_signin_alias_verifies_before_storage(login):
    result = runner.invoke(app, ["auth", "signin"])
    assert result.exit_code == 0 and login["order"] == ["begin", "poll", "verify", "save"]


def test_signup_uses_browser_and_verifies_before_storage(login):
    result = runner.invoke(app, ["auth", "signup"])
    assert result.exit_code == 0 and login["signup"] is True
    assert login["order"] == ["begin", "poll", "verify", "save"]
    assert "Register" in result.output and "Passwords stay" in result.output


def test_signup_unavailable_never_polls_or_saves(login):
    login["begin_error"] = LoginError("SIGNUP_UNAVAILABLE")
    result = runner.invoke(app, ["auth", "signup"])
    assert result.exit_code == 2 and login["order"] == ["begin"]
    assert "administrator" in result.output


def test_status_uses_bounded_gateway_identity_verification(monkeypatch):
    from promptrail.auth.device import VerifiedIdentity
    import time
    class Flow:
        def __init__(self, settings): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def inspect_identity(self, token):
            assert token.get_secret_value() == "private-token"
            return VerifiedIdentity(subject="member", issuer="https://identity.example", audience="api",
                                    provider="oidc", permissions=["example:inspect"], expires_at=int(time.time())+300)
    monkeypatch.setattr(commands, "DeviceLogin", Flow)
    monkeypatch.setattr(commands, "get_token", lambda _: "private-token")
    result = runner.invoke(app, ["auth", "status", "--json"])
    assert result.exit_code == 0 and '"authenticated": true' in result.output
    assert "private-token" not in result.output


def test_expired_session_is_actionable_and_never_prints_token(monkeypatch):
    class Flow:
        def __init__(self, settings): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def inspect_identity(self, token): raise LoginError("TOKEN_EXPIRED")
    monkeypatch.setattr(commands, "DeviceLogin", Flow)
    monkeypatch.setattr(commands, "get_token", lambda _: "private-token")
    result = runner.invoke(app, ["auth", "status"])
    assert result.exit_code == 1 and "signin" in result.output and "TOKEN_EXPIRED" in result.output
    assert "private-token" not in result.output


def test_signout_reports_environment_override_without_value(monkeypatch):
    monkeypatch.setattr(commands.keyring, "delete_password", Mock())
    monkeypatch.setenv("PROMPTRAIL_AUTH_TOKEN", "private-token")
    result = runner.invoke(app, ["auth", "signout"])
    assert result.exit_code == 0 and "PROMPTRAIL_AUTH_TOKEN" in result.output
    assert "private-token" not in result.output
