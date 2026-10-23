"""Login, status, and local credential removal; output never contains tokens."""

import json
import os
from datetime import datetime, timezone
from typing import Annotated

import httpx
import keyring
import typer

from promptrail.auth.device import DeviceLogin, LoginError, VerifiedIdentity
from promptrail.config import SERVICE, get_token, load_settings, set_token

app = typer.Typer(no_args_is_help=True, help="Authenticate with the gateway's configured identity provider.")


@app.command("signin")
@app.command("login")
def login(
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    no_store: Annotated[bool, typer.Option("--no-store", help="Verify login without persisting the token.")] = False,
):
    """Sign in through the browser and verify the credential with the gateway."""
    _authenticate(gateway_url, no_store, signup=False)


@app.command("signup")
def signup(
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    no_store: Annotated[bool, typer.Option("--no-store")] = False,
):
    """Create an account in the identity provider's browser flow, then sign in."""
    _authenticate(gateway_url, no_store, signup=True)


def _authenticate(gateway_url, no_store, *, signup):
    """Run browser authorization and gateway verification before optional secure storage."""
    try:
        settings = load_settings(gateway_url)
        # Fail before starting browser login if the requested persistent session cannot be stored securely.
        if not no_store and keyring.get_keyring().priority <= 0:
            raise LoginError("SECURE_KEYRING_UNAVAILABLE")
        with DeviceLogin(settings) as flow:
            challenge = flow.begin(signup=True) if signup else flow.begin()
            if signup:
                typer.echo("In the identity-provider browser page choose Register, then create your account.")
                typer.echo("Passwords stay with the identity provider. Signup grants basic gateway access only.")
            typer.echo("Human intervention required: open this URL and authorize the displayed device code.")
            typer.echo(challenge.verification_uri_complete or challenge.verification_uri)
            typer.echo("Device code: " + challenge.user_code)
            typer.echo(f"Waiting for browser authorization (expires in {challenge.expires_in} seconds).")
            token = flow.poll(challenge)
            identity = flow.verify(token)
            # Browser success alone is insufficient: save only after gateway identity/permission verification.
            if not no_store:
                set_token(settings.gateway_url, token.get_secret_value())
            typer.echo("Login verified by the gateway.")
            typer.echo("Credential was not stored." if no_store else "Credential stored in the system keyring.")
            typer.echo("Permissions: " + ", ".join(identity.permissions))
            typer.echo("The access token is short-lived. Sign in again after it expires; refresh tokens are not stored.")
    except LoginError as error:
        typer.echo("Login failed: " + error.code, err=True)
        if error.code == "SECURE_KEYRING_UNAVAILABLE":
            typer.echo("Enable a system keyring, or use --no-store for verification only.", err=True)
        if error.code == "SIGNUP_UNAVAILABLE":
            typer.echo("Self-registration is disabled or unavailable. Ask the gateway administrator for an account or invitation.", err=True)
        if error.code == "INSUFFICIENT_PERMISSION":
            typer.echo("The account needs gateway access assigned by an administrator; signup alone is not authorization.", err=True)
        raise typer.Exit(2)
    except (keyring.errors.KeyringError, ValueError, OSError):
        typer.echo("Login could not securely validate or save the credential.", err=True)
        raise typer.Exit(2)
    except KeyboardInterrupt:
        typer.echo("Login interrupted.", err=True)
        raise typer.Exit(130)


@app.command()
def status(gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
           json_output: Annotated[bool, typer.Option("--json")] = False):
    """Ask the gateway to verify the current token; never trust decoded JWT claims locally."""
    def report(value):
        """Format verified identity or a safe unauthenticated reason without credentials."""
        if json_output:
            typer.echo(json.dumps(value))
        elif value["authenticated"]:
            typer.echo("Signed in; identity verified by the gateway.")
            typer.echo("Expires: " + datetime.fromtimestamp(value["expires_at"], timezone.utc).isoformat())
            typer.echo("Permissions: " + ", ".join(value["permissions"]))
        else:
            typer.echo("Not signed in: " + value["reason_code"] + ". Run promptrail auth signin.")
    try:
        settings = load_settings(gateway_url)
        token = get_token(settings.gateway_url)
        if not token:
            report({"authenticated": False, "reason_code": "NO_CREDENTIAL"})
            raise typer.Exit(1)
        from pydantic import SecretStr
        with DeviceLogin(settings) as flow:
            # Revalidate with the selected gateway on every status check, including token expiry.
            identity = flow.inspect_identity(SecretStr(token))
        report({"authenticated": True, **identity.model_dump()})
    except LoginError as error:
        report({"authenticated": False, "reason_code": error.code})
        raise typer.Exit(1 if error.code in {"TOKEN_EXPIRED", "GATEWAY_TOKEN_REJECTED", "INVALID_TOKEN"} else 2)
    except (httpx.HTTPError, ValueError, keyring.errors.KeyringError):
        report({"authenticated": False, "reason_code": "STATUS_UNAVAILABLE"})
        raise typer.Exit(2)


@app.command("signout")
@app.command("logout")
def logout(gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None):
    """Delete the gateway-scoped keyring entry and report any environment override."""
    # This is local signout; it neither revokes server-issued JWTs nor clears browser SSO cookies.
    try:
        settings = load_settings(gateway_url)
        for service in (SERVICE,):
            try:
                keyring.delete_password(service, settings.gateway_url)
            except keyring.errors.PasswordDeleteError:
                pass
    except (keyring.errors.KeyringError, ValueError):
        typer.echo("Local credential could not be removed.", err=True)
        raise typer.Exit(2)
    typer.echo("Local keyring credential removed. Issued tokens expire on the server's schedule.")
    for name in ("PROMPTRAIL_AUTH_TOKEN",):
        if os.getenv(name):
            typer.echo(name + " still supplies a credential; unset it to stop using that override.", err=True)
