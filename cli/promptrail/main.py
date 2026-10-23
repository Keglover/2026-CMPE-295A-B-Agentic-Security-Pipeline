"""Promptrail's authentication-only terminal entry point."""
import json
from importlib.metadata import version
from typing import Annotated

import typer

from promptrail.auth.commands import app as auth_app
from promptrail.config import load_settings
from promptrail.readiness import ReadinessError, inspect_gateway

app = typer.Typer(no_args_is_help=True, invoke_without_command=True, help="Promptrail: gateway authentication and access.")
app.add_typer(auth_app, name="auth")


@app.callback()
def main(show_version: Annotated[bool, typer.Option("--version", is_eager=True)] = False):
    """Handle the installed package version before dispatching a subcommand."""
    if show_version:
        typer.echo("promptrail " + version("promptrail-cli"))
        raise typer.Exit()


@app.command()
def doctor(
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    """Check the authentication gateway without sending credentials."""
    try:
        report = inspect_gateway(load_settings(gateway_url))
    except (ReadinessError, ValueError) as error:
        reason = str(error) if isinstance(error, ReadinessError) else "INVALID_CONFIGURATION"
        if json_output:
            typer.echo(json.dumps({"gateway_reachable": False, "reason_code": reason}))
        else:
            typer.echo("Gateway check failed: " + reason, err=True)
        raise typer.Exit(2)
    if json_output:
        typer.echo(json.dumps(report))
    else:
        typer.echo("Authentication gateway reachable; login required.")
        typer.echo("Provider: " + report["provider"])
        typer.echo("Capabilities: authentication. Execution is not implemented in this release.")
