"""Evaluation and local audit commands. No subprocess or executor access."""

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from promptrail.audit import append_event, read_events
from promptrail.client import GatewayClient
from promptrail.config import get_token, load_settings
from promptrail.models import EvaluationRequest, ExecutionRequirement, PolicyAction, UserContext
from promptrail.auth.commands import app as auth_app
from promptrail.agent.commands import app as agent_app
from promptrail.approvals.commands import app as approvals_app

app = typer.Typer(no_args_is_help=True, help="Inspect agent requests through the security gateway.")
app.add_typer(auth_app, name="auth")
app.add_typer(agent_app, name="agent")
app.add_typer(approvals_app, name="approvals")


def _safe(text: str) -> str:
    return "".join(char for char in text if char.isprintable() or char == "\n")


@app.command("eval")
def evaluate(
    content: Annotated[str | None, typer.Argument(help="Content to inspect; use --stdin for sensitive input.")] = None,
    tool: Annotated[str | None, typer.Option("--tool", help="Explicit proposed tool.")] = None,
    args_json: Annotated[str, typer.Option("--args-json", help="JSON object of tool arguments.")] = "{}",
    stdin: Annotated[bool, typer.Option("--stdin", help="Read content from standard input.")] = False,
    include_cwd: Annotated[bool, typer.Option("--include-cwd", help="Send current directory as advisory context.")] = False,
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    timeout: Annotated[float, typer.Option(min=0.1, max=120)] = 10.0,
    audit_path: Annotated[Path | None, typer.Option("--audit-path")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit one machine-readable result.")] = False,
):
    try:
        if stdin and content is not None:
            raise ValueError("Use either a content argument or --stdin")
        if stdin:
            content = sys.stdin.read(50001)
        if content is None:
            raise ValueError("Provide content or --stdin")
        def invalid_constant(value):
            raise ValueError("Non-finite JSON numbers are not allowed")
        arguments = json.loads(args_json, parse_constant=invalid_constant)
        request = EvaluationRequest(content=content, proposed_tool=tool, tool_args=arguments,
            context=UserContext(platform=sys.platform, shell=os.getenv("SHELL"),
                                working_directory=os.getcwd() if include_cwd else None))
        settings = load_settings(gateway_url, timeout, audit_path)
        token = get_token(settings.gateway_url)
    except (ValidationError, ValueError, OSError):
        if json_output:
            typer.echo(json.dumps({"status": "invalid_input", "reason_code": "INVALID_INPUT",
                                   "execution_authorized": False}))
        else:
            typer.echo("Invalid input or configuration. Check content, tool arguments, and gateway URL.", err=True)
        raise typer.Exit(2)

    with GatewayClient(settings, token=token) as client:
        result = client.evaluate(request)
    audit_failed = False
    try:
        append_event(settings.audit_path, result)
    except (OSError, ValueError):
        audit_failed = True
        typer.echo("Local audit unavailable. The gateway assessment grants no execution authority.", err=True)
    if json_output:
        typer.echo(result.model_dump_json())
    else:
        color = "red" if result.execution_requirement == ExecutionRequirement.DENIED else (
            "yellow" if result.execution_requirement == ExecutionRequirement.REQUIRE_APPROVAL else "green")
        body = (f"Status: {result.status}\nPolicy: {result.policy_action.value}\n"
                f"Risk: {result.risk_score if result.risk_score is not None else 'unavailable'}\n"
                f"Execution requirement: {result.execution_requirement.value}\n"
                f"Reason: {result.reason_code}\n{_safe(result.reason)}\n"
                "Execution authorized: false")
        Console().print(Panel(Text(body), title="Promptrail evaluation", border_style=color))
        if result.execution_requirement == ExecutionRequirement.REQUIRE_APPROVAL:
            typer.echo("Human review is required for execution. Evaluation has not queued an approval.")
    if result.status == "unavailable" or audit_failed:
        raise typer.Exit(2)
    if (result.execution_requirement != ExecutionRequirement.NONE
            or result.policy_action in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}):
        raise typer.Exit(1)


@app.command("audit")
def audit(
    limit: Annotated[int, typer.Option(min=1, max=500)] = 20,
    audit_path: Annotated[Path | None, typer.Option("--audit-path")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
):
    try:
        path = load_settings(audit_path=audit_path).audit_path
        events, skipped = read_events(path, limit)
    except (OSError, ValueError):
        typer.echo("Cannot read local audit history.", err=True)
        raise typer.Exit(2)
    if json_output:
        typer.echo(json.dumps({"entries": [event.model_dump() for event in events], "skipped": skipped}))
        return
    if not events:
        typer.echo("No audit logs found.")
    else:
        table = Table("Timestamp", "Request", "Policy", "Risk", "Execution requirement")
        for event in events:
            table.add_row(*[Text(_safe(str(value))) for value in [event.timestamp, event.request_id,
                event.policy_action, event.risk_score, event.execution_requirement]])
        Console().print(table)
    if skipped:
        typer.echo(f"Skipped {skipped} invalid audit records.", err=True)
