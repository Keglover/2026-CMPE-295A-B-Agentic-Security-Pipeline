"""Run agent proposals and stop at an exact action awaiting human approval."""
import json
import os
from contextlib import ExitStack
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import typer

from promptrail.agent.client import AgentSession, SecurityException
from promptrail.agent.models import Checkpoint, ToolCallRequest
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.model_client import ModelClient
from promptrail.agent.state import lease, load, save
from promptrail.audit import append_event
from promptrail.auth.device import DeviceLogin, LoginError
from promptrail.config import get_token, load_settings

app = typer.Typer(no_args_is_help=True, help="Execute agent proposals through the authenticated gateway.")


def _credential(settings, login):
    if not login:
        token = get_token(settings.gateway_url)
        if not token:
            raise SecurityException("LOGIN_REQUIRED")
        return token
    with DeviceLogin(settings) as flow:
        challenge = flow.begin(scopes=["openid", "jev:evaluate", "jev:tools:call"])
        typer.echo("Human intervention required: authorize with the agent development account.")
        typer.echo(challenge.verification_uri_complete or challenge.verification_uri)
        typer.echo("Device code: " + challenge.user_code)
        token = flow.poll(challenge)
        flow.verify(token)
        return token.get_secret_value()


def _run(checkpoint, checkpoint_path, settings, login, renew_review=False):
    if checkpoint.status in {"complete", "uncertain"}:
        raise SecurityException("CHECKPOINT_COMPLETE" if checkpoint.status == "complete" else "MANUAL_RECONCILIATION_REQUIRED")
    if renew_review and checkpoint.status != "approval_required":
        raise SecurityException("REVIEW_RENEWAL_NOT_APPLICABLE")
    with ExitStack() as stack:
        model = stack.enter_context(ModelClient(checkpoint)) if isinstance(checkpoint, ConversationCheckpoint) else None
        token = _credential(settings, login)
        session = stack.enter_context(AgentSession(settings, token))
        checkpoint.agent_id = session.exchange(checkpoint.tools, checkpoint.agent_id)
        if renew_review:
            pending = checkpoint.requests[checkpoint.next_index]
            status = session.approval_status(pending.request_id)
            if status != "timed_out":
                raise SecurityException("MANUAL_RECONCILIATION_REQUIRED" if status in {"consumed", "not_found"}
                                        else "REVIEW_NOT_EXPIRED")
            checkpoint.requests[checkpoint.next_index] = pending.model_copy(update={"request_id": str(uuid4())})
            checkpoint.status = "ready"
            typer.echo("Expired review stays denied. Submitting the unexecuted action for a fresh assessment and review.")
        save(checkpoint_path, checkpoint)
        _continue(checkpoint, checkpoint_path, settings, session, model)
    typer.echo("Agent proposals completed. Credentials were not persisted.")


def _dispatch(checkpoint, checkpoint_path, settings, session):
    """Continue an authenticated session, preserving the uncertainty guard."""
    for index in range(checkpoint.next_index, len(checkpoint.requests)):
        request = checkpoint.requests[index]
        # A crash or transport loss may occur after dispatch. Record uncertainty first.
        checkpoint.status = "uncertain"
        save(checkpoint_path, checkpoint)
        result = session.call(request)
        append_event(settings.audit_path, result.evaluation, outcome=result.outcome,
                     reason_code=result.reason_code, executor_mode=result.executor_mode)
        typer.echo(f"{request.request_id}: {result.outcome} ({result.reason_code}; {result.executor_mode})")
        if result.outcome == "EXECUTED" and result.tool_output is not None:
            rendered = str(result.tool_output)[:65536]
            typer.echo("".join(c for c in rendered if c.isprintable() or c == "\n"))
        if result.outcome == "REQUIRE_APPROVAL":
            checkpoint.status = "approval_required"
            save(checkpoint_path, checkpoint)
            typer.echo("Human intervention required: review this action in /pending and approve its request ID.")
            typer.echo(f"Context saved to {checkpoint_path}. Resume with: jev agent resume {checkpoint_path}")
            raise typer.Exit(1)
        if result.outcome in {"UNAVAILABLE", "EXECUTION_UNKNOWN"}:
            raise SecurityException("MANUAL_RECONCILIATION_REQUIRED")
        checkpoint.next_index = index + 1
        checkpoint.status = "ready"
        save(checkpoint_path, checkpoint)
    checkpoint.status = "complete"
    save(checkpoint_path, checkpoint)


def _continue(checkpoint, checkpoint_path, settings, session, model=None):
    if isinstance(checkpoint, ConversationCheckpoint):
        from promptrail.agent.engine import run
        run(checkpoint, checkpoint_path, settings, session, model)
    else:
        _dispatch(checkpoint, checkpoint_path, settings, session)


@app.command()
def start(
    checkpoint_path: Annotated[Path, typer.Option("--checkpoint", help="Owner-only action context file.")],
    plan: Annotated[Path | None, typer.Option("--plan", help="JSON array of strict tool proposals.")] = None,
    prompt: Annotated[str | None, typer.Option("--prompt", help="Autonomous model prompt; use instead of --plan.")] = None,
    tools: Annotated[list[str] | None, typer.Option("--tool", help="Explicit model tool selection; repeat for each permitted tool.")] = None,
    model_url: Annotated[str | None, typer.Option("--model-url", help="Explicit OpenAI-compatible model base URL.")] = None,
    model_name: Annotated[str | None, typer.Option("--model")] = None,
    model_protocol: Annotated[str | None, typer.Option("--model-protocol", help="ollama for native /api/chat, openai for /chat/completions.")] = None,
    model_key_env: Annotated[str, typer.Option("--model-key-env")] = "OLLAMA_API_KEY",
    model_env_file: Annotated[Path | None, typer.Option("--model-env-file", help="Owner-only model settings/credentials file; no shell evaluation.")] = None,
    fallback_url: Annotated[str | None, typer.Option("--fallback-url")] = None,
    fallback_model: Annotated[str | None, typer.Option("--fallback-model")] = None,
    fallback_key_env: Annotated[str, typer.Option("--fallback-key-env")] = "OPENAI_API_KEY",
    token_limit_field: Annotated[str, typer.Option("--token-limit-field")] = "max_tokens",
    fallback_token_limit_field: Annotated[str, typer.Option("--fallback-token-limit-field")] = "max_completion_tokens",
    max_iterations: Annotated[int, typer.Option("--max-iterations", min=1, max=20)] = 5,
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    login: Annotated[bool, typer.Option("--login", help="Browser login for this run; token stays in memory.")] = False,
):
    try:
        settings = load_settings(gateway_url)
        if (plan is None) == (prompt is None):
            raise ValueError("Use either --plan or --prompt")
        with lease(checkpoint_path):
            if checkpoint_path.exists():
                raise SecurityException("CHECKPOINT_EXISTS_USE_RESUME")
            if prompt is not None:
                from promptrail.agent.definitions import definitions
                from promptrail.agent.model_config import model_values
                values = model_values(model_env_file)
                definitions(tools)
                checkpoint = ConversationCheckpoint(gateway_url=settings.gateway_url, tools=tools, prompt=prompt,
                    model_url=model_url or os.getenv("JEV_MODEL_URL") or values.get("JEV_MODEL_URL"),
                    model_name=model_name or os.getenv("JEV_MODEL_NAME") or values.get("JEV_MODEL_NAME"),
                    model_protocol=model_protocol or os.getenv("JEV_MODEL_PROTOCOL") or values.get("JEV_MODEL_PROTOCOL") or "openai",
                    model_key_env=model_key_env, model_env_file=str(model_env_file) if model_env_file else None,
                    token_limit_field=token_limit_field,
                    fallback_url=fallback_url or os.getenv("JEV_FALLBACK_MODEL_URL") or values.get("JEV_FALLBACK_MODEL_URL"),
                    fallback_model=fallback_model or os.getenv("JEV_FALLBACK_MODEL_NAME") or values.get("JEV_FALLBACK_MODEL_NAME") or None,
                    fallback_protocol="openai",
                    fallback_key_env=fallback_key_env, fallback_token_limit_field=fallback_token_limit_field,
                    max_iterations=max_iterations)
            else:
                if tools or model_url or model_name or model_protocol or fallback_url or fallback_model or model_env_file:
                    raise ValueError("Model options require --prompt")
                with plan.open("rb") as stream:
                    data = stream.read(4194305)
                if len(data) > 4194304:
                    raise ValueError("Plan too large")
                requests = [ToolCallRequest.model_validate(item) for item in json.loads(data)]
                if len({request.request_id for request in requests}) != len(requests):
                    raise ValueError("Request IDs must be unique within a plan")
                checkpoint = Checkpoint(gateway_url=settings.gateway_url, tools=sorted({r.proposed_tool for r in requests}),
                                        requests=requests, next_index=0)
            save(checkpoint_path, checkpoint)
            _run(checkpoint, checkpoint_path, settings, login)
    except (SecurityException, LoginError) as exc:
        typer.echo("Agent stopped: " + exc.code, err=True)
        raise typer.Exit(2)
    except (ValueError, OSError, TypeError):
        typer.echo("Agent stopped: invalid plan, configuration, or local state.", err=True)
        raise typer.Exit(2)


@app.command()
def resume(
    checkpoint_path: Annotated[Path, typer.Argument()],
    login: Annotated[bool, typer.Option("--login")] = False,
    renew_review: Annotated[bool, typer.Option("--renew-review", help="Reassess an expired, unexecuted review under a new request ID.")] = False,
):
    try:
        with lease(checkpoint_path):
            checkpoint = load(checkpoint_path)
            settings = load_settings(checkpoint.gateway_url)
            _run(checkpoint, checkpoint_path, settings, login, renew_review=renew_review)
    except (SecurityException, LoginError) as exc:
        typer.echo("Agent stopped: " + exc.code, err=True)
        raise typer.Exit(2)
    except (ValueError, OSError):
        typer.echo("Agent stopped: invalid checkpoint or local state.", err=True)
        raise typer.Exit(2)
