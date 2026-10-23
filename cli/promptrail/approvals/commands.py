import json
import re
from pathlib import Path
from typing import Annotated

import httpx
import typer

from promptrail.auth.device import DeviceLogin, LoginError
from promptrail.agent.client import AgentSession, SecurityException
from promptrail.agent.commands import _continue
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.model_client import ModelClient
from promptrail.agent.state import lease, load
from promptrail.config import get_token, load_settings

app = typer.Typer(no_args_is_help=True, help="Review exact pending actions with reviewer permission.")


def _request(client, method, url, **kwargs):
    with client.stream(method, url, **kwargs) as response:
        if response.status_code != 200:
            raise LoginError("REVIEW_DENIED" if response.status_code in {401, 403} else "REVIEW_UNAVAILABLE")
        data = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            data.extend(chunk)
            if len(data) > 1048576:
                raise LoginError("INVALID_REVIEW_RESPONSE")
        return json.loads(data)


def _paired_login(settings):
    """Start both challenges before waiting; keep both credentials in memory."""
    with DeviceLogin(settings) as caller, DeviceLogin(settings) as reviewer:
        caller_challenge = caller.begin(scopes=["openid", "jev:evaluate", "jev:tools:call"])
        reviewer_challenge = reviewer.begin(scopes=["openid", "jev:evaluate", "jev:approvals:write"])
        for label, challenge in [("caller", caller_challenge), ("reviewer", reviewer_challenge)]:
            typer.echo(f"Human intervention required: sign in with the {label} account in a separate browser context.")
            typer.echo(challenge.verification_uri_complete or challenge.verification_uri)
            typer.echo(f"{label.capitalize()} device code: {challenge.user_code}")
        caller_token = caller.poll(caller_challenge)
        reviewer_token = reviewer.poll(reviewer_challenge)
        caller_identity = caller.verify(caller_token)
        reviewer_identity = reviewer.verify(reviewer_token)
        if (caller_identity.issuer, caller_identity.subject) == (reviewer_identity.issuer, reviewer_identity.subject):
            raise LoginError("SEPARATE_REVIEWER_REQUIRED")
        return caller_token, reviewer_token


def _validate_action(item, checkpoint):
    """A combined review may only address the checkpoint's next exact action."""
    request = checkpoint.requests[checkpoint.next_index]
    details = {"content": request.content, "source_type": request.source_type, "tool_args": request.tool_args}
    if (item.get("request_id") != request.request_id or item.get("requester") != checkpoint.agent_id
            or item.get("proposed_tool") != request.proposed_tool or item.get("action_details") != details):
        raise SecurityException("REVIEW_CHECKPOINT_MISMATCH")


def _review_resume(settings, checkpoint_path, checkpoint, expected_hash=None):
    if isinstance(checkpoint, ConversationCheckpoint):
        with ModelClient(checkpoint) as model:
            return _review_resume_ready(settings, checkpoint_path, checkpoint, expected_hash, model)
    return _review_resume_ready(settings, checkpoint_path, checkpoint, expected_hash)


def _review_resume_ready(settings, checkpoint_path, checkpoint, expected_hash=None, model=None):
    caller_token, reviewer_token = _paired_login(settings)
    with AgentSession(settings, caller_token.get_secret_value()) as session, httpx.Client(
            timeout=settings.timeout, trust_env=False, follow_redirects=False,
            headers={"Authorization": "Bearer " + reviewer_token.get_secret_value()}) as client:
        session.exchange(checkpoint.tools, checkpoint.agent_id)
        request = checkpoint.requests[checkpoint.next_index]
        if session.approval_status(request.request_id) != "pending":
            raise SecurityException("REVIEW_NOT_PENDING")
        queue = _request(client, "GET", settings.gateway_url + "/pending")
        pending = [item for item in queue["pending"] if item["request_id"] == request.request_id]
        if len(pending) != 1:
            raise SecurityException("REVIEW_NOT_PENDING")
        item = pending[0]
        _validate_action(item, checkpoint)
        digest = item["action_hash"]
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise LoginError("INVALID_REVIEW_RESPONSE")
        if expected_hash is not None and digest != expected_hash:
            raise SecurityException("REVIEW_HASH_MISMATCH")
        text = json.dumps(item, indent=2)
        typer.echo("".join(c for c in text if c.isprintable() or c == "\n"))
        approved = typer.confirm(f"Approve exact action {request.request_id} ({digest}) and resume?", default=False)
        # Refuse a changed local plan rather than applying approval to fresh context.
        if load(checkpoint_path) != checkpoint:
            raise SecurityException("CHECKPOINT_CHANGED")
        if session.approval_status(request.request_id) != "pending":
            raise SecurityException("REVIEW_NOT_PENDING")
        action = "approve" if approved else "reject"
        result = _request(client, "POST", settings.gateway_url + f"/{action}/{request.request_id}",
                          json={"reason": "Explicit CLI review of action hash " + digest})
        if result.get("status") != ("approved" if approved else "rejected"):
            raise LoginError("INVALID_REVIEW_RESPONSE")
        typer.echo("Review recorded: " + result["status"])
        if approved:
            if session.approval_status(request.request_id) != "approved":
                raise SecurityException("APPROVAL_NOT_VALID")
            _continue(checkpoint, checkpoint_path, settings, session, model)
            typer.echo("Agent proposals completed. Credentials were not persisted.")


@app.command()
def review(
    gateway_url: Annotated[str | None, typer.Option("--gateway-url")] = None,
    login: Annotated[bool, typer.Option("--login", help="Browser reviewer login without credential persistence.")] = False,
    request_id: Annotated[str | None, typer.Option("--request-id")] = None,
    resume_checkpoint: Annotated[Path | None, typer.Option("--resume-checkpoint", help="Authenticate both identities before review, then immediately resume the exact checkpoint.")] = None,
    expected_hash: Annotated[str | None, typer.Option("--expected-hash", help="Refuse a changed action fingerprint; requires --request-id. Confirmation is still required.")] = None,
):
    try:
        if expected_hash is not None and (not request_id or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)):
            raise SecurityException("INVALID_REVIEW_HASH")
        if resume_checkpoint is not None:
            with lease(resume_checkpoint):
                checkpoint = load(resume_checkpoint)
                settings = load_settings(gateway_url or checkpoint.gateway_url)
                if (not login or settings.gateway_url != checkpoint.gateway_url or not checkpoint.agent_id
                        or checkpoint.status != "approval_required" or checkpoint.next_index >= len(checkpoint.requests)
                        or (request_id is not None and request_id != checkpoint.requests[checkpoint.next_index].request_id)):
                    raise SecurityException("INVALID_REVIEW_RESUME")
                _review_resume(settings, resume_checkpoint, checkpoint, expected_hash)
            return
        settings = load_settings(gateway_url)
        if login:
            with DeviceLogin(settings) as flow:
                challenge = flow.begin(scopes=["openid", "jev:evaluate", "jev:approvals:write"])
                typer.echo("Human intervention required: sign in with the reviewer account.")
                typer.echo(challenge.verification_uri_complete or challenge.verification_uri)
                typer.echo("Device code: " + challenge.user_code)
                credential = flow.poll(challenge)
                flow.verify(credential)
                token = credential.get_secret_value()
        else:
            token = get_token(settings.gateway_url)
            if not token:
                raise LoginError("LOGIN_REQUIRED")
        with httpx.Client(timeout=settings.timeout, trust_env=False, follow_redirects=False,
                          headers={"Authorization": "Bearer " + token}) as client:
            queue = _request(client, "GET", settings.gateway_url + "/pending")
            pending = queue["pending"]
            if request_id:
                pending = [item for item in pending if item["request_id"] == request_id]
            if not pending:
                typer.echo("No matching pending actions.")
            for item in pending:
                rid, digest = item["request_id"], item["action_hash"]
                # Bound identifiers prevent a response from changing the destination path.
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", rid) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise LoginError("INVALID_REVIEW_RESPONSE")
                if expected_hash is not None and digest != expected_hash:
                    raise SecurityException("REVIEW_HASH_MISMATCH")
                text = json.dumps(item, indent=2)
                typer.echo("".join(c for c in text if c.isprintable() or c == "\n"))
                approved = typer.confirm(f"Approve exact action {rid} ({digest})?", default=False)
                action = "approve" if approved else "reject"
                result = _request(client, "POST", settings.gateway_url + f"/{action}/{rid}",
                                  json={"reason": "Explicit CLI review of action hash " + digest})
                typer.echo("Review recorded: " + result["status"])
    except (LoginError, SecurityException) as exc:
        typer.echo("Review stopped: " + exc.code, err=True)
        raise typer.Exit(2)
    except (httpx.HTTPError, ValueError, OSError, KeyError, TypeError):
        typer.echo("Review stopped: unavailable or invalid response.", err=True)
        raise typer.Exit(2)
