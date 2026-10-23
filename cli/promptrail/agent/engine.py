"""Model proposals pass through the gateway; saved tool calls are never replayed."""
import json

import typer

from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import Message, SYSTEM_PROMPT, arguments
from promptrail.agent.definitions import definitions
from promptrail.agent.models import ToolCallRequest
from promptrail.agent.state import save
from promptrail.audit import append_event
from promptrail.models import EvaluationRequest, ExecutionRequirement, PolicyAction

WITHHELD = "[Content withheld by the security gateway.]"


def _screen(content, settings, session, source_type="retrieved_content"):
    if not content:
        return True
    if len(content) > 50000:
        return False
    result = session.evaluate(EvaluationRequest(content=content, source_type=source_type))
    append_event(settings.audit_path, result)
    return (result.status == "evaluated" and result.policy_action == PolicyAction.ALLOW
            and result.execution_requirement == ExecutionRequirement.NONE)


def _safe_output(output, settings, session):
    text = output if isinstance(output, str) else json.dumps(output, allow_nan=False, sort_keys=True)
    return text if _screen(text, settings, session) else WITHHELD


def _model_history(checkpoint, settings, session):
    messages = []
    for message in checkpoint.messages:
        item = message.wire()
        if message.role not in {"system", "user"}:
            if message.content and not _screen(message.content, settings, session):
                item["content"] = WITHHELD
            for call in item.get("tool_calls", []):
                if not _screen(call["function"]["arguments"], settings, session):
                    call["function"]["arguments"] = "{}"
        messages.append(item)
    return messages


def _pending(checkpoint, checkpoint_path, settings, session):
    for index in range(checkpoint.next_index, len(checkpoint.requests)):
        request = checkpoint.requests[index]
        checkpoint.status = "uncertain"
        save(checkpoint_path, checkpoint)
        result = session.call(request)
        append_event(settings.audit_path, result.evaluation, outcome=result.outcome,
                     reason_code=result.reason_code, executor_mode=result.executor_mode)
        typer.echo(f"{request.request_id}: {result.outcome} ({result.reason_code}; {result.executor_mode})")
        if result.outcome == "REQUIRE_APPROVAL":
            checkpoint.status = "approval_required"
            save(checkpoint_path, checkpoint)
            typer.echo(f"Human intervention required: review exact action {request.request_id}.")
            typer.echo(f"Context saved to {checkpoint_path}. Resume with: jev agent resume {checkpoint_path}")
            raise typer.Exit(1)
        if result.outcome in {"EXECUTION_UNKNOWN", "UNAVAILABLE"}:
            raise SecurityException("MANUAL_RECONCILIATION_REQUIRED")
        output = (_safe_output(result.tool_output, settings, session) if result.outcome == "EXECUTED"
                  and result.tool_output is not None else "Tool result: " + result.reason_code)
        checkpoint.messages.append(Message(role="tool", tool_call_id=checkpoint.tool_call_ids[index], content=output))
        checkpoint.next_index = index + 1
        checkpoint.status = "ready"
        save(checkpoint_path, checkpoint)


def run(checkpoint, checkpoint_path, settings, session, model):
    if checkpoint.status in {"uncertain", "complete"}:
        raise SecurityException("MANUAL_RECONCILIATION_REQUIRED" if checkpoint.status == "uncertain" else "CHECKPOINT_COMPLETE")
    if not _screen(checkpoint.prompt, settings, session, "direct_prompt"):
        raise SecurityException("PROMPT_NOT_ALLOWED")
    if not checkpoint.messages:
        checkpoint.messages = [Message(role="system", content=SYSTEM_PROMPT), Message(role="user", content=checkpoint.prompt)]
        save(checkpoint_path, checkpoint)
    hints = definitions(checkpoint.tools)
    while True:
        _pending(checkpoint, checkpoint_path, settings, session)
        if checkpoint.iteration >= checkpoint.max_iterations:
            checkpoint.messages.append(Message(role="assistant", content="Agent reached the configured iteration limit."))
            checkpoint.status = "complete"
            save(checkpoint_path, checkpoint)
            typer.echo("Agent reached the configured iteration limit.")
            return
        message = model.complete(_model_history(checkpoint, settings, session), hints)
        if getattr(model, "last_endpoint", None) == "fallback":
            typer.echo("Primary model unavailable; generated a response with the configured fallback.")
        # Validate the entire batch before persisting or dispatching any proposal.
        known = set(checkpoint.tool_call_ids)
        proposals = []
        for call in message.tool_calls:
            if call.id in known or call.function.name not in checkpoint.tools:
                raise SecurityException("INVALID_MODEL_PROPOSAL")
            known.add(call.id)
            try:
                proposals.append(ToolCallRequest(content=checkpoint.prompt, proposed_tool=call.function.name,
                                                 tool_args=arguments(call.function.arguments)))
            except (ValueError, TypeError):
                raise SecurityException("INVALID_MODEL_PROPOSAL") from None
        if len(checkpoint.requests) + len(proposals) > 50:
            raise SecurityException("AGENT_ACTION_LIMIT")
        checkpoint.iteration += 1
        checkpoint.last_model_endpoint = getattr(model, "last_endpoint", None)
        if message.tool_calls:
            checkpoint.messages.append(message)
            checkpoint.requests.extend(proposals)
            checkpoint.tool_call_ids.extend(call.id for call in message.tool_calls)
            save(checkpoint_path, checkpoint)
        else:
            text = message.content or ""
            if not _screen(text, settings, session):
                message = Message(role="assistant", content=WITHHELD)
            checkpoint.messages.append(message)
            checkpoint.status = "complete"
            save(checkpoint_path, checkpoint)
            typer.echo("".join(char for char in message.content if char.isprintable() or char == "\n"))
            return
