"""Reassess executable arguments; assessment results cannot authorize dispatch."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from app.evaluation.models import EvaluationRequest, ExecutionRequirement
from app.evaluation.service import evaluate, unavailable
from app.execution.models import ToolCallResponse
from app.gateway import gateway
from app.models import GatewayDecision, GatewayResult, PipelineRequest, PolicyAction, PolicyResult
from app.policy.pii_detector import redact


def _record(phase, request, evaluation, result=None):
    path = Path(os.getenv("EXECUTION_AUDIT_LOG_PATH", str(
        Path(__file__).resolve().parents[2] / "audit_logs" / "execution.ndjson")))
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), "phase": phase,
             "request_id": request.request_id, "trace_id": evaluation.trace_id,
             "requester": request.agent_id or "anonymous", "tool": request.proposed_tool,
             "content_hash": evaluation.content_hash, "policy_action": evaluation.policy_action.value,
             "policy_version": evaluation.policy_version, "registry_version": evaluation.registry_version}
    if result:
        event.update(decision=result.gateway_decision.value, reason_code=result.reason_code)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def execute_action(request: PipelineRequest, prior_policy: PolicyResult | None = None):
    """Shared by /tools/call and the /pipeline adapter. Never trust caller policy."""
    def denied(code):
        return GatewayResult(request_id=request.request_id, gateway_decision=GatewayDecision.DENIED,
                             reason_code=code, decision_reason=("Tool is not on the allowlist."
                             if code in {"TOOL_NOT_ALLOWED", "UNKNOWN_TOOL"} else "Execution denied by the gateway."))
    try:
        wire = EvaluationRequest(request_id=request.request_id, content=request.content,
                                 source_type=request.source_type.value, proposed_tool=request.proposed_tool,
                                 tool_args=request.tool_args or {})
    except ValidationError:
        return unavailable("invalid-request", "INVALID_REQUEST"), denied("INVALID_REQUEST")
    evaluation = evaluate(wire)
    if evaluation.status != "evaluated":
        return evaluation, denied(evaluation.reason_code)
    action = evaluation.policy_action
    if prior_policy and prior_policy.policy_action in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}:
        action = prior_policy.policy_action
    elif prior_policy and prior_policy.policy_action == PolicyAction.REQUIRE_APPROVAL:
        if action not in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}:
            action = PolicyAction.REQUIRE_APPROVAL
    policy = PolicyResult(request_id=request.request_id, policy_action=action,
                          policy_reason=evaluation.reason_code,
                          risk_score=evaluation.risk_score,
                          requires_approval=action == PolicyAction.REQUIRE_APPROVAL)
    # Redact the actual tool payload, not only the descriptive prompt.
    if action == PolicyAction.SANITIZE:
        args = {key: redact(value)[0] if isinstance(value, str) else value
                for key, value in (request.tool_args or {}).items()}
        if request.proposed_tool == "execute_command" and args != request.tool_args:
            return evaluation, denied("COMMAND_SANITIZATION_DENIED")
        # Intent stays exact for approval binding; only executable arguments are transformed.
        request = request.model_copy(update={"tool_args": args})
    try:
        _record("prepared", request, evaluation)
    except Exception:
        return unavailable(wire.request_id, "AUDIT_UNAVAILABLE", content_hash=evaluation.content_hash,
                           trace_id=evaluation.trace_id), denied("AUDIT_UNAVAILABLE")
    result = gateway.mediate(request, policy)
    try:
        _record("completed", request, evaluation, result)
    except Exception:
        # Preserve the fact that execution may already have happened; never retry automatically.
        result = result.model_copy(update={"reason_code": "EXECUTION_AUDIT_UNAVAILABLE"})
    return evaluation, result


def response_for(evaluation, result):
    outcome = "DENIED"
    if result.reason_code in {"EXECUTION_AUDIT_UNAVAILABLE", "EXECUTION_FAILED", "EXECUTION_TIMEOUT"}:
        outcome = "EXECUTION_UNKNOWN"
    elif evaluation.status == "unavailable":
        outcome = "UNAVAILABLE"
    elif result.gateway_decision == GatewayDecision.EXECUTED:
        outcome = "EXECUTED"
    elif result.reason_code == "APPROVAL_REQUIRED":
        outcome = "REQUIRE_APPROVAL"
    return ToolCallResponse(evaluation=evaluation, outcome=outcome,
                            reason_code=result.reason_code or "EXECUTION_DENIED",
                            executor_mode=gateway._executor_mode,
                            tool_output=result.tool_output if outcome == "EXECUTED" else None)
