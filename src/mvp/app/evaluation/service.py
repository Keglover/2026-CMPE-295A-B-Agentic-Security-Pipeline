"""Evaluate content and explicit tool arguments without planner or dispatch."""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.assessment import assess_content
from app.evaluation.models import EvaluationRequest, EvaluationResponse, ExecutionRequirement
from app.gateway import gateway
from app.gateway.domain_validation import validate_tool_urls
from app.gateway.validation import ArgumentValidationError, validate_tool_args
from app.models import PipelineRequest, PolicyAction
from app.policy import engine as policy_engine

_log = logging.getLogger(__name__)


def _hash_request(request: EvaluationRequest) -> str:
    # Bind the hash to intent and arguments, never persist their raw values.
    material = json.dumps({"content": request.content,
                           "source_type": request.source_type,
                           "proposed_tool": request.proposed_tool,
                           "tool_args": request.tool_args}, sort_keys=True, allow_nan=False)
    return hashlib.sha256(material.encode()).hexdigest()


def unavailable(request_id: str, code: str, *, content_hash: str | None = None,
                trace_id: str | None = None) -> EvaluationResponse:
    return EvaluationResponse(
        schema_version="1", request_id=request_id, trace_id=trace_id or str(uuid4()),
        status="unavailable", policy_action=PolicyAction.BLOCK, risk_score=None,
        execution_requirement=ExecutionRequirement.DENIED, execution_authorized=False,
        reason_code=code, reason="Evaluation unavailable; execution is not authorized.",
        content_hash=content_hash or hashlib.sha256(b"").hexdigest(),
        policy_version=policy_engine.POLICY_VERSION, registry_version=gateway.REGISTRY_VERSION)


def _record(result: EvaluationResponse) -> None:
    default = Path(__file__).resolve().parents[2] / "audit_logs" / "evaluation.ndjson"
    path = Path(os.getenv("EVALUATION_AUDIT_LOG_PATH", str(default)))
    path.parent.mkdir(parents=True, exist_ok=True)
    # Omit free-text reasons, content, arguments, context, and credentials.
    event = result.model_dump(mode="json", exclude={"reason"})
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def evaluate(request: EvaluationRequest) -> EvaluationResponse:
    trace_id = str(uuid4())
    content_hash = None
    try:
        content_hash = _hash_request(request)
        registry = gateway._registry
        if "fallback" in gateway.REGISTRY_VERSION or "fallback" in policy_engine.POLICY_VERSION:
            raise ValueError("Security configuration unavailable")
        if request.proposed_tool:
            validate_tool_args(request.proposed_tool, request.tool_args, registry)
        # Score tool strings as untrusted content too; context is advisory only.
        strings = [value for value in request.tool_args.values() if isinstance(value, str)]
        assessment_request = PipelineRequest(
            request_id=request.request_id, source_type=request.source_type,
            content="\n".join([request.content, *strings]))
        _, risk, policy = assess_content(assessment_request, fail_on_policy_error=True)
        requirement = ExecutionRequirement.NONE
        code = "POLICY_" + policy.policy_action.value
        reason = "Assessment complete; no execution authorization is issued."
        action = policy.policy_action
        if action in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}:
            requirement = ExecutionRequirement.DENIED
        elif action == PolicyAction.REQUIRE_APPROVAL:
            requirement = ExecutionRequirement.REQUIRE_APPROVAL
        elif request.proposed_tool == "execute_command":
            requirement = ExecutionRequirement.REQUIRE_APPROVAL
            code = "COMMAND_APPROVAL_REQUIRED"
            reason = "Command execution requires human approval through the gateway."
        elif (request.proposed_tool == "summarize"
              and gateway._SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL
              and len(request.tool_args["text"]) > gateway._SUMMARIZE_LOCAL_MAX_CHARS):
            requirement = ExecutionRequirement.REQUIRE_APPROVAL
            code = "SUMMARY_APPROVAL_REQUIRED"
        if request.proposed_tool and any(
            not item.is_approved for item in validate_tool_urls(request.tool_args)
        ):
            action, requirement, code = PolicyAction.BLOCK, ExecutionRequirement.DENIED, "DOMAIN_DENIED"
            reason = "Tool URL is outside the configured domain policy."
        result = EvaluationResponse(
            schema_version="1", request_id=request.request_id, trace_id=trace_id,
            status="evaluated", policy_action=action, risk_score=risk.risk_score,
            execution_requirement=requirement, execution_authorized=False,
            reason_code=code, reason=reason, content_hash=content_hash,
            policy_version=policy_engine.POLICY_VERSION, registry_version=gateway.REGISTRY_VERSION)
    except ArgumentValidationError as error:
        result = unavailable(request.request_id, error.code, content_hash=content_hash,
                             trace_id=trace_id).model_copy(update={
            "status": "rejected", "reason": "Tool or arguments failed registry validation."})
    except Exception:
        _log.error("Evaluation unavailable request_id=%s trace_id=%s", request.request_id, trace_id)
        result = unavailable(request.request_id, "ASSESSMENT_UNAVAILABLE",
                             content_hash=content_hash, trace_id=trace_id)
    return persist_result(result)


def persist_result(result: EvaluationResponse) -> EvaluationResponse:
    try:
        _record(result)
    except Exception:
        _log.error("Evaluation audit unavailable trace_id=%s", result.trace_id)
        return unavailable(result.request_id, "AUDIT_UNAVAILABLE",
                           content_hash=result.content_hash, trace_id=result.trace_id)
    return result
