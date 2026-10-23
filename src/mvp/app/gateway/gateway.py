"""
Tool Gateway module — Deliverable A: Tool Proxy.

Project Plan Ref: Phase 3 (Core Development: Tool Proxy)

Responsibility: Act as the ONLY execution path for tool calls.
No tool call may bypass this module — that is the hard enforcement boundary.

On every call the gateway checks:
1. Tool is on the allowlist.
2. Required arguments are present and pass schema validation.
3. The policy action permits execution (ALLOW or SANITIZE only).
4. Rate limit is not exceeded.
5. Circuit breaker allows the request.

If any check fails the gateway returns DENIED with a reason code.
If all checks pass it routes to the selected executor set and returns the result.

Executor selection (controlled by REAL_TOOLS env var):
REAL_TOOLS=false (default) → gateway_mock.py  — safe stubs, no side effects
REAL_TOOLS=true            → sandbox workers  — real network/FS calls via sandbox HTTP boundary
                            with network restrictions enabled.
"""

from __future__ import annotations

import logging as _logging
import os
from typing import Any

from app.approval.workflow import ApprovalStatus, approval_manager
from app.gateway.circuit_breaker import circuit_registry
from app.gateway.executor_policy import run_with_policy
from app.models import (
    GatewayDecision,
    GatewayResult,
    PolicyAction,
    PolicyResult,
    PipelineRequest,
)
from app.policy.config_loader import load_tool_registry
from app.gateway.rate_limiter import rate_limiter

_log = _logging.getLogger("gateway")

# ---------------------------------------------------------------------------
# Tool schema registry — loaded from config/tool_registry.yaml (Task 3.3)
# ---------------------------------------------------------------------------

_registry = load_tool_registry()
_tools_config: dict = _registry.get("tools", {})

_sandbox_config: dict = _registry.get("sandbox", {})
SANDBOX_ENABLED: bool = bool(_sandbox_config.get("enabled", False))

# Build TOOL_SCHEMAS in the same format the rest of the code expects:
#   { "tool_name": ["required_arg1", "required_arg2", ...] }
# Only include enabled tools.
TOOL_SCHEMAS: dict[str, list[str]] = {
    name: info.get("required_args", [])
    for name, info in _tools_config.items()
    if info.get("enabled", True)
}

TOOL_ALLOWLIST: set[str] = set(TOOL_SCHEMAS.keys())

# Domain allowlist for fetch_url (consumed by gateway_real.py)
DOMAIN_ALLOWLIST: list[str] = _registry.get("domain_allowlist", ["example.com"])

REGISTRY_VERSION: str = str(_registry.get("version", "unknown"))


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_summarize_cfg: dict[str, Any] = _sandbox_config.get("summarize", {})
_SUMMARIZE_LOCAL_MAX_CHARS: int = _safe_int(
    os.getenv(
        "SUMMARIZE_LOCAL_MAX_CHARS",
        _summarize_cfg.get("local_max_chars", 8000),
    ),
    8000,
)
_SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL: bool = str(
    _summarize_cfg.get("require_approval_above_local_max", True)
).strip().lower() in {"1", "true", "yes", "on"}

_EXECUTE_COMMAND_ALWAYS_REQUIRES_APPROVAL: bool = True

# Policy actions that permit execution
EXECUTABLE_ACTIONS: set[PolicyAction] = {PolicyAction.ALLOW, PolicyAction.SANITIZE}

_log.info(
    "Tool registry loaded (v%s): %s",
    REGISTRY_VERSION, sorted(TOOL_ALLOWLIST),
)
_log.info(
    "Summarize local_max_chars=%d oversize_requires_approval=%s",
    _SUMMARIZE_LOCAL_MAX_CHARS,
    _SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL,
)

# ---------------------------------------------------------------------------
# Executor selection — controlled at startup via environment variable.
# ---------------------------------------------------------------------------

_USE_REAL_TOOLS: bool = os.getenv("REAL_TOOLS", "false").strip().lower() == "true"

if _USE_REAL_TOOLS:
    if not SANDBOX_ENABLED:
        raise RuntimeError(
            "REAL_TOOLS=true requires sandbox.enabled=true so real tools run only in the sandbox."
        )
    from app.gateway.sandbox_client import build_sandbox_executor

    _TOOL_EXECUTORS = {
        tool_name: build_sandbox_executor(tool_name)
        for tool_name in TOOL_ALLOWLIST
    }
    _executor_mode = "SANDBOX"
else:
    from app.gateway.gateway_mock import EXECUTORS as _TOOL_EXECUTORS
    _executor_mode = "MOCK"

_log.info(
    "Tool executor mode: %s (set REAL_TOOLS=true to activate real tools)",
    _executor_mode,
)


# ---------------------------------------------------------------------------
# Gateway entry point
# ---------------------------------------------------------------------------


def action_fingerprint(request: PipelineRequest, policy: PolicyResult) -> str:
    """Bind approval to exact intent, executable payload, identity and configuration."""
    import hashlib
    import json
    from app.policy.engine import POLICY_VERSION
    material = {"content": request.content, "source_type": request.source_type.value,
                "tool": request.proposed_tool, "args": request.tool_args or {},
                "requester": request.agent_id or "anonymous", "policy": policy.policy_action.value,
                "policy_version": POLICY_VERSION, "registry_version": REGISTRY_VERSION}
    return hashlib.sha256(json.dumps(material, sort_keys=True, allow_nan=False).encode()).hexdigest()


def mediate(request: PipelineRequest, policy: PolicyResult) -> GatewayResult:
    """Validate, bind approval, enforce quotas, then dispatch through one boundary."""
    from app.gateway.validation import ArgumentValidationError, validate_tool_args
    from app.gateway.domain_validation import validate_tool_urls
    req_id = request.request_id
    agent_id = request.agent_id or "anonymous"
    tool_name = request.proposed_tool
    tool_args = request.tool_args or {}

    def deny(code: str, reason: str) -> GatewayResult:
        return GatewayResult(request_id=req_id, gateway_decision=GatewayDecision.DENIED,
                             reason_code=code, decision_reason=reason)

    if not tool_name:
        return deny("TOOL_REQUIRED", "No tool proposed in request.")
    if tool_name not in TOOL_ALLOWLIST:
        return deny("TOOL_NOT_ALLOWED", "Tool is not on the allowlist.")
    try:
        validate_tool_args(tool_name, tool_args, _registry)
        if any(not item.is_approved for item in validate_tool_urls(tool_args)):
            return deny("DOMAIN_DENIED", "Tool URL is outside the configured domain policy.")
        fingerprint = action_fingerprint(request, policy)
    except ArgumentValidationError as exc:
        return deny(exc.code, "Missing required argument." if exc.code == "MISSING_ARGUMENT"
                    else "Tool arguments are invalid or outside registry constraints.")
    except Exception:
        return deny("CONFIGURATION_UNAVAILABLE", "Security configuration unavailable.")
    if policy.policy_action not in EXECUTABLE_ACTIONS | {PolicyAction.REQUIRE_APPROVAL}:
        return deny("POLICY_DENIED", f"Policy action '{policy.policy_action.value}' denies execution.")

    needs_approval = (policy.policy_action == PolicyAction.REQUIRE_APPROVAL
                      or tool_name == "execute_command"
                      or (tool_name == "summarize" and _SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL
                          and len(tool_args["text"]) > _SUMMARIZE_LOCAL_MAX_CHARS))
    # An existing approval must never be transferable, even if policy now permits the action.
    record = approval_manager.get_status(req_id)
    if record and (record.action_hash != fingerprint or record.requester != agent_id):
        return deny("APPROVAL_ACTION_MISMATCH", "Request ID is already bound to a different action or caller.")
    if record and record.status == ApprovalStatus.CONSUMED:
        return deny("APPROVAL_CONSUMED", "Approval has already been used.")
    if needs_approval:
        if record is None:
            try:
                record = approval_manager.submit(req_id, policy.risk_score or 0, [], tool_name,
                                                 action_hash=fingerprint, requester=agent_id,
                                                 action_details={"content": request.content,
                                                                 "source_type": request.source_type.value,
                                                                 "tool_args": tool_args})
            except ValueError:
                return deny("APPROVAL_ACTION_MISMATCH", "Concurrent request ID conflicts with this action.")
        if record.status != ApprovalStatus.APPROVED:
            if record.status == ApprovalStatus.PENDING:
                return deny("APPROVAL_REQUIRED", "Execution requires human approval; request queued. "
                            f"Use POST /approve/{req_id} then replay this exact request.")
            return deny("APPROVAL_NOT_VALID", f"Approval status '{record.status.value}' denies execution.")

    if not rate_limiter.check(tool_name, agent_id=agent_id):
        return deny("RATE_LIMITED", f"Rate limit exceeded for agent '{agent_id}' on tool '{tool_name}'.")
    cb = circuit_registry.get(tool_name)
    if not cb.allow_request():
        return deny("CIRCUIT_OPEN", "Circuit breaker OPEN; tool backend unavailable.")
    if needs_approval and not approval_manager.consume(req_id, fingerprint, agent_id):
        return deny("APPROVAL_NOT_VALID", "Approval expired or was already consumed by another dispatch.")

    try:
        executor = _TOOL_EXECUTORS[tool_name]
        if _USE_REAL_TOOLS:
            from app.auth.capabilities import issue_runner
            from app.gateway.sandbox_client import build_sandbox_executor
            capability = issue_runner(request, policy, request.request_id)
            executor = build_sandbox_executor(tool_name, capability=capability)
        output = run_with_policy(tool_name, executor, tool_args, max_attempts=1 if needs_approval else None)
        cb.record_success()
    except Exception as exc:
        cb.record_failure()
        _log.warning("Tool execution failed tool=%s request_id=%s error_type=%s",
                     tool_name, req_id, type(exc).__name__)
        return deny("EXECUTION_TIMEOUT" if isinstance(exc, TimeoutError) else "EXECUTION_FAILED",
                    "Tool timed out; execution outcome may be uncertain." if isinstance(exc, TimeoutError)
                    else "Tool execution failed; execution outcome may be uncertain.")
    return GatewayResult(request_id=req_id, gateway_decision=GatewayDecision.EXECUTED,
                         reason_code="EXECUTED", decision_reason=f"Tool executed via {_executor_mode} executor.",
                         tool_output=output)
