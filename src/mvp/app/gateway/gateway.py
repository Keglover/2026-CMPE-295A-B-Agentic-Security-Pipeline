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


def mediate(
    request: PipelineRequest,
    policy: PolicyResult,
) -> GatewayResult:
    """
    Evaluate a proposed tool call and either execute or deny it.

    Checks: tool proposed → allowlist → policy gate → rate limit →
            circuit breaker → schema → approval → execute.
    """
    req_id = request.request_id
    agent_id = (request.agent_id or "anonymous").strip() or "anonymous"
    tool_name = request.proposed_tool
    tool_args = request.tool_args or {}

    # --- No tool proposed ---
    if not tool_name:
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason="No tool proposed in request.",
        )

    # --- Allowlist check ---
    if tool_name not in TOOL_ALLOWLIST:
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Tool '{tool_name}' is not on the allowlist. "
                f"Allowed tools: {sorted(TOOL_ALLOWLIST)}."
            ),
        )

    # --- Policy gate: only ALLOW and SANITIZE permit execution ---
    if policy.policy_action not in EXECUTABLE_ACTIONS:
        # If REQUIRE_APPROVAL, submit to approval queue instead of flat deny
        if policy.policy_action == PolicyAction.REQUIRE_APPROVAL:
            approval_record = approval_manager.get_status(req_id)
            if approval_record is None:
                approval_manager.submit(
                    request_id=req_id,
                    risk_score=0,  # actual score is in policy_reason text
                    risk_categories=[],
                    proposed_tool=tool_name,
                )
                return GatewayResult(
                    request_id=req_id,
                    gateway_decision=GatewayDecision.DENIED,
                    decision_reason=(
                        f"Awaiting human approval. Request '{req_id}' has been "
                        f"queued. Use POST /approve/{req_id} to approve."
                    ),
                )

            if approval_record.status == ApprovalStatus.APPROVED:
                _log.info("Approved replay request_id=%s tool=%s", req_id, tool_name)
            elif approval_record.status == ApprovalStatus.PENDING:
                return GatewayResult(
                    request_id=req_id,
                    gateway_decision=GatewayDecision.DENIED,
                    decision_reason=(
                        f"Awaiting human approval. Request '{req_id}' is still pending. "
                        f"Use POST /approve/{req_id} to approve."
                    ),
                )
            else:
                return GatewayResult(
                    request_id=req_id,
                    gateway_decision=GatewayDecision.DENIED,
                    decision_reason=(
                        f"Request '{req_id}' approval status is "
                        f"'{approval_record.status.value}', so execution is denied."
                    ),
                )
        else:
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Policy action '{policy.policy_action.value}' does not permit "
                    f"tool execution. Reason: {policy.policy_reason}"
                ),
            )

    # --- execute_command: always require explicit human approval ---
    if tool_name == "execute_command" and _EXECUTE_COMMAND_ALWAYS_REQUIRES_APPROVAL:
        approval_record = approval_manager.get_status(req_id)
        if approval_record is None:
            approval_manager.submit(
                request_id=req_id,
                risk_score=0,
                risk_categories=["EXECUTE_COMMAND"],
                proposed_tool=tool_name,
            )
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Command execution always requires human approval. "
                    f"Request '{req_id}' has been queued. Use POST /approve/{req_id} to approve."
                ),
            )

        if approval_record.status == ApprovalStatus.APPROVED:
            _log.info("execute_command approved request_id=%s", req_id)
        elif approval_record.status == ApprovalStatus.PENDING:
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Awaiting human approval. Request '{req_id}' is still pending. "
                    f"Use POST /approve/{req_id} to approve."
                ),
            )
        else:
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Request '{req_id}' approval status is "
                    f"'{approval_record.status.value}'."
                ),
            )

    # --- Argument schema check ---
    required_args = TOOL_SCHEMAS[tool_name]
    missing = [arg for arg in required_args if arg not in tool_args]
    if missing:
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Tool '{tool_name}' is missing required argument(s): {missing}."
            ),
        )

    # --- Summarize oversize guard: queue for human approval before cloud path ---
    if (
        tool_name == "summarize"
        and _SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL
        and len(str(tool_args.get("text", ""))) > _SUMMARIZE_LOCAL_MAX_CHARS
    ):
        approval_record = approval_manager.get_status(req_id)
        if approval_record is None:
            approval_manager.submit(
                request_id=req_id,
                risk_score=0,
                risk_categories=["SUMMARIZE_OVERSIZE"],
                proposed_tool=tool_name,
            )
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Summarize input exceeded local threshold of "
                    f"{_SUMMARIZE_LOCAL_MAX_CHARS} chars and requires human approval. "
                    f"Request '{req_id}' has been queued. Use POST /approve/{req_id} to approve."
                ),
            )
        if approval_record.status == ApprovalStatus.APPROVED:
            _log.info("Approved oversize summarize replay request_id=%s", req_id)
        elif approval_record.status == ApprovalStatus.PENDING:
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Summarize oversize request '{req_id}' is still pending approval. "
                    f"Use POST /approve/{req_id} to approve."
                ),
            )
        else:
            return GatewayResult(
                request_id=req_id,
                gateway_decision=GatewayDecision.DENIED,
                decision_reason=(
                    f"Request '{req_id}' approval status is "
                    f"'{approval_record.status.value}', so execution is denied."
                ),
            )

    # --- Rate limit check (Task 3.20) ---
    if not rate_limiter.check(tool_name, agent_id=agent_id):
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Rate limit exceeded for agent '{agent_id}' on tool "
                f"'{tool_name}'. Try again later."
            ),
        )

    # --- Circuit breaker check (Task 3.21) ---
    cb = circuit_registry.get(tool_name)
    if not cb.allow_request():
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Circuit breaker OPEN for tool '{tool_name}'. "
                f"Backend is experiencing failures; request rejected to prevent cascade."
            ),
        )

    # --- All checks passed: route to executor (with timeout + retry policy) ---
    executor = _TOOL_EXECUTORS[tool_name]
    try:
        output = run_with_policy(tool_name, executor, tool_args)
        cb.record_success()
    except TimeoutError as exc:
        cb.record_failure()
        _log.warning("Executor timed out for tool '%s': %s", tool_name, exc)
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=str(exc),
        )
    except Exception as exc:
        cb.record_failure()
        _log.error("Executor failed for tool '%s': %s", tool_name, exc)
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=f"Tool '{tool_name}' execution failed: {exc}",
        )

    return GatewayResult(
        request_id=req_id,
        gateway_decision=GatewayDecision.EXECUTED,
        decision_reason=(
            f"Tool '{tool_name}' passed all checks and was executed "
            f"via {_executor_mode} executor."
        ),
        tool_output=output,
    )
