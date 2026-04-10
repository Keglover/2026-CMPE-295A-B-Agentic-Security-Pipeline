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
REAL_TOOLS=true            → gateway_real.py  — real network/FS calls; only activate inside 
                            an isolated Docker container with network restrictions enabled.
"""

from __future__ import annotations

import logging as _logging
import os
from typing import Any

from app.models import (
    GatewayDecision,
    GatewayResult,
    PolicyAction,
    PolicyResult,
    PipelineRequest,
)
from app.policy.config_loader import load_tool_registry
from app.gateway.rate_limiter import rate_limiter
from app.gateway.circuit_breaker import circuit_registry
from app.approval.workflow import approval_manager

_log = _logging.getLogger("gateway")

# ---------------------------------------------------------------------------
# Executor selection — controlled at startup via environment variable.
# ---------------------------------------------------------------------------

_USE_REAL_TOOLS: bool = os.getenv("REAL_TOOLS", "false").strip().lower() == "true"

if _USE_REAL_TOOLS:
    from app.gateway.gateway_real import EXECUTORS as _TOOL_EXECUTORS
    _executor_mode = "REAL"
else:
    from app.gateway.gateway_mock import EXECUTORS as _TOOL_EXECUTORS
    _executor_mode = "MOCK"

_log.info(
    "Tool executor mode: %s (set REAL_TOOLS=true to activate real tools)",
    _executor_mode,
)

# ---------------------------------------------------------------------------
# Tool schema registry — loaded from config/tool_registry.yaml (Task 3.3)
# ---------------------------------------------------------------------------

_registry = load_tool_registry()
_tools_config: dict = _registry.get("tools", {})

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

# Policy actions that permit execution
EXECUTABLE_ACTIONS: set[PolicyAction] = {PolicyAction.ALLOW, PolicyAction.SANITIZE}

_log.info(
    "Tool registry loaded (v%s): %s",
    REGISTRY_VERSION, sorted(TOOL_ALLOWLIST),
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
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Policy action '{policy.policy_action.value}' does not permit "
                f"tool execution. Reason: {policy.policy_reason}"
            ),
        )

    # --- Rate limit check (Task 3.20) ---
    if not rate_limiter.check(tool_name):
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=f"Rate limit exceeded for tool '{tool_name}'. Try again later.",
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

    # --- All checks passed: route to executor ---
    executor = _TOOL_EXECUTORS[tool_name]
    try:
        output = executor(tool_args)
        cb.record_success()
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
