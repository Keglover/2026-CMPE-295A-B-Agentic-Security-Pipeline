"""
Tool Gateway module — Deliverable A: Tool Proxy.

Project Plan Ref: Phase 3 (Core Development: Tool Proxy)

Responsibility: Act as the ONLY execution path for tool calls.
No tool call may bypass this module — that is the hard enforcement boundary.

On every call the gateway checks:
  1. Tool is on the allowlist.
  2. Required arguments are present and pass schema validation.
  3. The policy action permits execution (ALLOW or SANITIZE only).

If any check fails the gateway returns DENIED with a reason code.
If all checks pass it routes to the selected executor set and returns the result.

Executor selection (controlled by REAL_TOOLS env var):
  REAL_TOOLS=false (default) → gateway_mock.py  — safe stubs, no side effects
  REAL_TOOLS=true            → gateway_real.py  — real network/FS calls; only
                                                   activate inside an isolated
                                                   Docker container with network
                                                   restrictions enabled.

TODO List (from Project Plan):
    - [ ] Task 3.3  — Load TOOL_SCHEMAS from config/tool_registry.yaml
    - [ ] Task 3.7  — Implement argument type validation (string, int, URL)
    - [ ] Task 3.8  — Implement argument value constraints (max length, patterns)
    - [ ] Task 3.12 — Implement REQUIRE_APPROVAL hold-and-wait logic
    - [ ] Task 3.13 — Implement configurable approval timeout with auto-deny
    - [ ] Task 3.20 — Wire rate_limiter.py into mediate() before execution
    - [ ] Task 3.21 — Wire circuit_breaker.py for downstream tool failures
    - [ ] Task 3.23 — Implement request deduplication
"""

from __future__ import annotations

import os
from typing import Any

from app.models import (
    GatewayDecision,
    GatewayResult,
    PolicyAction,
    PolicyResult,
    PipelineRequest,
)

# ---------------------------------------------------------------------------
# Executor selection — controlled at startup via environment variable.
# Defaults to mock (safe) so developers can never accidentally run real tools
# without explicitly opting in.
# ---------------------------------------------------------------------------

# Reason: read once at import time so the decision is visible in logs and
# cannot change mid-run from a request payload.
_USE_REAL_TOOLS: bool = os.getenv("REAL_TOOLS", "false").strip().lower() == "true"

if _USE_REAL_TOOLS:
    from app.gateway.gateway_real import EXECUTORS as _TOOL_EXECUTORS

    _executor_mode = "REAL"
else:
    from app.gateway.gateway_mock import EXECUTORS as _TOOL_EXECUTORS

    _executor_mode = "MOCK"

import logging as _logging

_logging.getLogger("gateway").info(
    "Tool executor mode: %s (set REAL_TOOLS=true to activate real tools)",
    _executor_mode,
)

# ---------------------------------------------------------------------------
# Tool schema registry
# Each tool declares its required argument names.
# TODO: [ ] Task 3.3 — Replace with config_loader.load_tool_registry()
# TODO: [ ] Task 3.4 — Add description, risk_tier, privilege_level metadata
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: dict[str, list[str]] = {
    "summarize": ["text"],
    "write_note": ["title", "body"],
    "search_notes": ["query"],
    "fetch_url": ["url"],
}

# Tools that are permitted to execute (may be a subset of TOOL_SCHEMAS)
TOOL_ALLOWLIST: set[str] = set(TOOL_SCHEMAS.keys())

# Policy actions that permit execution
EXECUTABLE_ACTIONS: set[PolicyAction] = {PolicyAction.ALLOW, PolicyAction.SANITIZE}


# ---------------------------------------------------------------------------
# Gateway entry point
# ---------------------------------------------------------------------------


def mediate(
    request: PipelineRequest,
    policy: PolicyResult,
) -> GatewayResult:
    """
    Evaluate a proposed tool call and either execute or deny it.

    Args:
        request (PipelineRequest): Original request, carries proposed_tool
                                   and tool_args.
        policy (PolicyResult): Decision from the policy engine.

    Returns:
        GatewayResult: EXECUTED with tool output, or DENIED with reason.
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
        return GatewayResult(
            request_id=req_id,
            gateway_decision=GatewayDecision.DENIED,
            decision_reason=(
                f"Policy action '{policy.policy_action.value}' does not permit "
                f"tool execution. Reason: {policy.policy_reason}"
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
    output = executor(tool_args)

    return GatewayResult(
        request_id=req_id,
        gateway_decision=GatewayDecision.EXECUTED,
        decision_reason=(
            f"Tool '{tool_name}' passed all checks and was executed "
            f"via {_executor_mode} executor."
        ),
        tool_output=output,
    )
