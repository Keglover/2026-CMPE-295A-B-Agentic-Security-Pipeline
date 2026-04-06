"""
Tests for the Policy Engine module.

Covers:
  - ALLOW for low-risk (score < 15)
  - SANITIZE for low-medium risk (score 15-34)
  - REQUIRE_APPROVAL for medium risk or high-attention categories
  - QUARANTINE for high risk (score 60-79)
  - BLOCK for very high risk (score >= 80)
  - requires_approval flag is set correctly
"""

import pytest

from app.models import RiskCategory, RiskResult
from app.policy.engine import decide


def _risk(
    score: int,
    categories: list[RiskCategory] | None = None,
    req_id: str = "pol-test",
) -> RiskResult:
    return RiskResult(
        request_id=req_id,
        risk_score=score,
        risk_categories=categories or [RiskCategory.BENIGN],
        matched_signals=[],
        rationale="test",
    )


# ---------------------------------------------------------------------------
# ALLOW
# ---------------------------------------------------------------------------


def test_low_score_produces_allow():
    """Score below 15 with benign category must produce ALLOW."""
    from app.models import PolicyAction

    result = decide(_risk(score=0))
    assert result.policy_action == PolicyAction.ALLOW
    assert result.requires_approval is False


# ---------------------------------------------------------------------------
# SANITIZE
# ---------------------------------------------------------------------------


def test_medium_low_score_produces_sanitize():
    """Score between 15-34 with benign category must produce SANITIZE."""
    from app.models import PolicyAction

    result = decide(_risk(score=20, categories=[RiskCategory.OBFUSCATION]))
    assert result.policy_action == PolicyAction.SANITIZE
    assert result.requires_approval is False


# ---------------------------------------------------------------------------
# REQUIRE_APPROVAL
# ---------------------------------------------------------------------------


def test_medium_score_produces_require_approval():
    """Score of 35-59 must produce REQUIRE_APPROVAL."""
    from app.models import PolicyAction

    result = decide(_risk(score=40, categories=[RiskCategory.INSTRUCTION_OVERRIDE]))
    assert result.policy_action == PolicyAction.REQUIRE_APPROVAL
    assert result.requires_approval is True


def test_tool_coercion_at_low_score_bumps_to_approval():
    """TOOL_COERCION at score 20 should still require approval."""
    from app.models import PolicyAction

    result = decide(_risk(score=20, categories=[RiskCategory.TOOL_COERCION]))
    assert result.policy_action == PolicyAction.REQUIRE_APPROVAL
    assert result.requires_approval is True


# ---------------------------------------------------------------------------
# QUARANTINE
# ---------------------------------------------------------------------------


def test_high_score_produces_quarantine():
    """Score 60-79 must produce QUARANTINE."""
    from app.models import PolicyAction

    result = decide(_risk(score=65, categories=[RiskCategory.DATA_EXFILTRATION]))
    assert result.policy_action == PolicyAction.QUARANTINE
    assert result.requires_approval is False


# ---------------------------------------------------------------------------
# BLOCK
# ---------------------------------------------------------------------------


def test_very_high_score_produces_block():
    """Score >= 80 must produce BLOCK."""
    from app.models import PolicyAction

    result = decide(_risk(score=95, categories=[RiskCategory.TOOL_COERCION]))
    assert result.policy_action == PolicyAction.BLOCK
    assert result.requires_approval is False

def test_immediate_block_threshold():
    from app.models import PolicyAction

    result = decide(_risk(score=96))
    assert result.policy_action == PolicyAction.BLOCK
    assert "Immediate block" in result.policy_reason

def test_policy_result_includes_reason():
    """Every policy result must include a non-empty policy_reason."""
    result = decide(_risk(score=50))
    assert result.policy_reason
    assert len(result.policy_reason) > 5
