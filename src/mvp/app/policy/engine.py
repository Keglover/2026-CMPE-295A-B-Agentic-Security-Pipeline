"""
Policy Engine module — Deliverable B: Policy Enforcement Layer.

Project Plan Ref: Phase 4 (Core Development: Policy Enforcement Layer)

Responsibility: Convert a RiskResult into a deterministic PolicyAction.

Design principle: The mapping must be a pure function — same inputs always
produce the same output. No randomness, no model inference. This ensures
the pipeline's security behaviour is testable, auditable, and predictable.

Threshold table (v1):
  risk_score >= 80  → BLOCK
  risk_score >= 60  → QUARANTINE      (or REQUIRE_APPROVAL for TOOL_COERCION)
  risk_score >= 35  → REQUIRE_APPROVAL
  risk_score >= 15  → SANITIZE
  risk_score <  15  → ALLOW

Additionally, any TOOL_COERCION or BYPASS signal above 40 overrides to
REQUIRE_APPROVAL at minimum, regardless of numeric score.

TODO List (from Project Plan):
    - [ ] Task 4.4  — Load thresholds from config/policy_thresholds.yaml
    - [ ] Task 4.5  — Implement hot-reload without service restart
    - [ ] Task 4.6  — Integrate PII detection from pii_detector.py
    - [ ] Task 4.8  — Implement tool-specific policy overrides
    - [ ] Task 4.9  — Implement policy rule chaining (most restrictive wins)
    - [ ] Task 2.15 — Implement fail-closed default when Risk Engine unavailable
    - [ ] Task 4.18 — Add policy rule version tracking
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.models import PolicyAction, PolicyResult, RiskCategory, RiskResult
from app.policy.config_loader import load_policy_config

_log = logging.getLogger("policy_engine")

# ---------------------------------------------------------------------------
# Load thresholds from config/policy_thresholds.yaml (Task 4.4)
# Falls back to hardcoded defaults if the YAML file is missing.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyConfig:
    """Validated immutable policy settings used by the pure decision function."""

    block: int
    quarantine: int
    approval: int
    sanitize: int
    high_attention_categories: frozenset[RiskCategory]
    high_attention_min_score: int
    fail_closed_action: str
    fail_closed_reason: str
    version: str


def _threshold(config: dict[str, Any], name: str, default: int) -> int:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError(f"policy threshold {name!r} must be an integer from 0 to 100")
    return value


def _load_config() -> PolicyConfig:
    config = load_policy_config()
    thresholds = config.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("policy thresholds must be a mapping")
    block = _threshold(thresholds, "block", 80)
    quarantine = _threshold(thresholds, "quarantine", 60)
    approval = _threshold(thresholds, "require_approval", 35)
    sanitize = _threshold(thresholds, "sanitize", 15)
    if not block >= quarantine >= approval >= sanitize:
        raise ValueError("policy thresholds must descend: block >= quarantine >= approval >= sanitize")

    configured_categories = config.get(
        "high_attention_categories", ["TOOL_COERCION", "DATA_EXFILTRATION"]
    )
    if not isinstance(configured_categories, list):
        raise ValueError("high_attention_categories must be a list")
    categories = frozenset(
        RiskCategory(name)
        for name in configured_categories
        if name in RiskCategory.__members__
    )
    minimum = _threshold(
        config, "high_attention_min_score", sanitize
    )
    fail_closed = config.get("fail_closed", {})
    if not isinstance(fail_closed, dict):
        raise ValueError("fail_closed policy settings must be a mapping")
    return PolicyConfig(
        block=block,
        quarantine=quarantine,
        approval=approval,
        sanitize=sanitize,
        high_attention_categories=categories,
        high_attention_min_score=minimum,
        fail_closed_action=str(fail_closed.get("default_action", "BLOCK")),
        fail_closed_reason=str(
            fail_closed.get(
                "default_reason", "Risk Engine unreachable — fail-closed to BLOCK"
            )
        ),
        version=str(config.get("version", "unknown")),
    )


_policy_config = _load_config()

BLOCK_THRESHOLD = _policy_config.block
QUARANTINE_THRESHOLD = _policy_config.quarantine
APPROVAL_THRESHOLD = _policy_config.approval
SANITIZE_THRESHOLD = _policy_config.sanitize

# Categories that warrant human approval even at lower score
HIGH_ATTENTION_CATEGORIES = _policy_config.high_attention_categories

# Minimum score for high-attention override to activate
_HIGH_ATTENTION_MIN_SCORE = _policy_config.high_attention_min_score

# Fail-closed defaults (used by main.py when risk engine is unreachable)
FAIL_CLOSED_ACTION = _policy_config.fail_closed_action
FAIL_CLOSED_REASON = _policy_config.fail_closed_reason

POLICY_VERSION = _policy_config.version

_log.info(
    "Policy config loaded (v%s): BLOCK>=%d QUARANTINE>=%d APPROVAL>=%d SANITIZE>=%d",
    POLICY_VERSION, BLOCK_THRESHOLD, QUARANTINE_THRESHOLD,
    APPROVAL_THRESHOLD, SANITIZE_THRESHOLD,
)


def decide(risk: RiskResult) -> PolicyResult:
    """
    Map a RiskResult to a deterministic PolicyAction.

    Args:
        risk (RiskResult): Output from the Risk Engine.

    Returns:
        PolicyResult: Action the pipeline should take, with justification.
    """
    score = risk.risk_score
    categories = set(risk.risk_categories)

    # --- Hard block for very high risk ---
    categories_text = ", ".join(category.value for category in risk.risk_categories)

    if score >= BLOCK_THRESHOLD:
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.BLOCK,
            policy_reason=(
                f"Risk score {score} exceeds BLOCK threshold ({BLOCK_THRESHOLD}). "
                f"Categories: {categories_text or 'none'}."
            ),
            requires_approval=False,
        )

    # --- Quarantine for high risk ---
    if score >= QUARANTINE_THRESHOLD:
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.QUARANTINE,
            policy_reason=(
                f"Risk score {score} exceeds QUARANTINE threshold ({QUARANTINE_THRESHOLD}). "
                f"Content isolated; tool execution prevented."
            ),
            requires_approval=False,
        )

    # --- High-attention categories bump to approval even at medium score ---
    if score >= APPROVAL_THRESHOLD or (
        HIGH_ATTENTION_CATEGORIES & categories and score >= _HIGH_ATTENTION_MIN_SCORE
    ):
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.REQUIRE_APPROVAL,
            policy_reason=(
                f"Risk score {score} or high-attention category detected "
                f"({categories_text or 'none'}). "
                f"Human approval required before execution."
            ),
            requires_approval=True,
        )

    # --- Low-medium risk: sanitize and allow under monitoring ---
    if score >= SANITIZE_THRESHOLD:
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.SANITIZE,
            policy_reason=(
                f"Risk score {score} is low but non-zero. "
                f"Content sanitized; proceed with caution."
            ),
            requires_approval=False,
        )

    # --- Safe: allow ---
    return PolicyResult(
        request_id=risk.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason=f"Risk score {score}. No significant threats detected.",
        requires_approval=False,
    )
