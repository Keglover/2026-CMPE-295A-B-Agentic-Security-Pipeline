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

from app.models import PolicyAction, PolicyResult, RiskCategory, RiskResult

# ---------------------------------------------------------------------------
# Threshold constants — change here, tests update everywhere
# TODO: [ ] Task 4.4 — Replace with config_loader.load_policy_config()
# ---------------------------------------------------------------------------

BLOCK_THRESHOLD = 80
QUARANTINE_THRESHOLD = 60
APPROVAL_THRESHOLD = 35
SANITIZE_THRESHOLD = 15

# Categories that warrant human approval even at lower score
HIGH_ATTENTION_CATEGORIES = {
    RiskCategory.TOOL_COERCION,
    RiskCategory.DATA_EXFILTRATION,
}


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
    if score >= BLOCK_THRESHOLD:
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.BLOCK,
            policy_reason=(
                f"Risk score {score} exceeds BLOCK threshold ({BLOCK_THRESHOLD}). "
                f"Categories: {[c.value for c in risk.risk_categories]}."
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
        HIGH_ATTENTION_CATEGORIES & categories and score >= SANITIZE_THRESHOLD
    ):
        return PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.REQUIRE_APPROVAL,
            policy_reason=(
                f"Risk score {score} or high-attention category detected "
                f"({[c.value for c in risk.risk_categories]}). "
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
