"""
Turn Jev answers into one decision. The model assesses; this file decides.

Thresholds live in thresholds.json so you can tune them without editing code.
"""

from __future__ import annotations

from typing import Any


def route(
    nouls: dict[str, float],
    severity: float | None,
    thresholds: dict[str, float],
) -> dict[str, Any]:
    """
    Map hazard probabilities onto pass / review / block.

    Args:
        nouls: Question id → P(yes) in [0, 1].
        severity: Weighted score, or None if no Score question ran.
        thresholds: action_threshold, review_threshold, severity_block.

    Returns:
        dict: decision, trigger (hazard id or None), max_noul.
    """
    action_at = float(thresholds["action_threshold"])
    review_at = float(thresholds["review_threshold"])
    sev_block = float(thresholds["severity_block"])

    if not nouls:
        return {"decision": "pass", "trigger": None, "max_noul": 0.0}

    trigger, max_noul = max(nouls.items(), key=lambda item: item[1])
    decision = "pass"
    if max_noul >= action_at:
        decision = "block"
    elif max_noul >= review_at:
        decision = "review"

    if severity is not None and severity >= sev_block and decision == "review":
        decision = "block"

    return {
        "decision": decision,
        "trigger": trigger if decision != "pass" else None,
        "max_noul": max_noul,
    }
