"""Static tool-permission baseline (B1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.policy.config_loader import load_tool_registry


@dataclass(frozen=True)
class DeclarativeDecision:
    action: str
    reason: str
    matched_rule: str


def evaluate_tool(
    proposed_tool: str | None,
    tool_args: dict[str, Any] | None = None,
) -> DeclarativeDecision:
    """Evaluate only static tool permissions; content is intentionally ignored."""
    if not proposed_tool:
        return DeclarativeDecision("ALLOW", "No tool requested.", "no_tool")

    registry = load_tool_registry().get("tools", {})
    tool = registry.get(proposed_tool)
    if not tool:
        return DeclarativeDecision("BLOCK", f"Unknown tool: {proposed_tool}.", "unknown_tool")
    if not tool.get("enabled", False):
        return DeclarativeDecision("BLOCK", f"Tool disabled: {proposed_tool}.", "disabled_tool")

    required_args = tool.get("required_args", [])
    missing_args = [name for name in required_args if not tool_args or name not in tool_args]
    if missing_args:
        return DeclarativeDecision(
            "BLOCK",
            f"Missing required arguments: {', '.join(missing_args)}.",
            "missing_arguments",
        )

    if tool.get("risk_tier") == "high":
        return DeclarativeDecision(
            "REQUIRE_APPROVAL",
            f"High-risk tool requires approval: {proposed_tool}.",
            "high_risk_tool",
        )

    return DeclarativeDecision("ALLOW", f"Enabled static tool permission: {proposed_tool}.", "enabled_tool")
