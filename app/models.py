"""
Shared Pydantic data models (interface contracts) for the security pipeline.

Every module exchanges these typed structures, ensuring contracts are
enforceable and versioned from day one.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SourceType(str, Enum):
    """Origin of the content entering the pipeline."""

    DIRECT_PROMPT = "direct_prompt"
    RETRIEVED_CONTENT = "retrieved_content"


class RiskCategory(str, Enum):
    """Attack categories the risk engine can detect."""

    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    TOOL_COERCION = "TOOL_COERCION"
    OBFUSCATION = "OBFUSCATION"
    BENIGN = "BENIGN"


class PolicyAction(str, Enum):
    """Deterministic policy outcomes from the policy engine."""

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class GatewayDecision(str, Enum):
    """Final gateway decision for a tool call."""

    EXECUTED = "EXECUTED"
    DENIED = "DENIED"


# ---------------------------------------------------------------------------
# Pipeline request — the envelope that flows through all stages
# ---------------------------------------------------------------------------


class PipelineRequest(BaseModel):
    """
    Input envelope for a single pipeline execution.

    Args:
        content (str): The raw text payload to evaluate.
        source_type (SourceType): Where the content came from.
        proposed_tool (str | None): Tool the agent wants to call (if any).
        tool_args (dict | None): Arguments for the proposed tool call.
        request_id (str): Unique identifier; auto-generated if omitted.
    """

    content: str = Field(..., min_length=1, description="Raw text payload to evaluate")
    source_type: SourceType = Field(
        default=SourceType.DIRECT_PROMPT, description="Origin of the content"
    )
    proposed_tool: str | None = Field(
        default=None, description="Tool the agent wants to call"
    )
    tool_args: dict[str, Any] | None = Field(
        default=None, description="Arguments for the proposed tool call"
    )
    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique request identifier",
    )
    agent_id: str | None = Field(
        default=None,
        description="Identifier of the calling agent; defaults to anonymous if omitted",
    )


# ---------------------------------------------------------------------------
# Stage outputs — one per pipeline component
# ---------------------------------------------------------------------------


class NormalizedInput(BaseModel):
    """
    Output of the Ingest/Normalize stage.

    Args:
        request_id (str): Forwarded from the original request.
        original_content (str): Unmodified input.
        normalized_content (str): Cleaned, canonicalized text.
        normalization_notes (list[str]): Steps applied during normalization.
    """

    request_id: str
    original_content: str
    normalized_content: str
    normalization_notes: list[str] = Field(default_factory=list)


class RiskResult(BaseModel):
    """
    Output of the Risk Engine.

    Args:
        request_id (str): Forwarded from the original request.
        risk_score (int): 0–100; higher means more dangerous.
        risk_categories (list[RiskCategory]): Detected attack families.
        matched_signals (list[str]): Human-readable rule matches.
        rationale (str): Plain-English explanation.
    """

    request_id: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_categories: list[RiskCategory] = Field(default_factory=list)
    matched_signals: list[str] = Field(default_factory=list)
    rationale: str


class PolicyResult(BaseModel):
    """
    Output of the Policy Engine.

    Args:
        request_id (str): Forwarded from the original request.
        policy_action (PolicyAction): What the pipeline should do next.
        policy_reason (str): Human-readable justification.
        requires_approval (bool): True when a human must confirm before execution.
    """

    request_id: str
    policy_action: PolicyAction
    policy_reason: str
    requires_approval: bool = False


class GatewayResult(BaseModel):
    """
    Output of the Tool Gateway.

    Args:
        request_id (str): Forwarded from the original request.
        gateway_decision (GatewayDecision): EXECUTED or DENIED.
        decision_reason (str): Why the gateway allowed or blocked the call.
        tool_output (Any | None): Result of the tool, if executed.
    """

    request_id: str
    gateway_decision: GatewayDecision
    decision_reason: str
    tool_output: Any | None = None


# ---------------------------------------------------------------------------
# Full pipeline response — the top-level API response
# ---------------------------------------------------------------------------


class PipelineResponse(BaseModel):
    """
    Complete pipeline result returned to the caller.

    All intermediate stage results are included so the caller can trace
    exactly what happened at each layer.
    """

    request_id: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    normalized: NormalizedInput
    risk: RiskResult
    policy: PolicyResult
    gateway: GatewayResult | None = None
    sanitization_applied: bool = False
    pii_found: list[str] = Field(default_factory=list)
    summary: str = ""
