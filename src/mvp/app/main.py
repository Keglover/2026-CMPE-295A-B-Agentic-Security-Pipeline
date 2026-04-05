"""
FastAPI application entry point.

Wires together the five pipeline modules in the correct order:
  ingest/normalize → risk engine → policy engine → tool gateway → audit log

Exposes two endpoints:
  POST /pipeline   — Run the full security pipeline on a payload.
  GET  /health     — Quick liveness check.
  GET  /tools      — List the allowed tools and their required arguments.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.audit import logger as audit
from app.gateway import gateway
from app.ingest import normalizer
from app.models import PipelineRequest, PipelineResponse
from app.policy import engine as policy_engine
from app.risk import engine as risk_engine

# ---------------------------------------------------------------------------
# Logging setup — structured output to stdout
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
_log = logging.getLogger("main")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Agentic Security Pipeline MVP",
    description=(
        "A policy-mediated security pipeline that separates untrusted content "
        "processing from privileged tool execution. "
        "Every request flows through: normalize → risk → policy → gateway → audit."
    ),
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Liveness check — returns 200 if the service is running."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/tools", tags=["meta"])
def list_tools() -> dict:
    """Return the list of tools that the gateway will permit."""
    return {
        "allowed_tools": gateway.TOOL_SCHEMAS,
        "note": "Only these tools can be executed. All others are denied.",
    }


@app.post("/pipeline", response_model=PipelineResponse, tags=["pipeline"])
def run_pipeline(request: PipelineRequest) -> PipelineResponse:
    """
    Run the full security pipeline on an input payload.

    Flow:
      1. Normalize  — clean the input text
      2. Risk score — detect attack signals
      3. Policy     — decide what to do
      4. Gateway    — execute the tool (if proposed and allowed)
      5. Audit      — write the decision trace

    A tool call is only attempted when `proposed_tool` is set in the request.
    If no tool is proposed the gateway stage is skipped.

    Args:
        request (PipelineRequest): The input payload.

    Returns:
        PipelineResponse: Full trace of every stage's decision.
    """
    _log.info("Pipeline start request_id=%s", request.request_id)

    # Stage 1: Normalize
    normalized = normalizer.normalize(request)
    _log.info(
        "Normalized request_id=%s notes=%s",
        request.request_id,
        normalized.normalization_notes,
    )

    # Stage 2: Risk scoring
    risk = risk_engine.score(normalized)
    _log.info(
        "Risk request_id=%s score=%d categories=%s",
        request.request_id,
        risk.risk_score,
        [c.value for c in risk.risk_categories],
    )

    # Stage 3: Policy decision
    policy = policy_engine.decide(risk)
    _log.info(
        "Policy request_id=%s action=%s",
        request.request_id,
        policy.policy_action.value,
    )

    # Stage 4: Gateway (only when a tool call is proposed)
    gateway_result = None
    if request.proposed_tool:
        gateway_result = gateway.mediate(request, policy)
        _log.info(
            "Gateway request_id=%s decision=%s",
            request.request_id,
            gateway_result.gateway_decision.value,
        )

    # Stage 5: Audit log
    audit.record(request, risk, policy, gateway_result)

    # Build human-readable summary
    summary_parts = [
        f"Score: {risk.risk_score}/100",
        f"Action: {policy.policy_action.value}",
    ]
    if gateway_result:
        summary_parts.append(f"Gateway: {gateway_result.gateway_decision.value}")
    summary = " | ".join(summary_parts)

    return PipelineResponse(
        request_id=request.request_id,
        normalized=normalized,
        risk=risk,
        policy=policy,
        gateway=gateway_result,
        summary=summary,
    )
