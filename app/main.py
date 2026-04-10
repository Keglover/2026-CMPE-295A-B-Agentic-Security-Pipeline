"""
FastAPI application entry point.

Wires together the five pipeline modules in the correct order:
  ingest/normalize → risk engine → policy engine → tool gateway → audit log

Exposes endpoints:
  POST /pipeline           — Run the full security pipeline on a payload.
  GET  /health             — Quick liveness check.
  GET  /tools              — List the allowed tools and their required arguments.
  GET  /history            — Query past audit log entries.
  POST /approve/{id}       — Human approval for REQUIRE_APPROVAL actions.
  POST /reject/{id}        — Human rejection for REQUIRE_APPROVAL actions.
  GET  /pending            — List pending approval requests.
  GET  /policy/stats       — Policy decision statistics.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.audit import logger as audit
from app.approval.workflow import approval_manager
from app.gateway import gateway
from app.gateway.circuit_breaker import circuit_registry
from app.ingest import normalizer
from app.models import (
    PipelineRequest,
    PipelineResponse,
    PolicyAction,
    PolicyResult,
)
from app.policy import engine as policy_engine
from app.policy.pii_detector import redact as pii_redact
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
# Background tasks — approval timeout enforcement
# ---------------------------------------------------------------------------


async def _approval_timeout_loop() -> None:
    """Periodically sweep pending approvals and auto-deny expired ones."""
    while True:
        try:
            timed_out = approval_manager.check_timeouts()
            if timed_out:
                _log.info("Auto-denied %d timed-out approval(s)", len(timed_out))
        except Exception:
            _log.exception("Error in approval timeout sweep")
        await asyncio.sleep(30)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — launches background tasks."""
    task = asyncio.create_task(_approval_timeout_loop())
    _log.info("Approval timeout background task started")
    yield
    task.cancel()


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
    version="0.2.0",
    lifespan=_lifespan,
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Liveness check — returns 200 if the service is running."""
    return {
        "status": "ok",
        "version": "0.2.0",
        "circuit_breakers": circuit_registry.health_summary(),
        "pending_approvals": approval_manager.pending_count,
    }


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
      3b. PII redaction (if SANITIZE)
      4. Gateway    — execute the tool (if proposed and allowed)
      5. Audit      — write the decision trace
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

    # Stage 3: Policy decision (with fail-closed wrapper)
    try:
        policy = policy_engine.decide(risk)
    except Exception as exc:
        _log.error(
            "Policy engine failed for request_id=%s: %s — fail-closed to BLOCK",
            request.request_id, exc,
        )
        policy = PolicyResult(
            request_id=risk.request_id,
            policy_action=PolicyAction.BLOCK,
            policy_reason=policy_engine.FAIL_CLOSED_REASON,
            requires_approval=False,
        )
    _log.info(
        "Policy request_id=%s action=%s",
        request.request_id,
        policy.policy_action.value,
    )

    # Stage 3b: PII redaction when policy is SANITIZE
    sanitization_applied = False
    pii_found: list[str] = []
    if policy.policy_action == PolicyAction.SANITIZE:
        redacted_content, pii_matches = pii_redact(request.content)
        if pii_matches:
            sanitization_applied = True
            pii_found = list({m.pii_type.value for m in pii_matches})
            # Replace request content with redacted version for gateway
            request = request.model_copy(update={"content": redacted_content})
            _log.info(
                "PII redacted request_id=%s types=%s count=%d",
                request.request_id, pii_found, len(pii_matches),
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
    if sanitization_applied:
        summary_parts.append(f"PII redacted: {pii_found}")
    if gateway_result:
        summary_parts.append(f"Gateway: {gateway_result.gateway_decision.value}")
    summary = " | ".join(summary_parts)

    return PipelineResponse(
        request_id=request.request_id,
        normalized=normalized,
        risk=risk,
        policy=policy,
        gateway=gateway_result,
        sanitization_applied=sanitization_applied,
        pii_found=pii_found,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Approval Endpoints
# ---------------------------------------------------------------------------


class ApprovalBody(BaseModel):
    """Request body for approve/reject actions."""
    approved_by: str = "human_reviewer"
    reason: str = ""


@app.get("/pending", tags=["approval"])
def list_pending() -> dict:
    """List all requests awaiting human approval."""
    pending = approval_manager.list_pending()
    return {
        "count": len(pending),
        "pending": [
            {
                "request_id": r.request_id,
                "risk_score": r.risk_score,
                "proposed_tool": r.proposed_tool,
                "status": r.status.value,
                "created_at": r.created_at,
            }
            for r in pending
        ],
    }


@app.post("/approve/{request_id}", tags=["approval"])
def approve_request(request_id: str, body: ApprovalBody | None = None) -> dict:
    """Approve a pending REQUIRE_APPROVAL request."""
    body = body or ApprovalBody()
    record = approval_manager.approve(
        request_id, approved_by=body.approved_by, reason=body.reason,
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Request '{request_id}' not found in pending queue.",
        )
    return {
        "request_id": record.request_id,
        "status": record.status.value,
        "resolved_by": record.resolved_by,
        "reason": record.reason,
    }


@app.post("/reject/{request_id}", tags=["approval"])
def reject_request(request_id: str, body: ApprovalBody | None = None) -> dict:
    """Reject a pending REQUIRE_APPROVAL request."""
    body = body or ApprovalBody()
    record = approval_manager.reject(
        request_id, rejected_by=body.approved_by, reason=body.reason,
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Request '{request_id}' not found in pending queue.",
        )
    return {
        "request_id": record.request_id,
        "status": record.status.value,
        "resolved_by": record.resolved_by,
        "reason": record.reason,
    }


# ---------------------------------------------------------------------------
# Audit & Stats Endpoints
# ---------------------------------------------------------------------------


@app.get("/history", tags=["audit"])
def get_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    policy_action: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
) -> dict:
    """Query past audit log entries from audit_logs/audit.ndjson."""
    log_path = audit._LOG_PATH
    if not log_path.exists():
        return {"total": 0, "entries": []}

    entries: list[dict] = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Apply filters
            if request_id and entry.get("request_id") != request_id:
                continue
            if policy_action and entry.get("policy_action") != policy_action:
                continue
            entries.append(entry)

    total = len(entries)
    # Return newest first, with pagination
    entries.reverse()
    page = entries[offset : offset + limit]
    return {"total": total, "limit": limit, "offset": offset, "entries": page}


@app.get("/policy/stats", tags=["policy"])
def policy_stats() -> dict:
    """Return policy decision statistics aggregated from the audit log."""
    log_path = audit._LOG_PATH
    if not log_path.exists():
        return {"total": 0, "actions": {}}

    action_counts: dict[str, int] = {}
    total = 0
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            action = entry.get("policy_action", "UNKNOWN")
            action_counts[action] = action_counts.get(action, 0) + 1
            total += 1

    return {"total": total, "actions": action_counts}

