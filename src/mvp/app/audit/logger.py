"""
Audit / Telemetry module.

Responsibility: Persist a structured decision trace for every pipeline run.
Every request that flows through the pipeline gets one log entry containing:
  - request_id and timestamp
  - input hash (never the raw content — privacy by design)
  - source type
  - risk score and categories
  - policy action
  - gateway decision (if a tool was invoked)

Logs are written as newline-delimited JSON (NDJSON) to audit_logs/audit.ndjson.
This makes them easy to grep, import into pandas, or ingest into a SIEM.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from app.models import GatewayResult, PolicyResult, PipelineRequest, RiskResult

# ---------------------------------------------------------------------------
# File path — can be overridden via AUDIT_LOG_PATH env var for Docker use
# ---------------------------------------------------------------------------

_DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent.parent / "audit_logs"
_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", str(_DEFAULT_LOG_DIR / "audit.ndjson")))

# Standard Python logger for console output alongside the file audit trail
_log = logging.getLogger("audit")


def _sha256_prefix(text: str, chars: int = 16) -> str:
    """
    Return the first `chars` hex characters of the SHA-256 of `text`.

    We store a hash prefix rather than the raw input to avoid retaining
    sensitive content in audit logs while still enabling deduplication.
    """
    return hashlib.sha256(text.encode()).hexdigest()[:chars]


def record(
    request: PipelineRequest,
    risk: RiskResult,
    policy: PolicyResult,
    gateway: GatewayResult | None = None,
) -> dict:
    """
    Build and persist an audit log entry for a single pipeline run.

    Args:
        request (PipelineRequest): Original request (content is hashed, not stored).
        risk (RiskResult): Output from the Risk Engine.
        policy (PolicyResult): Output from the Policy Engine.
        gateway (GatewayResult | None): Output from the Tool Gateway, if invoked.

    Returns:
        dict: The log entry that was written (useful for tests and API responses).
    """
    entry: dict = {
        "request_id": request.request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": request.source_type.value,
        "content_hash": _sha256_prefix(request.content),
        "proposed_tool": request.proposed_tool,
        "risk_score": risk.risk_score,
        "risk_categories": [c.value for c in risk.risk_categories],
        "matched_signals": risk.matched_signals,
        "policy_action": policy.policy_action.value,
        "requires_approval": policy.requires_approval,
        "gateway_decision": gateway.gateway_decision.value if gateway else None,
        "gateway_reason": gateway.decision_reason if gateway else None,
    }

    # Ensure the log directory exists
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Append as a single line of JSON
    with _LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    
    _log.info(
        "AUDIT request_id=%s action=%s score=%d gateway=%s",
        entry["request_id"],
        entry["policy_action"],
        entry["risk_score"],
        entry["gateway_decision"] or "N/A",
    )

    return entry
