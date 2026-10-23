"""Reusable assessment stages; this module has no execution dependencies."""

import logging

from app.ingest import normalizer
from app.models import PipelineRequest, PolicyAction, PolicyResult
from app.policy import engine as policy_engine
from app.risk import engine as risk_engine

_log = logging.getLogger(__name__)


def assess_content(request: PipelineRequest, *, fail_on_policy_error: bool = False):
    normalized = normalizer.normalize(request)
    risk = risk_engine.score(normalized)
    try:
        policy = policy_engine.decide(risk)
    except Exception:
        if fail_on_policy_error:
            raise
        _log.error("Policy assessment unavailable request_id=%s", request.request_id)
        policy = PolicyResult(request_id=risk.request_id,
                              policy_action=PolicyAction.BLOCK,
                              policy_reason=policy_engine.FAIL_CLOSED_REASON,
                              requires_approval=False)
    return normalized, risk, policy
