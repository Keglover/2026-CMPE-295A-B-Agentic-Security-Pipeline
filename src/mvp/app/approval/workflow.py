"""
Approval Workflow module.

Project Plan Ref: Tasks 4.11–4.15, 3.12–3.13 (Phase 4 — Approval Workflow)

Manages the human-in-the-loop approval process for requests that receive a
REQUIRE_APPROVAL policy action. Implements a pending request queue with
configurable timeouts and audit trail integration.

Architecture:
    When the Policy Engine returns REQUIRE_APPROVAL, the gateway holds the
    request and registers it in the approval queue. A human reviewer can
    then approve or reject it via POST /approve/{request_id}. If no action
    is taken within the timeout, the request is auto-denied.

TODO List:
    - [ ] Task 4.11 — Implement POST /approve/{request_id} endpoint in main.py
    - [ ] Task 4.12 — Implement approval state store (in-memory for MVP)
    - [ ] Task 4.13 — Implement approval timeout with auto-deny
    - [ ] Task 4.14 — Implement approval audit trail
    - [ ] Task 4.15 — Implement approval escalation (stretch goal)
    - [ ] Task 3.12 — Wire REQUIRE_APPROVAL hold-and-wait into gateway
    - [ ] Task 3.13 — Implement configurable approval timeout with auto-deny
    - [ ] Task 7.10 — Audit for race conditions (double-approve, approve-after-timeout)
    - [ ] Migrate state store to Redis for production deployments
    - [ ] Write unit tests in tests/test_approval.py
"""

from __future__ import annotations

import logging
import os
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_log = logging.getLogger("approval")


class ApprovalStatus(str, Enum):
    """State of a pending approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    CONSUMED = "consumed"


@dataclass
class ApprovalRecord:
    """
    A single approval request in the queue.

    Args:
        request_id: The pipeline request ID awaiting approval.
        risk_score: The risk score that triggered REQUIRE_APPROVAL.
        risk_categories: Categories detected by the risk engine.
        proposed_tool: The tool the agent wants to execute.
        created_at: Timestamp when the approval was requested.
        status: Current approval status.
        resolved_at: Timestamp when the approval was resolved (if any).
        resolved_by: Identity of the approver (if any).
        reason: Human-provided reason for approval/rejection.
    """

    request_id: str
    risk_score: int
    risk_categories: list[str]
    proposed_tool: str | None
    created_at: float = field(default_factory=time.time)
    status: ApprovalStatus = ApprovalStatus.PENDING
    resolved_at: float | None = None
    resolved_by: str | None = None
    reason: str = ""
    action_hash: str | None = None
    requester: str | None = None
    expires_at: float | None = None
    consumed_at: float | None = None
    action_details: dict[str, Any] = field(default_factory=dict)


class ApprovalManager:
    """
    In-memory approval state manager.

    Stores pending approval requests and handles approve/reject/timeout
    transitions. Thread-safe for concurrent API access.

    For production: replace with Redis or a persistent store so approvals
    survive service restarts.

    TODO: [ ] Task 4.12 — Complete implementation and wire into gateway
    TODO: [ ] Task 4.13 — Background thread/task for timeout enforcement
    """

    def __init__(self, timeout_seconds: float = 300.0, approved_timeout_seconds: float | None = None) -> None:
        """
        Args:
            timeout_seconds: Seconds before a pending request auto-denies.
                             Default: 300s (5 minutes).
        """
        self._timeout = timeout_seconds
        self._approved_timeout = approved_timeout_seconds
        self._pending: dict[str, ApprovalRecord] = {}
        self._resolved: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        request_id: str,
        risk_score: int,
        risk_categories: list[str],
        proposed_tool: str | None = None,
        *,
        action_hash: str | None = None,
        requester: str | None = None,
        action_details: dict[str, Any] | None = None,
    ) -> ApprovalRecord:
        """
        Register a new request for approval.

        Args:
            request_id: The pipeline request ID.
            risk_score: Risk score from the risk engine.
            risk_categories: Detected risk categories.
            proposed_tool: Tool the agent wants to call.

        Returns:
            ApprovalRecord: The newly created pending record.
        """
        record = ApprovalRecord(
            request_id=request_id,
            risk_score=risk_score,
            risk_categories=risk_categories,
            proposed_tool=proposed_tool,
            action_hash=action_hash,
            requester=requester,
            expires_at=time.time() + self._timeout,
            action_details=__import__("copy").deepcopy(action_details or {}),
        )
        with self._lock:
            existing = self._pending.get(request_id) or self._resolved.get(request_id)
            if existing is not None:
                if existing.action_hash != action_hash or existing.requester != requester:
                    raise ValueError("APPROVAL_ACTION_MISMATCH")
                return existing
            self._pending[request_id] = record
        _log.info(
            "Approval requested: request_id=%s tool=%s score=%d",
            request_id,
            proposed_tool,
            risk_score,
        )
        return record

    def approve(
        self,
        request_id: str,
        approved_by: str = "human_reviewer",
        reason: str = "",
    ) -> ApprovalRecord | None:
        """
        Approve a pending request.

        Args:
            request_id: The request to approve.
            approved_by: Identity of the approver.
            reason: Optional justification.

        Returns:
            ApprovalRecord if found and approved, None if not found or already resolved.
        """
        with self._lock:
            record = self._pending.pop(request_id, None)
            if record is None:
                _log.warning("Approve failed: request_id=%s not found in pending", request_id)
                return None
            if self._expired(record):
                self._expire(record)
                return None
            record.status = ApprovalStatus.APPROVED
            record.resolved_at = time.time()
            if self._approved_timeout is not None:
                record.expires_at = min(record.created_at + self._timeout,
                                        record.resolved_at + self._approved_timeout)
            record.resolved_by = approved_by
            record.reason = reason
            self._resolved[request_id] = record
        _log.info("Approved: request_id=%s by=%s", request_id, approved_by)
        return record

    def reject(
        self,
        request_id: str,
        rejected_by: str = "human_reviewer",
        reason: str = "",
    ) -> ApprovalRecord | None:
        """
        Reject a pending request.

        Args:
            request_id: The request to reject.
            rejected_by: Identity of the rejector.
            reason: Optional justification.

        Returns:
            ApprovalRecord if found and rejected, None if not found or already resolved.
        """
        with self._lock:
            record = self._pending.pop(request_id, None)
            if record is None:
                _log.warning("Reject failed: request_id=%s not found in pending", request_id)
                return None
            record.status = ApprovalStatus.REJECTED
            record.resolved_at = time.time()
            record.resolved_by = rejected_by
            record.reason = reason
            self._resolved[request_id] = record
        _log.info("Rejected: request_id=%s by=%s", request_id, rejected_by)
        return record

    def check_timeouts(self) -> list[ApprovalRecord]:
        """
        Scan pending requests and auto-deny any that have exceeded the timeout.

        Returns:
            list[ApprovalRecord]: Records that were timed out in this sweep.
        """
        now = time.time()
        timed_out: list[ApprovalRecord] = []
        with self._lock:
            expired_ids = [
                rid
                for rid, rec in self._pending.items()
                if self._expired(rec)
            ]
            for rid in expired_ids:
                record = self._pending.pop(rid)
                record.status = ApprovalStatus.TIMED_OUT
                record.resolved_at = now
                record.reason = f"Auto-denied: no response within {self._timeout}s"
                self._resolved[rid] = record
                timed_out.append(record)
                _log.warning("Timed out: request_id=%s after %.0fs", rid, self._timeout)
        return timed_out

    def get_status(self, request_id: str) -> ApprovalRecord | None:
        """Look up the current status of any request (pending or resolved)."""
        with self._lock:
            record = self._pending.get(request_id) or self._resolved.get(request_id)
            if record and record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED} and self._expired(record):
                self._pending.pop(request_id, None)
                self._expire(record)
            return record

    def _expired(self, record: ApprovalRecord) -> bool:
        # Use the earlier deadline so old records and clock-based tests remain safe.
        return time.time() >= min(record.created_at + self._timeout,
                                  record.expires_at or float("inf"))

    def _expire(self, record: ApprovalRecord) -> None:
        record.status = ApprovalStatus.TIMED_OUT
        record.resolved_at = time.time()
        record.reason = "Approval expired; execution denied."
        self._resolved[record.request_id] = record

    def consume(self, request_id: str, action_hash: str, requester: str) -> bool:
        """Atomically reserve an exact approved action for one dispatch attempt."""
        with self._lock:
            record = self._resolved.get(request_id)
            if (record is None or record.status != ApprovalStatus.APPROVED
                    or record.action_hash != action_hash or record.requester != requester):
                return False
            if self._expired(record):
                self._expire(record)
                return False
            record.status = ApprovalStatus.CONSUMED
            record.consumed_at = time.time()
            return True

    def list_pending(self) -> list[ApprovalRecord]:
        """Return all currently pending approval requests."""
        self.check_timeouts()
        with self._lock:
            return list(self._pending.values())

    @property
    def pending_count(self) -> int:
        """Number of requests currently awaiting approval."""
        return len(self.list_pending())


# Module-level singleton
# TODO: [ ] Initialize timeout from config/policy_thresholds.yaml
_pending_ttl = int(os.getenv("JEV_APPROVAL_PENDING_TTL", "300"))
_grant_ttl = int(os.getenv("JEV_APPROVAL_GRANT_TTL", "300"))
if not 1 <= _pending_ttl <= 604800 or not 1 <= _grant_ttl <= 300:
    raise ValueError("Invalid approval lifetime configuration")
if os.getenv("JEV_GATEWAY_STATE_DB"):
    from app.approval.durable import SQLiteApprovalManager
    approval_manager = SQLiteApprovalManager(os.environ["JEV_GATEWAY_STATE_DB"], _pending_ttl, _grant_ttl)
else:
    approval_manager = ApprovalManager(_pending_ttl, _grant_ttl)
