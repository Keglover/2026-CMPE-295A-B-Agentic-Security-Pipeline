"""
Tests for the Approval Workflow module.

Project Plan Ref: Tasks 4.11–4.15, 7.10

TODO List:
    - [ ] Task 4.11 — Test POST /approve/{request_id} endpoint
    - [ ] Task 4.13 — Test approval timeout auto-deny
    - [ ] Task 4.14 — Test approval audit trail entries
    - [ ] Task 7.10 — Test race conditions (double-approve, approve-after-timeout)
    - [ ] Test concurrent approval submissions
    - [ ] Test rejection workflow
    - [ ] Test list_pending and get_status queries

Covers:
    - Submit a request for approval and verify PENDING state
    - Approve a pending request and verify APPROVED state
    - Reject a pending request and verify REJECTED state
    - Timeout enforcement auto-denies expired requests
    - Double-approve returns None (idempotency)
    - Approve after timeout returns None
    - List pending returns correct set
"""

import time

import pytest

from app.approval.workflow import ApprovalManager, ApprovalStatus


@pytest.fixture
def manager() -> ApprovalManager:
    """Fresh approval manager for each test."""
    return ApprovalManager(timeout_seconds=2.0)


# ---------------------------------------------------------------------------
# Submit and status
# ---------------------------------------------------------------------------


def test_submit_creates_pending_record(manager: ApprovalManager) -> None:
    """Submitting a request should create a PENDING record."""
    record = manager.submit(
        request_id="test-001",
        risk_score=45,
        risk_categories=["INSTRUCTION_OVERRIDE"],
        proposed_tool="summarize",
    )
    assert record.status == ApprovalStatus.PENDING
    assert record.request_id == "test-001"
    assert manager.pending_count == 1


def test_get_status_returns_pending(manager: ApprovalManager) -> None:
    """get_status should find a pending request."""
    manager.submit("test-002", 40, ["TOOL_COERCION"])
    status = manager.get_status("test-002")
    assert status is not None
    assert status.status == ApprovalStatus.PENDING


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------


def test_approve_transitions_to_approved(manager: ApprovalManager) -> None:
    """Approving a pending request should transition to APPROVED."""
    manager.submit("test-003", 50, ["DATA_EXFILTRATION"], "fetch_url")
    record = manager.approve("test-003", approved_by="reviewer_a", reason="Verified safe")
    assert record is not None
    assert record.status == ApprovalStatus.APPROVED
    assert record.resolved_by == "reviewer_a"
    assert manager.pending_count == 0


def test_approve_nonexistent_returns_none(manager: ApprovalManager) -> None:
    """Approving a request that doesn't exist should return None."""
    result = manager.approve("nonexistent-id")
    assert result is None


def test_double_approve_returns_none(manager: ApprovalManager) -> None:
    """Approving an already-approved request should return None (idempotent)."""
    manager.submit("test-004", 40, ["OBFUSCATION"])
    manager.approve("test-004")
    second = manager.approve("test-004")
    assert second is None


# ---------------------------------------------------------------------------
# Reject
# ---------------------------------------------------------------------------


def test_reject_transitions_to_rejected(manager: ApprovalManager) -> None:
    """Rejecting a pending request should transition to REJECTED."""
    manager.submit("test-005", 55, ["TOOL_COERCION"], "write_note")
    record = manager.reject("test-005", rejected_by="reviewer_b", reason="Too risky")
    assert record is not None
    assert record.status == ApprovalStatus.REJECTED
    assert manager.pending_count == 0


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


def test_timeout_auto_denies(manager: ApprovalManager) -> None:
    """Pending requests past timeout should be auto-denied."""
    manager._timeout = 0.1  # 100ms for fast test
    manager.submit("test-006", 35, ["INSTRUCTION_OVERRIDE"])
    time.sleep(0.2)
    timed_out = manager.check_timeouts()
    assert len(timed_out) == 1
    assert timed_out[0].status == ApprovalStatus.TIMED_OUT
    assert manager.pending_count == 0


def test_approve_after_timeout_returns_none(manager: ApprovalManager) -> None:
    """Approving a timed-out request should return None."""
    manager._timeout = 0.1
    manager.submit("test-007", 45, ["DATA_EXFILTRATION"])
    time.sleep(0.2)
    manager.check_timeouts()
    result = manager.approve("test-007")
    assert result is None


# ---------------------------------------------------------------------------
# List pending
# ---------------------------------------------------------------------------


def test_list_pending_returns_all(manager: ApprovalManager) -> None:
    """list_pending should return all pending requests."""
    manager.submit("a", 30, [])
    manager.submit("b", 40, [])
    manager.submit("c", 50, [])
    manager.approve("b")
    pending = manager.list_pending()
    assert len(pending) == 2
    pending_ids = {r.request_id for r in pending}
    assert pending_ids == {"a", "c"}
