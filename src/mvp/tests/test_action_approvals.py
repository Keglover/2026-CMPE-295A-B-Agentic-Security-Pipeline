"""Approval authority cannot be replayed, changed, expired or raced."""

from concurrent.futures import ThreadPoolExecutor
import time

import pytest

from app.approval.workflow import ApprovalManager, ApprovalStatus, approval_manager
from app.gateway import gateway
from app.models import PipelineRequest, PolicyAction, PolicyResult


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    manager = ApprovalManager()
    monkeypatch.setattr(gateway, "approval_manager", manager)
    monkeypatch.setattr(gateway.rate_limiter, "check", lambda *a, **k: True)
    monkeypatch.setattr(gateway.circuit_registry.get("execute_command"), "allow_request", lambda: True)
    return manager


def action():
    return PipelineRequest(request_id="bound-action", content="Print a greeting",
                           proposed_tool="execute_command", tool_args={"command": "echo hello"},
                           agent_id="alice")


def policy():
    return PolicyResult(request_id="bound-action", policy_action=PolicyAction.ALLOW, policy_reason="Safe")


def approved(manager):
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_REQUIRED"
    assert manager.approve("bound-action", approved_by="reviewer")


@pytest.mark.parametrize("change", [
    {"tool_args": {"command": "echo changed"}}, {"content": "Changed intent"},
    {"agent_id": "mallory"}, {"source_type": "retrieved_content"},
    {"proposed_tool": "summarize", "tool_args": {"text": "Hello"}},
])
def test_changed_action_cannot_inherit_approval(isolated, change):
    approved(isolated)
    changed = PipelineRequest.model_validate(action().model_dump() | change)
    assert gateway.mediate(changed, policy()).reason_code == "APPROVAL_ACTION_MISMATCH"


def test_registry_change_invalidates_approval(isolated, monkeypatch):
    approved(isolated)
    monkeypatch.setattr(gateway, "REGISTRY_VERSION", "new-version")
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_ACTION_MISMATCH"


def test_approval_consumed_once_under_race(isolated, monkeypatch):
    approved(isolated)
    calls = []
    monkeypatch.setitem(gateway._TOOL_EXECUTORS, "execute_command", lambda args: calls.append(args) or "hello")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: gateway.mediate(action(), policy()), range(8)))
    assert sum(r.reason_code == "EXECUTED" for r in results) == 1
    assert len(calls) == 1
    assert isolated.get_status("bound-action").status == ApprovalStatus.CONSUMED


def test_expired_pending_cannot_be_approved(isolated):
    gateway.mediate(action(), policy())
    isolated.get_status("bound-action").expires_at = time.time() - 1
    assert isolated.approve("bound-action") is None
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_NOT_VALID"


def test_expired_approved_cannot_be_consumed(isolated):
    approved(isolated)
    isolated.get_status("bound-action").expires_at = time.time() - 1
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_NOT_VALID"


def test_unbound_legacy_record_cannot_authorize_execution(isolated):
    isolated.submit("bound-action", 0, [], "execute_command")
    isolated.approve("bound-action")
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_ACTION_MISMATCH"


@pytest.mark.parametrize("args", [{"command": 123}, {"command": "echo hi", "extra": True},
                                  {"command": "x" * 4001}])
def test_invalid_arguments_do_not_queue(isolated, args):
    result = gateway.mediate(action().model_copy(update={"tool_args": args}), policy())
    assert result.gateway_decision.value == "DENIED"
    assert isolated.pending_count == 0


def test_caller_domains_do_not_authorize_execution(isolated):
    req = PipelineRequest(content="Read a page", proposed_tool="fetch_url",
                          tool_args={"url": "https://untrusted.invalid"},
                          approved_domains=["untrusted.invalid"])
    assert gateway.mediate(req, policy()).reason_code == "DOMAIN_DENIED"


def test_approved_action_is_consumed_even_if_execution_fails(isolated, monkeypatch):
    from app.gateway.executor_policy import ExecutionPolicy, RetryPolicy
    approved(isolated)
    calls = []
    def fail(args):
        calls.append(args)
        raise RuntimeError("temporarily unavailable")
    monkeypatch.setitem(gateway._TOOL_EXECUTORS, "execute_command", fail)
    monkeypatch.setattr("app.gateway.executor_policy._load_policy", lambda _: ExecutionPolicy(
        tool_name="execute_command", retry=RetryPolicy(max_attempts=3, backoff_base=0)))
    assert gateway.mediate(action(), policy()).reason_code == "EXECUTION_FAILED"
    assert len(calls) == 1
    assert gateway.mediate(action(), policy()).reason_code == "APPROVAL_CONSUMED"
