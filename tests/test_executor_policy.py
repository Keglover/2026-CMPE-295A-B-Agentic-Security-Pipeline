"""
Tests for executor_policy.py — per-tool timeout and retry semantics.

Covers:
  - Policy loading resolves correct per-tool config
  - Defaults apply when no by_tool override exists
  - Successful executor returns its value immediately
  - Timeout raises TimeoutError after the configured wall-clock limit
  - Non-retryable error is raised on first attempt without retry
  - Retryable error is retried up to max_attempts then re-raised
  - Retryable error that succeeds on a later attempt returns the value
  - All-attempts-exhausted emits a single clean RuntimeError
"""

from __future__ import annotations

import time
from unittest.mock import call, patch

import pytest

from app.gateway.executor_policy import (
    ExecutionPolicy,
    RetryPolicy,
    _is_retryable,
    _load_policy,
    run_with_policy,
)


# ---------------------------------------------------------------------------
# Helper executors
# ---------------------------------------------------------------------------


def _ok_executor(args: dict) -> str:
    return "ok"


def _slow_executor(args: dict) -> str:
    time.sleep(5)  # Will outlast tiny test timeout
    return "done"


def _fail_executor(args: dict) -> str:
    raise RuntimeError("connection refused")


def _permanent_fail_executor(args: dict) -> str:
    raise RuntimeError("invalid API key")


def _intermittent_executor(succeed_on: int):
    """Returns an executor that fails until attempt *succeed_on* (0-indexed)."""
    state = {"calls": 0}

    def executor(args: dict) -> str:
        n = state["calls"]
        state["calls"] += 1
        if n < succeed_on:
            raise RuntimeError("temporarily unavailable")
        return f"ok_on_attempt_{n}"

    return executor


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------


def test_load_policy_returns_execution_policy():
    policy = _load_policy("summarize")
    assert isinstance(policy, ExecutionPolicy)
    assert policy.tool_name == "summarize"


def test_load_policy_summarize_timeout():
    """summarize has a long timeout because LLM inference is slow."""
    policy = _load_policy("summarize")
    assert policy.timeout_sec >= 30.0  # Registry says 90s


def test_load_policy_fetch_url_timeout():
    """fetch_url should use a shorter timeout than summarize."""
    summarize_p = _load_policy("summarize")
    fetch_p = _load_policy("fetch_url")
    assert fetch_p.timeout_sec < summarize_p.timeout_sec


def test_load_policy_write_note_no_retry():
    """write_note is filesystem-only; no retry to avoid duplicate writes."""
    policy = _load_policy("write_note")
    assert policy.retry.max_attempts == 1


def test_load_policy_unknown_tool_uses_defaults():
    """Unknown tools should fall back to the global defaults, not error."""
    policy = _load_policy("nonexistent_tool_xyz")
    assert policy.timeout_sec > 0
    assert policy.retry.max_attempts >= 1


def test_load_policy_summarize_retryable_includes_timeout():
    policy = _load_policy("summarize")
    assert any("timeout" in r.lower() for r in policy.retry.retryable)


# ---------------------------------------------------------------------------
# _is_retryable helper
# ---------------------------------------------------------------------------


def test_is_retryable_match():
    assert _is_retryable("connection refused", ["timeout", "connect"]) is True


def test_is_retryable_no_match():
    assert _is_retryable("invalid api key", ["timeout", "connect"]) is False


def test_is_retryable_case_insensitive():
    assert _is_retryable("TIMEOUT exceeded", ["timeout"]) is True


# ---------------------------------------------------------------------------
# run_with_policy — success cases
# ---------------------------------------------------------------------------


def test_run_success_returns_value():
    result = run_with_policy("summarize", _ok_executor, {})
    assert result == "ok"


def test_run_success_no_retry_needed():
    """An executor that always succeeds should only be called once."""
    call_count = {"n": 0}

    def counting_executor(args):
        call_count["n"] += 1
        return "done"

    run_with_policy("summarize", counting_executor, {})
    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# run_with_policy — timeout
# ---------------------------------------------------------------------------


def test_run_timeout_raises_timeout_error():
    """A slow executor must be stopped by the policy timeout."""
    # summarize has 90s timeout from config — patch _load_policy to use 0.1s
    tiny_policy = ExecutionPolicy(
        tool_name="summarize",
        timeout_sec=0.1,
        retry=RetryPolicy(max_attempts=1),
    )
    with patch("app.gateway.executor_policy._load_policy", return_value=tiny_policy):
        with pytest.raises(TimeoutError):
            run_with_policy("summarize", _slow_executor, {})


# ---------------------------------------------------------------------------
# run_with_policy — retries
# ---------------------------------------------------------------------------


def test_run_non_retryable_error_raises_immediately():
    """Errors not in the retryable list must surface without retry."""
    call_count = {"n": 0}

    def executor(args):
        call_count["n"] += 1
        raise RuntimeError("invalid api key")

    non_retryable_policy = ExecutionPolicy(
        tool_name="summarize",
        timeout_sec=5.0,
        retry=RetryPolicy(max_attempts=3, retryable=["timeout", "connect"]),
    )
    with patch("app.gateway.executor_policy._load_policy", return_value=non_retryable_policy):
        with pytest.raises(RuntimeError, match="permanent error"):
            run_with_policy("summarize", executor, {})

    assert call_count["n"] == 1  # No retries


def test_run_retryable_error_retries_up_to_max():
    """A transient failure should be retried up to max_attempts times."""
    call_count = {"n": 0}

    def always_fails(args):
        call_count["n"] += 1
        raise RuntimeError("temporarily unavailable")

    retry_policy = ExecutionPolicy(
        tool_name="summarize",
        timeout_sec=5.0,
        retry=RetryPolicy(
            max_attempts=3,
            backoff_base=0.0,
            backoff_max=0.0,
            retryable=["temporarily unavailable"],
        ),
    )
    with patch("app.gateway.executor_policy._load_policy", return_value=retry_policy):
        with pytest.raises(RuntimeError):
            run_with_policy("summarize", always_fails, {})

    assert call_count["n"] == 3


def test_run_succeeds_on_second_attempt():
    """Verify the return value is correct when a retry succeeds."""
    retry_policy = ExecutionPolicy(
        tool_name="fetch_url",
        timeout_sec=5.0,
        retry=RetryPolicy(
            max_attempts=3,
            backoff_base=0.0,
            backoff_max=0.0,
            retryable=["temporarily unavailable"],
        ),
    )
    with patch("app.gateway.executor_policy._load_policy", return_value=retry_policy):
        result = run_with_policy(
            "fetch_url",
            _intermittent_executor(succeed_on=1),
            {},
        )
    assert result == "ok_on_attempt_1"


def test_run_fetch_url_retries_on_503():
    """fetch_url should retry on 503 patterns."""
    call_count = {"n": 0}

    def http_503(args):
        call_count["n"] += 1
        raise RuntimeError("HTTP 503 service unavailable")

    retry_policy = ExecutionPolicy(
        tool_name="fetch_url",
        timeout_sec=5.0,
        retry=RetryPolicy(
            max_attempts=3,
            backoff_base=0.0,
            backoff_max=0.0,
            retryable=["503"],
        ),
    )
    with patch("app.gateway.executor_policy._load_policy", return_value=retry_policy):
        with pytest.raises(RuntimeError):
            run_with_policy("fetch_url", http_503, {})

    assert call_count["n"] == 3


# ---------------------------------------------------------------------------
# Gateway integration — timeout surfaces as DENIED
# ---------------------------------------------------------------------------


def test_gateway_timeout_returns_denied():
    """A timed-out executor must DENIED the gateway result (not raise)."""
    from app.gateway.gateway import mediate
    from app.models import GatewayDecision, PolicyAction, PolicyResult, PipelineRequest, SourceType

    req = PipelineRequest(
        content="test",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="summarize",
        tool_args={"text": "hello"},
        request_id="timeout-test",
        agent_id="agent-test",
    )
    policy = PolicyResult(
        request_id="timeout-test",
        policy_action=PolicyAction.ALLOW,
        policy_reason="allow",
    )

    tiny_policy = ExecutionPolicy(
        tool_name="summarize",
        timeout_sec=0.05,
        retry=RetryPolicy(max_attempts=1),
    )

    def slow_mock(args):
        time.sleep(2)
        return "done"

    with patch("app.gateway.executor_policy._load_policy", return_value=tiny_policy):
        with patch("app.gateway.gateway._TOOL_EXECUTORS", {"summarize": slow_mock}):
            result = mediate(req, policy)

    assert result.gateway_decision == GatewayDecision.DENIED
    assert "timed out" in result.decision_reason.lower()
