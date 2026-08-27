"""
Tests for the Rate Limiter module.

Project Plan Ref: Task 3.20 (Phase 3 — Resilience & Rate Limiting)

TODO List:
    - [ ] Task 3.20 — Validate rate limiter integration with gateway
    - [ ] Task 7.5  — Validate rate limiting prevents resource exhaustion
    - [ ] Test per-tool independent rate limiting
    - [ ] Test burst handling
    - [ ] Test rate recovery after time passes

Covers:
    - Token bucket allows requests within capacity
    - Token bucket denies requests when exhausted
    - Tokens refill over time
    - RateLimiter creates per-tool buckets
    - Independent rate limiting per tool
"""

import time

import pytest

from app.gateway.rate_limiter import TokenBucket, RateLimiter


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


def test_bucket_allows_within_capacity() -> None:
    """Requests within burst capacity should be allowed."""
    bucket = TokenBucket(capacity=5, refill_rate=1.0)
    for _ in range(5):
        assert bucket.consume() is True


def test_bucket_denies_when_exhausted() -> None:
    """Requests beyond capacity should be denied."""
    bucket = TokenBucket(capacity=3, refill_rate=0.0)  # No refill
    for _ in range(3):
        bucket.consume()
    assert bucket.consume() is False


def test_bucket_refills_over_time() -> None:
    """After exhaustion, tokens should refill based on elapsed time."""
    bucket = TokenBucket(capacity=2, refill_rate=10.0)  # 10/sec
    bucket.consume()
    bucket.consume()
    assert bucket.consume() is False
    time.sleep(0.15)  # Should refill ~1.5 tokens
    assert bucket.consume() is True


def test_bucket_remaining_count() -> None:
    """remaining property should reflect current token count."""
    bucket = TokenBucket(capacity=10, refill_rate=0.0)
    assert bucket.remaining == 10
    bucket.consume()
    assert bucket.remaining == 9


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


def test_limiter_allows_default() -> None:
    """Default rate limiter should allow requests within burst."""
    limiter = RateLimiter(default_rpm=60, default_burst=5)
    assert limiter.check("summarize", agent_id="agent-a") is True


def test_limiter_per_tool_independence() -> None:
    """Rate limits should be independent per tool."""
    limiter = RateLimiter(default_rpm=60, default_burst=2)
    limiter.check("summarize", agent_id="agent-a")
    limiter.check("summarize", agent_id="agent-a")
    assert limiter.check("summarize", agent_id="agent-a") is False  # Exhausted
    assert limiter.check("fetch_url", agent_id="agent-a") is True   # Different tool, fresh bucket


def test_limiter_remaining() -> None:
    """remaining should reflect per-tool token count."""
    limiter = RateLimiter(default_rpm=60, default_burst=10)
    limiter.check("write_note", agent_id="agent-a")
    assert limiter.remaining("write_note", agent_id="agent-a") == 9


def test_limiter_per_agent_independence() -> None:
    """Different agents should not share token buckets for the same tool."""
    limiter = RateLimiter(default_rpm=60, default_burst=1)

    assert limiter.check("summarize", agent_id="agent-a") is True
    assert limiter.check("summarize", agent_id="agent-a") is False
    assert limiter.check("summarize", agent_id="agent-b") is True


def test_limiter_anonymous_normalization() -> None:
    """None/blank agent IDs should map to the same anonymous bucket."""
    limiter = RateLimiter(default_rpm=60, default_burst=1)

    assert limiter.check("summarize", agent_id=None) is True
    assert limiter.check("summarize", agent_id="") is False
