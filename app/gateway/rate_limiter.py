"""
Rate Limiter for Tool Gateway.

Project Plan Ref: Task 3.20 (Phase 3 — Resilience & Rate Limiting)

Implements per-tool rate limiting using a token bucket algorithm to prevent
resource exhaustion and abuse of external tool backends.

TODO List:
    - [ ] Task 3.20 — Implement token bucket algorithm with configurable rates
    - [ ] Wire into gateway.py mediate() before executor dispatch
    - [ ] Load rate limit config from config/tool_registry.yaml
    - [ ] Add 429 Too Many Requests response to API when limit exceeded
    - [ ] Add rate limit headers (X-RateLimit-Remaining, X-RateLimit-Reset)
    - [ ] Add per-agent rate limiting (requires agent identity in request)
    - [ ] Add rate limit metrics to audit log
    - [ ] Write unit tests in tests/test_rate_limiter.py
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """
    Token bucket rate limiter for a single tool.

    Args:
        capacity: Maximum number of tokens (burst size).
        refill_rate: Tokens added per second.
    """

    capacity: int
    refill_rate: float
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens. Returns True if allowed, False if rate limited.

        Args:
            tokens: Number of tokens to consume (default: 1 per request).

        Returns:
            bool: True if request is permitted, False if rate limited.
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    @property
    def remaining(self) -> int:
        """Return approximate number of remaining tokens."""
        with self._lock:
            self._refill()
            return int(self._tokens)


class RateLimiter:
    """
    Per-tool rate limiter registry.

    Creates and manages TokenBucket instances for each tool, using
    configuration from the tool registry.

    TODO: [ ] Load config from config/tool_registry.yaml rate_limits section
    TODO: [ ] Support dynamic config reload without restart
    """

    def __init__(self, default_rpm: int = 60, default_burst: int = 10) -> None:
        self._default_rpm = default_rpm
        self._default_burst = default_burst
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_or_create_bucket(self, tool_name: str) -> TokenBucket:
        """Get existing bucket or create one with defaults."""
        if tool_name not in self._buckets:
            with self._lock:
                if tool_name not in self._buckets:
                    self._buckets[tool_name] = TokenBucket(
                        capacity=self._default_burst,
                        refill_rate=self._default_rpm / 60.0,
                    )
        return self._buckets[tool_name]

    def check(self, tool_name: str) -> bool:
        """
        Check if a tool call is within rate limits.

        Args:
            tool_name: The tool being invoked.

        Returns:
            bool: True if allowed, False if rate limited.
        """
        bucket = self._get_or_create_bucket(tool_name)
        return bucket.consume()

    def remaining(self, tool_name: str) -> int:
        """Return remaining request budget for a tool."""
        bucket = self._get_or_create_bucket(tool_name)
        return bucket.remaining


# Module-level singleton — imported by gateway.py
# TODO: [ ] Initialize from config/tool_registry.yaml at startup
rate_limiter = RateLimiter()
