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

from app.policy.config_loader import load_tool_registry


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

    def __init__(
        self,
        default_rpm: int = 60,
        default_burst: int = 10,
        use_registry_config: bool = False,
    ) -> None:
        self._default_rpm = default_rpm
        self._default_burst = default_burst
        self._per_tool_limits: dict[str, tuple[int, int]] = {}
        if use_registry_config:
            self._load_rate_limit_config()
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def _load_rate_limit_config(self) -> None:
        """Load optional global and per-tool rates from config/tool_registry.yaml."""
        limits: dict[str, tuple[int, int]] = {}
        try:
            registry = load_tool_registry()
            rate_limits = registry.get("rate_limits", {})
            global_cfg = rate_limits.get("global", {})
            self._default_rpm = int(global_cfg.get("requests_per_minute", self._default_rpm))
            self._default_burst = int(global_cfg.get("burst", self._default_burst))
            by_tool = rate_limits.get("by_tool", {})
            for tool_name, cfg in by_tool.items():
                rpm = int(cfg.get("requests_per_minute", self._default_rpm))
                burst = int(cfg.get("burst", self._default_burst))
                limits[tool_name] = (rpm, burst)
        except Exception:
            # Fail-open to defaults so rate limiting still protects the gateway.
            self._per_tool_limits = {}
            return
        self._per_tool_limits = limits

    def _resolve_limits(self, tool_name: str) -> tuple[int, int]:
        """Resolve effective rate limits for a tool."""
        if tool_name in self._per_tool_limits:
            return self._per_tool_limits[tool_name]
        return self._default_rpm, self._default_burst

    def _normalize_agent_id(self, agent_id: str | None) -> str:
        """Normalize missing/blank identities to a stable anonymous key."""
        if not agent_id or not agent_id.strip():
            return "anonymous"
        return agent_id.strip()

    def _get_or_create_bucket(self, tool_name: str, agent_id: str | None) -> TokenBucket:
        """Get existing bucket or create one per (agent_id, tool_name)."""
        agent_key = self._normalize_agent_id(agent_id)
        bucket_key = (agent_key, tool_name)

        if bucket_key not in self._buckets:
            with self._lock:
                if bucket_key not in self._buckets:
                    rpm, burst = self._resolve_limits(tool_name)
                    self._buckets[bucket_key] = TokenBucket(
                        capacity=burst,
                        refill_rate=rpm / 60.0,
                    )
        return self._buckets[bucket_key]

    def check(self, tool_name: str, agent_id: str | None = None) -> bool:
        """
        Check if a tool call is within rate limits.

        Args:
            tool_name: The tool being invoked.
            agent_id: Identifier of the calling agent.

        Returns:
            bool: True if allowed, False if rate limited.
        """
        bucket = self._get_or_create_bucket(tool_name, agent_id)
        return bucket.consume()

    def remaining(self, tool_name: str, agent_id: str | None = None) -> int:
        """Return remaining request budget for an (agent, tool) pair."""
        bucket = self._get_or_create_bucket(tool_name, agent_id)
        return bucket.remaining


# Module-level singleton — imported by gateway.py
rate_limiter = RateLimiter(use_registry_config=True)
