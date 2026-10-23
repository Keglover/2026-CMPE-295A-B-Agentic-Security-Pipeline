"""
Circuit Breaker for Tool Gateway downstream calls.

Project Plan Ref: Tasks 3.21, 2.5 (Phase 3 — Resilience & Rate Limiting)

Implements the circuit breaker pattern (closed → open → half-open) to handle
downstream tool backend and Policy Engine failures gracefully, preventing
cascading failures and reducing latency during outages.

Reference: Search "circuit breaker pattern Martin Fowler" for the canonical
description of this state machine.

TODO List:
    - [ ] Task 3.21 — Wire circuit breaker into gateway executor dispatch
    - [ ] Task 2.5  — Wire circuit breaker for Policy Engine calls
    - [ ] Task 3.22 — Implement graceful degradation mode (all tools unavailable)
    - [ ] Configure thresholds from config file or environment variables
    - [ ] Add circuit breaker state to /health endpoint response
    - [ ] Add circuit breaker state transitions to audit log
    - [ ] Write unit tests in tests/test_circuit_breaker.py
"""

from __future__ import annotations

import time
import threading
import logging
from enum import Enum
from dataclasses import dataclass, field

_log = logging.getLogger("circuit_breaker")


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"          # Normal operation — requests pass through
    OPEN = "open"              # Failure threshold exceeded — requests rejected
    HALF_OPEN = "half_open"    # Recovery probe — one test request allowed


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for a single downstream dependency.

    State machine:
        CLOSED  → (failure_threshold exceeded) → OPEN
        OPEN    → (recovery_timeout elapsed)   → HALF_OPEN
        HALF_OPEN → (probe succeeds)           → CLOSED
        HALF_OPEN → (probe fails)              → OPEN

    Args:
        name: Identifier for this circuit (e.g., tool name or "policy_engine").
        failure_threshold: Number of consecutive failures before opening.
        recovery_timeout: Seconds to wait in OPEN before trying HALF_OPEN.
        success_threshold: Consecutive successes in HALF_OPEN to close.
    """

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    success_threshold: int = 2
    _state: CircuitState = field(init=False, default=CircuitState.CLOSED)
    _failure_count: int = field(init=False, default=0)
    _success_count: int = field(init=False, default=0)
    _last_failure_time: float = field(init=False, default=0.0)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    _log.info("Circuit '%s' transitioning OPEN → HALF_OPEN", self.name)
            return self._state

    def allow_request(self) -> bool:
        """
        Check if a request should be allowed through the circuit.

        Returns:
            bool: True if the request may proceed, False if circuit is open.
        """
        current = self.state
        if current == CircuitState.CLOSED:
            return True
        if current == CircuitState.HALF_OPEN:
            return True  # Allow probe request
        return False  # OPEN — reject

    def record_success(self) -> None:
        """Record a successful call. May transition HALF_OPEN → CLOSED."""
        with self._lock:
            self._failure_count = 0
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    _log.info("Circuit '%s' recovered: HALF_OPEN → CLOSED", self.name)

    def record_failure(self) -> None:
        """Record a failed call. May transition CLOSED → OPEN or HALF_OPEN → OPEN."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                _log.warning("Circuit '%s' probe failed: HALF_OPEN → OPEN", self.name)
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                _log.warning(
                    "Circuit '%s' opened after %d failures",
                    self.name,
                    self._failure_count,
                )

    def reset(self) -> None:
        """Force-reset the circuit to CLOSED state (for testing/admin use)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            _log.info("Circuit '%s' manually reset to CLOSED", self.name)


class CircuitBreakerRegistry:
    """
    Registry of circuit breakers for all downstream dependencies.

    Creates breakers on demand and provides a unified interface for
    checking health across all downstreams.

    TODO: [ ] Load thresholds from config file
    TODO: [ ] Expose circuit state via /health endpoint
    """

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> CircuitBreaker:
        """Get or create a circuit breaker by name."""
        if name not in self._breakers:
            with self._lock:
                if name not in self._breakers:
                    self._breakers[name] = CircuitBreaker(name=name)
        return self._breakers[name]

    def health_summary(self) -> dict[str, str]:
        """Return a dict of breaker name → current state for health checks."""
        return {name: cb.state.value for name, cb in self._breakers.items()}


# Module-level singleton — imported by gateway.py and main.py
# TODO: [ ] Initialize from config at startup
circuit_registry = CircuitBreakerRegistry()
