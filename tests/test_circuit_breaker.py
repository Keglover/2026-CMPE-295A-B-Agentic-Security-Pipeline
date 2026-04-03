"""
Tests for the Circuit Breaker module.

Project Plan Ref: Tasks 3.21, 2.5 (Phase 3 — Resilience)

TODO List:
    - [ ] Task 3.21 — Validate circuit breaker integration with gateway
    - [ ] Task 2.5  — Validate circuit breaker for Policy Engine calls
    - [ ] Test concurrent access safety
    - [ ] Test registry health_summary endpoint

Covers:
    - CLOSED state allows requests
    - Consecutive failures transition to OPEN
    - OPEN state denies requests
    - Recovery timeout transitions to HALF_OPEN
    - Successful probe closes the circuit
    - Failed probe re-opens the circuit
    - Manual reset returns to CLOSED
    - Registry creates and manages independent breakers
"""

import time

import pytest

from app.gateway.circuit_breaker import CircuitBreaker, CircuitState, CircuitBreakerRegistry


# ---------------------------------------------------------------------------
# Basic state transitions
# ---------------------------------------------------------------------------


def test_starts_closed() -> None:
    """New circuit breaker should start in CLOSED state."""
    cb = CircuitBreaker(name="test", failure_threshold=3)
    assert cb.state == CircuitState.CLOSED


def test_closed_allows_requests() -> None:
    """CLOSED circuit should allow requests."""
    cb = CircuitBreaker(name="test", failure_threshold=3)
    assert cb.allow_request() is True


def test_failures_open_circuit() -> None:
    """Consecutive failures exceeding threshold should open the circuit."""
    cb = CircuitBreaker(name="test", failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False


def test_success_resets_failure_count() -> None:
    """A success should reset the failure count, preventing premature opening."""
    cb = CircuitBreaker(name="test", failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_success()
    cb.record_failure()  # Only 1 after reset
    assert cb.state == CircuitState.CLOSED


# ---------------------------------------------------------------------------
# OPEN → HALF_OPEN → CLOSED recovery
# ---------------------------------------------------------------------------


def test_open_transitions_to_half_open() -> None:
    """OPEN circuit should transition to HALF_OPEN after recovery timeout."""
    cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.allow_request() is True  # Probe allowed


def test_half_open_success_closes() -> None:
    """Successful probes in HALF_OPEN should close the circuit."""
    cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1, success_threshold=2)
    cb.record_failure()
    cb.record_failure()
    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_success()
    cb.record_success()
    assert cb.state == CircuitState.CLOSED


def test_half_open_failure_reopens() -> None:
    """A failure in HALF_OPEN should immediately reopen the circuit."""
    cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.1)
    cb.record_failure()
    cb.record_failure()
    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Manual reset
# ---------------------------------------------------------------------------


def test_reset_returns_to_closed() -> None:
    """Manual reset should force circuit back to CLOSED."""
    cb = CircuitBreaker(name="test", failure_threshold=2)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    cb.reset()
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_creates_breakers() -> None:
    """Registry should create breakers on demand."""
    registry = CircuitBreakerRegistry()
    cb = registry.get("tool_a")
    assert cb.name == "tool_a"
    assert cb.state == CircuitState.CLOSED


def test_registry_returns_same_instance() -> None:
    """Registry should return the same breaker for the same name."""
    registry = CircuitBreakerRegistry()
    cb1 = registry.get("tool_b")
    cb2 = registry.get("tool_b")
    assert cb1 is cb2


def test_registry_health_summary() -> None:
    """health_summary should report state of all breakers."""
    registry = CircuitBreakerRegistry()
    registry.get("healthy_tool")
    failing = registry.get("failing_tool")
    failing._failure_count = 999
    failing._state = CircuitState.OPEN
    summary = registry.health_summary()
    assert summary["healthy_tool"] == "closed"
    assert summary["failing_tool"] == "open"
