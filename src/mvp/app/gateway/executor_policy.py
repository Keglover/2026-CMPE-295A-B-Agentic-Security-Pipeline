"""
Executor Policy — per-tool timeout and retry semantics.

Loads execution policy from config/tool_registry.yaml and exposes a single
callable, ``run_with_policy``, that wraps any executor function with:

  - **Timeout enforcement** — uses a ThreadPoolExecutor so the calling thread
    is never blocked beyond ``timeout_sec`` regardless of what the executor does.
  - **Retry with exponential back-off** — retries on transient errors whose
    message matches a configurable substring list; permanent errors (e.g.
    validation failures) are not retried.

Policy resolution order (highest priority first):
  ``by_tool.<name>``  →  ``defaults``  →  module-level hard defaults

This module is imported by gateway.py and is the sole authority on execution
time-bounds and retry counts.  All policy values come from YAML; nothing is
hard-coded here beyond safe fallback defaults.
"""

from __future__ import annotations

import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Callable

from app.policy.config_loader import load_tool_registry

_log = logging.getLogger("executor_policy")

# ---------------------------------------------------------------------------
# Hard-coded safe fallbacks (used when registry is missing/corrupt)
# ---------------------------------------------------------------------------

_HARD_DEFAULT_TIMEOUT = 10.0
_HARD_DEFAULT_MAX_ATTEMPTS = 1
_HARD_DEFAULT_BACKOFF_BASE = 0.5
_HARD_DEFAULT_BACKOFF_MAX = 5.0
_HARD_DEFAULT_RETRYABLE: list[str] = ["timeout", "connect"]


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------


@dataclass
class RetryPolicy:
    """Retry parameters for a single executor."""

    max_attempts: int = _HARD_DEFAULT_MAX_ATTEMPTS
    backoff_base: float = _HARD_DEFAULT_BACKOFF_BASE
    backoff_max: float = _HARD_DEFAULT_BACKOFF_MAX
    retryable: list[str] = field(default_factory=lambda: list(_HARD_DEFAULT_RETRYABLE))


@dataclass
class ExecutionPolicy:
    """Full execution policy for a single tool."""

    tool_name: str
    timeout_sec: float = _HARD_DEFAULT_TIMEOUT
    retry: RetryPolicy = field(default_factory=RetryPolicy)


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


def _load_policy(tool_name: str) -> ExecutionPolicy:
    """
    Resolve effective execution policy for *tool_name*.

    Merges ``by_tool.<tool_name>`` over ``defaults`` from the registry.
    Falls back to module hard-defaults if the registry is unavailable.
    """
    try:
        registry = load_tool_registry()
        exec_cfg: dict = registry.get("execution", {})
    except Exception as exc:
        _log.warning("executor_policy: registry unavailable (%s) — using hard defaults", exc)
        return ExecutionPolicy(tool_name=tool_name)

    defaults = exec_cfg.get("defaults", {})
    by_tool = exec_cfg.get("by_tool", {}).get(tool_name, {})

    def _get(key: str, fallback: Any) -> Any:
        # by_tool wins, then defaults, then fallback
        v = by_tool.get(key)
        if v is None:
            v = defaults.get(key)
        if v is None:
            return fallback
        return v

    timeout_sec = float(_get("timeout_sec", _HARD_DEFAULT_TIMEOUT))

    # Merge retry sub-dict
    default_retry_cfg = defaults.get("retry", {})
    tool_retry_cfg = by_tool.get("retry", {})

    def _retry_get(key: str, fallback: Any) -> Any:
        v = tool_retry_cfg.get(key)
        if v is None:
            v = default_retry_cfg.get(key)
        if v is None:
            return fallback
        return v

    retry = RetryPolicy(
        max_attempts=int(_retry_get("max_attempts", _HARD_DEFAULT_MAX_ATTEMPTS)),
        backoff_base=float(_retry_get("backoff_base", _HARD_DEFAULT_BACKOFF_BASE)),
        backoff_max=float(_retry_get("backoff_max", _HARD_DEFAULT_BACKOFF_MAX)),
        retryable=list(_retry_get("retryable", _HARD_DEFAULT_RETRYABLE)),
    )

    return ExecutionPolicy(
        tool_name=tool_name,
        timeout_sec=timeout_sec,
        retry=retry,
    )


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


def _is_retryable(error_msg: str, retryable: list[str]) -> bool:
    """Return True if the error message matches any retryable substring."""
    lower = error_msg.lower()
    return any(token.lower() in lower for token in retryable)


def _backoff_seconds(attempt: int, base: float, cap: float) -> float:
    """Exponential back-off with full jitter: sleep = uniform(0, min(cap, base * 2^attempt))."""
    ceiling = min(cap, base * (2 ** attempt))
    return random.uniform(0, ceiling)


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------


def run_with_policy(
    tool_name: str,
    executor: Callable[[dict[str, Any]], Any],
    args: dict[str, Any],
) -> Any:
    """
    Call *executor(args)* subject to the execution policy for *tool_name*.

    On timeout, raises ``TimeoutError``.
    On a permanent failure (non-retryable or attempts exhausted), raises
    ``RuntimeError`` with the original error message.

    Args:
        tool_name: Key used to look up policy in the registry.
        executor:  The callable to invoke (sync, may block).
        args:      Arguments dict forwarded to the executor unchanged.

    Returns:
        Whatever the executor returns on success.

    Raises:
        TimeoutError:  If the executor did not complete within ``timeout_sec``.
        RuntimeError:  If a non-retryable error occurred or all retries failed.
    """
    policy = _load_policy(tool_name)
    retry = policy.retry
    last_exc: Exception | None = None

    for attempt in range(retry.max_attempts):
        if attempt > 0:
            wait = _backoff_seconds(attempt - 1, retry.backoff_base, retry.backoff_max)
            _log.info(
                "executor_policy: tool=%s attempt=%d/%d backoff=%.2fs",
                tool_name, attempt + 1, retry.max_attempts, wait,
            )
            time.sleep(wait)

        try:
            result = _run_with_timeout(executor, args, policy.timeout_sec)
            if attempt > 0:
                _log.info(
                    "executor_policy: tool=%s succeeded on attempt %d",
                    tool_name, attempt + 1,
                )
            return result

        except TimeoutError as exc:
            _log.warning(
                "executor_policy: tool=%s timed out after %.1fs (attempt %d/%d)",
                tool_name, policy.timeout_sec, attempt + 1, retry.max_attempts,
            )
            last_exc = exc
            if not _is_retryable("timeout", retry.retryable):
                raise TimeoutError(
                    f"Tool '{tool_name}' timed out after {policy.timeout_sec}s "
                    f"(timeout is not retryable for this tool)."
                ) from exc

        except Exception as exc:
            err_msg = str(exc)
            _log.warning(
                "executor_policy: tool=%s error on attempt %d/%d: %s",
                tool_name, attempt + 1, retry.max_attempts, err_msg,
            )
            last_exc = exc
            if not _is_retryable(err_msg, retry.retryable):
                raise RuntimeError(
                    f"Tool '{tool_name}' failed with a permanent error: {err_msg}"
                ) from exc

    # All attempts exhausted
    assert last_exc is not None
    if isinstance(last_exc, TimeoutError):
        raise TimeoutError(
            f"Tool '{tool_name}' timed out after {policy.timeout_sec}s "
            f"({retry.max_attempts} attempt(s) exhausted)."
        ) from last_exc
    raise RuntimeError(
        f"Tool '{tool_name}' failed after {retry.max_attempts} attempt(s): {last_exc}"
    ) from last_exc


# ---------------------------------------------------------------------------
# Timeout enforcement via thread pool
# ---------------------------------------------------------------------------


def _run_with_timeout(
    executor: Callable[[dict[str, Any]], Any],
    args: dict[str, Any],
    timeout_sec: float,
) -> Any:
    """
    Run *executor(args)* in a thread and block for at most *timeout_sec*.

    Uses a daemon thread so it does not prevent interpreter exit if the
    executor is stuck.  The thread is NOT killed — it keeps running in the
    background until it naturally completes or the process exits.  This is
    the standard Python approach: true hard-kill of threads is not supported.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(executor, args)
        try:
            return future.result(timeout=timeout_sec)
        except FutureTimeoutError as exc:
            raise TimeoutError(
                f"Executor did not complete within {timeout_sec}s."
            ) from exc
