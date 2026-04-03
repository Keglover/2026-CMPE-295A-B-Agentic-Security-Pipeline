"""
Real tool executors — Sprint 2 implementation stubs.

These functions will make actual network calls, filesystem writes, and
external API requests. They MUST only be activated in an isolated
environment (Docker with network restrictions, or a VM).

DO NOT enable in production or on a developer's local machine until:
  1. Each function is fully implemented and reviewed.
  2. The container runs with Docker network restrictions (internal: true
     or an allowlisted egress proxy — see docker-compose.yml).
  3. Volume mounts are restricted to ./audit_logs only.

To activate: set REAL_TOOLS=true in the Docker environment.
Default is REAL_TOOLS=false, which routes all calls to gateway_mock.py.

Reason: failing loudly (NotImplementedError) on accidental activation is
safer than silently falling back — it makes the misconfiguration obvious.
"""

from __future__ import annotations

from typing import Any, Callable


def _real_summarize(args: dict[str, Any]) -> str:
    """
    Call an LLM summarisation endpoint with the provided text.

    TODO (Sprint 2): Implement with OpenAI or local model API.

    Args:
        args (dict): Must contain 'text' (str).

    Returns:
        str: Summarised text from the model.

    Raises:
        NotImplementedError: Until Sprint 2 implementation is complete.
    """
    raise NotImplementedError(
        "Real summarize tool not yet implemented. "
        "Set REAL_TOOLS=false to use mock executors."
    )


def _real_write_note(args: dict[str, Any]) -> str:
    """
    Write a note to the sandbox notes directory on the container filesystem.

    TODO (Sprint 2): Implement with pathlib, writing only under
    /app/sandbox/notes/ inside the container. Never write to a host-mounted
    path outside of the explicitly allowed audit_logs volume.

    Args:
        args (dict): Must contain 'title' (str) and 'body' (str).

    Returns:
        str: Confirmation with the written file path.

    Raises:
        NotImplementedError: Until Sprint 2 implementation is complete.
    """
    raise NotImplementedError(
        "Real write_note tool not yet implemented. "
        "Set REAL_TOOLS=false to use mock executors."
    )


def _real_search_notes(args: dict[str, Any]) -> str:
    """
    Search notes written by write_note within the sandbox directory.

    TODO (Sprint 2): Implement with simple file glob or SQLite FTS.

    Args:
        args (dict): Must contain 'query' (str).

    Returns:
        str: Matching note titles and snippets.

    Raises:
        NotImplementedError: Until Sprint 2 implementation is complete.
    """
    raise NotImplementedError(
        "Real search_notes tool not yet implemented. "
        "Set REAL_TOOLS=false to use mock executors."
    )


def _real_fetch_url(args: dict[str, Any]) -> str:
    """
    Fetch a URL over HTTP and return stripped text content.

    TODO (Sprint 2): Implement with httpx; enforce domain allowlist;
    cap response size; strip scripts and dangerous HTML.

    IMPORTANT: This function makes real outbound HTTP requests.
    Only activate inside a Docker container with network restrictions.

    Args:
        args (dict): Must contain 'url' (str).

    Returns:
        str: Stripped text content of the page.

    Raises:
        NotImplementedError: Until Sprint 2 implementation is complete.
    """
    raise NotImplementedError(
        "Real fetch_url tool not yet implemented. "
        "Set REAL_TOOLS=false to use mock executors."
    )


# Exported registry consumed by gateway.py
EXECUTORS: dict[str, Callable[[dict[str, Any]], str]] = {
    "summarize": _real_summarize,
    "write_note": _real_write_note,
    "search_notes": _real_search_notes,
    "fetch_url": _real_fetch_url,
}
