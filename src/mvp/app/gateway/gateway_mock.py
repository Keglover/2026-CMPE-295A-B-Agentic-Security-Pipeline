"""
Mock tool executors — safe for local development and testing.

All functions return fabricated strings. Nothing touches the network,
filesystem, or any external system. This is the default executor set
and is always safe to run, including on a developer's local machine.

To use real implementations instead, set REAL_TOOLS=true in the environment
and ensure gateway_real.py has fully implemented equivalents.
"""

from __future__ import annotations

from typing import Any, Callable


def _mock_summarize(args: dict[str, Any]) -> str:
    """
    Return a mock summary string.

    Args:
        args (dict): Must contain 'text' (str).

    Returns:
        str: Fake summary message.
    """
    text_preview = str(args.get("text", ""))[:60]
    return f"[MOCK] Summary of '{text_preview}...' generated successfully."


def _mock_write_note(args: dict[str, Any]) -> str:
    """
    Simulate writing a note — does NOT touch the filesystem.

    Args:
        args (dict): Must contain 'title' (str) and 'body' (str).

    Returns:
        str: Confirmation message only.
    """
    title = args.get("title", "untitled")
    return f"[MOCK] Note '{title}' saved to sandbox/notes/ (simulated)."


def _mock_search_notes(args: dict[str, Any]) -> str:
    """
    Return hardcoded mock search results.

    Args:
        args (dict): Must contain 'query' (str).

    Returns:
        str: Fake search result message.
    """
    query = args.get("query", "")
    return f"[MOCK] Found 2 notes matching '{query}': note_001, note_042."


def _mock_fetch_url(args: dict[str, Any]) -> str:
    """
    Return a fake webpage excerpt — does NOT make any network request.

    Args:
        args (dict): Must contain 'url' (str).

    Returns:
        str: Fake page content string.
    """
    url = args.get("url", "")
    return f"[MOCK] Content from '{url}': <p>Example page content (simulated).</p>"


# Exported registry consumed by gateway.py
EXECUTORS: dict[str, Callable[[dict[str, Any]], str]] = {
    "summarize": _mock_summarize,
    "write_note": _mock_write_note,
    "search_notes": _mock_search_notes,
    "fetch_url": _mock_fetch_url,
}
