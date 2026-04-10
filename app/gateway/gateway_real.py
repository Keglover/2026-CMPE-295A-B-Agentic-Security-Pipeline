"""
Real tool executors — Sprint 2 implementations.

These functions make actual network calls, filesystem writes, and
external API requests. They MUST only be activated in an isolated
environment (Docker with network restrictions, or a VM).

To activate: set REAL_TOOLS=true in the Docker environment.
Default is REAL_TOOLS=false, which routes all calls to gateway_mock.py.

Executor implementations:
  - summarize:     Calls Ollama (local LLM) REST API
  - write_note:    Writes markdown files to a sandboxed directory
  - search_notes:  Searches note files in the sandboxed directory
  - fetch_url:     HTTP fetch with domain allowlist and SSRF protection
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

_log = logging.getLogger("gateway_real")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
_LLM_MODEL = os.getenv("LLM_MODEL", "mistral")

# Sandbox directory — /app/sandbox/notes/ in Docker, ./sandbox/notes/ locally
_SANDBOX_DIR = Path(os.getenv("SANDBOX_DIR", "/app/sandbox/notes"))

# Domain allowlist — loaded from gateway.py at import time; fallback here
_DOMAIN_ALLOWLIST: set[str] | None = None


def _get_domain_allowlist() -> set[str]:
    """Lazy-load domain allowlist from gateway config."""
    global _DOMAIN_ALLOWLIST
    if _DOMAIN_ALLOWLIST is None:
        try:
            from app.gateway.gateway import DOMAIN_ALLOWLIST as _da
            _DOMAIN_ALLOWLIST = set(_da)
        except ImportError:
            _DOMAIN_ALLOWLIST = {"example.com", "en.wikipedia.org"}
    return _DOMAIN_ALLOWLIST


# ---------------------------------------------------------------------------
# HTML stripping utility
# ---------------------------------------------------------------------------


class _HTMLStripper(HTMLParser):
    """Simple HTML tag stripper — extracts text content only."""

    def __init__(self) -> None:
        super().__init__()
        self._text = StringIO()
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._text.write(data)

    def get_text(self) -> str:
        return self._text.getvalue()


def _strip_html(html: str) -> str:
    """Remove HTML tags and return plain text."""
    stripper = _HTMLStripper()
    stripper.feed(html)
    return stripper.get_text()


# ---------------------------------------------------------------------------
# SSRF protection — block private/internal IP ranges
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a private/internal IP."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # Not an IP literal — will be resolved by httpx; we check the domain allowlist
        return False


# ---------------------------------------------------------------------------
# Real executor: summarize via Ollama
# ---------------------------------------------------------------------------


def _real_summarize(args: dict[str, Any]) -> str:
    """
    Call Ollama (local LLM inference server) to summarize text.

    Requires Ollama running at OLLAMA_HOST with model LLM_MODEL pulled.
    Default: http://localhost:11434 with 'mistral' model.
    """
    text = str(args.get("text", ""))
    if not text.strip():
        return "Error: no text provided for summarization."

    # Truncate to prevent huge prompts (50k char limit from tool_registry.yaml)
    text = text[:50000]

    prompt = (
        "Summarize the following text in 3-5 concise sentences. "
        "Focus on the key points and main ideas.\n\n"
        f"Text:\n{text}\n\nSummary:"
    )

    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(
                f"{_OLLAMA_HOST}/api/generate",
                json={
                    "model": _LLM_MODEL,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            summary = data.get("response", "").strip()
            if not summary:
                return "Error: LLM returned an empty response."
            return summary
    except httpx.TimeoutException:
        raise RuntimeError(f"Ollama request timed out after 60s (model: {_LLM_MODEL})")
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(f"Ollama returned HTTP {exc.response.status_code}: {exc.response.text[:200]}")
    except httpx.ConnectError:
        raise RuntimeError(
            f"Cannot connect to Ollama at {_OLLAMA_HOST}. "
            f"Ensure Ollama is running: 'ollama serve' or check OLLAMA_HOST env var."
        )


# ---------------------------------------------------------------------------
# Real executor: write_note to sandboxed filesystem
# ---------------------------------------------------------------------------

# Safe filename pattern — alphanumeric, dashes, underscores, spaces
_SAFE_TITLE_RE = re.compile(r"^[a-zA-Z0-9_\-\s]+$")


def _real_write_note(args: dict[str, Any]) -> str:
    """
    Write a markdown note to the sandboxed notes directory.

    Security: validates title against a safe pattern and verifies
    the resolved path stays inside the sandbox (prevents path traversal).
    """
    title = str(args.get("title", "")).strip()
    body = str(args.get("body", ""))

    if not title:
        return "Error: 'title' is required and cannot be empty."

    if len(title) > 200:
        return "Error: 'title' exceeds maximum length of 200 characters."

    if not _SAFE_TITLE_RE.match(title):
        return (
            "Error: 'title' contains invalid characters. "
            "Only alphanumeric characters, dashes, underscores, and spaces are allowed."
        )

    if len(body) > 10000:
        return "Error: 'body' exceeds maximum length of 10,000 characters."

    # Ensure sandbox exists
    _SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    # Build path and verify it's inside the sandbox (prevent traversal)
    filename = f"{title}.md"
    target = (_SANDBOX_DIR / filename).resolve()
    sandbox_resolved = _SANDBOX_DIR.resolve()

    if not str(target).startswith(str(sandbox_resolved)):
        return "Error: path traversal detected — write denied."

    target.write_text(body, encoding="utf-8")
    _log.info("Note written: %s (%d bytes)", target.name, len(body))
    return f"Note '{title}' saved to {target.name} ({len(body)} bytes)."


# ---------------------------------------------------------------------------
# Real executor: search_notes in sandboxed filesystem
# ---------------------------------------------------------------------------


def _real_search_notes(args: dict[str, Any]) -> str:
    """
    Search markdown notes in the sandbox directory by keyword.

    Returns matching filenames and first-line previews, capped at 20 results.
    """
    query = str(args.get("query", "")).strip().lower()
    if not query:
        return "Error: 'query' is required and cannot be empty."

    if not _SANDBOX_DIR.exists():
        return "No notes found — the notes directory is empty."

    matches: list[str] = []
    for note_path in sorted(_SANDBOX_DIR.glob("*.md")):
        try:
            content = note_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if query in content.lower():
            first_line = content.split("\n", 1)[0][:100]
            matches.append(f"  - {note_path.stem}: {first_line}")
        if len(matches) >= 20:
            break

    if not matches:
        return f"No notes matching '{query}'."

    header = f"Found {len(matches)} note(s) matching '{query}':\n"
    return header + "\n".join(matches)


# ---------------------------------------------------------------------------
# Real executor: fetch_url with domain allowlist and SSRF protection
# ---------------------------------------------------------------------------

_MAX_RESPONSE_BYTES = 1_000_000  # 1 MB


def _real_fetch_url(args: dict[str, Any]) -> str:
    """
    Fetch a URL over HTTP and return stripped text content.

    Security:
      - Only domains in the allowlist are permitted.
      - Private/internal IPs are blocked (SSRF protection).
      - Response is capped at 1 MB.
      - HTML tags are stripped; only text content is returned.
    """
    url = str(args.get("url", "")).strip()
    if not url:
        return "Error: 'url' is required."

    # Ensure scheme is present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Parse and validate URL
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return "Error: could not parse hostname from URL."

    # SSRF protection: block private IPs
    if _is_private_ip(hostname):
        return f"Error: access to private/internal address '{hostname}' is blocked."

    # Domain allowlist check
    allowlist = _get_domain_allowlist()
    domain_ok = any(
        hostname == d or hostname.endswith("." + d) for d in allowlist
    )
    if not domain_ok:
        return (
            f"Error: domain '{hostname}' is not in the allowlist. "
            f"Allowed domains: {sorted(allowlist)}."
        )

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, max_redirects=3) as client:
            resp = client.get(url, headers={"User-Agent": "AgenticSecurityPipeline/0.2"})
            resp.raise_for_status()

            # Cap response size
            content = resp.text[:_MAX_RESPONSE_BYTES]

            # Strip HTML to extract text
            text = _strip_html(content)
            # Collapse whitespace
            text = re.sub(r"\s+", " ", text).strip()

            # Return first 5000 chars
            if len(text) > 5000:
                text = text[:5000] + "... [truncated]"

            return text if text else "Page fetched but no text content found."

    except httpx.TimeoutException:
        return f"Error: request to '{hostname}' timed out after 10s."
    except httpx.HTTPStatusError as exc:
        return f"Error: HTTP {exc.response.status_code} from '{hostname}'."
    except httpx.ConnectError:
        return f"Error: could not connect to '{hostname}'."


# Exported registry consumed by gateway.py
EXECUTORS: dict[str, Callable[[dict[str, Any]], str]] = {
    "summarize": _real_summarize,
    "write_note": _real_write_note,
    "search_notes": _real_search_notes,
    "fetch_url": _real_fetch_url,
}
