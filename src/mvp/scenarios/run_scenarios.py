"""
Scenario runner for the Agentic Security Pipeline.

Loads scenario JSON files, POSTs each one to the pipeline, and compares
the response against the _expected block defined in each file.

Usage (from src/mvp/):
    python -m scenarios.run_scenarios

The pipeline server must be running before executing this script:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

import httpx

from agent.config import PIPELINE_URL

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s — %(message)s",
)
_log = logging.getLogger("run_scenarios")

# ---------------------------------------------------------------------------
# Derive sibling endpoint URLs from PIPELINE_URL
# e.g. http://localhost:8000/pipeline → http://localhost:8000
# ---------------------------------------------------------------------------

_parsed = urlparse(PIPELINE_URL)
BASE_URL: str = f"{_parsed.scheme}://{_parsed.netloc}"
HEALTH_URL: str = f"{BASE_URL}/health"
TOOLS_URL: str = f"{BASE_URL}/tools"

SCENARIOS_DIR: Path = Path(__file__).resolve().parent / "json files"

# ---------------------------------------------------------------------------
# Endpoint connections
# ---------------------------------------------------------------------------


def check_health() -> bool:
    """
    GET /health — confirm the pipeline server is reachable and alive.

    Returns:
        True if the server responds with status ok, False otherwise.
    """
    _log.info("Checking pipeline health at %s", HEALTH_URL)
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(HEALTH_URL)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                _log.info("Pipeline is healthy (version=%s)", data.get("version", "?"))
                return True
            _log.error("Unexpected health response: %s", data)
            return False
    except httpx.ConnectError:
        _log.error(
            "Cannot reach pipeline at %s — is the server running?", BASE_URL
        )
        return False
    except httpx.HTTPStatusError as exc:
        _log.error("Health check returned HTTP %d", exc.response.status_code)
        return False


def fetch_allowed_tools() -> set[str]:
    """
    GET /tools — retrieve the set of tool names the gateway will permit.

    Used to pre-validate scenario files before sending them to the pipeline,
    so a misconfigured proposed_tool fails early with a clear error rather
    than silently producing a DENIED gateway result.

    Returns:
        Set of allowed tool name strings, or empty set on failure.
    """
    _log.info("Fetching allowed tools from %s", TOOLS_URL)
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(TOOLS_URL)
            resp.raise_for_status()
            data = resp.json()
            tools = set(data.get("allowed_tools", {}).keys())
            _log.info("Allowed tools: %s", sorted(tools))
            return tools
    except httpx.ConnectError:
        _log.error("Cannot reach /tools endpoint")
        return set()
    except httpx.HTTPStatusError as exc:
        _log.error("/tools returned HTTP %d", exc.response.status_code)
        return set()


def run_scenario(payload: dict) -> dict | None:
    """
    POST /pipeline — submit a single scenario payload and return the response.

    The _expected block must be stripped from the payload before calling this.

    Args:
        payload: A PipelineRequest-shaped dict (no _expected, no _comment).

    Returns:
        The full PipelineResponse dict, or None if the request failed.
    """
    request_id = payload.get("request_id", "<auto>")
    _log.info("POSTing scenario request_id=%s to %s", request_id, PIPELINE_URL)
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(PIPELINE_URL, json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        _log.error("Cannot reach pipeline at %s", PIPELINE_URL)
        return None
    except httpx.HTTPStatusError as exc:
        _log.error(
            "Pipeline returned HTTP %d: %s",
            exc.response.status_code,
            exc.response.text[:200],
        )
        return None


# ---------------------------------------------------------------------------
# Entry point — basic connectivity smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _log.info("=== Scenario Runner starting ===")
    _log.info("Base URL : %s", BASE_URL)
    _log.info("Scenarios: %s", SCENARIOS_DIR)

    # Step 1: health gate — abort immediately if server is down
    if not check_health():
        _log.error("Aborting — pipeline server is not available.")
        sys.exit(1)

    # Step 2: fetch allowed tools for later pre-validation
    allowed_tools = fetch_allowed_tools()
    if not allowed_tools:
        _log.warning("Could not retrieve allowed tools — skipping pre-validation.")

    _log.info("=== Endpoint connections OK — ready to run scenarios ===")