"""
Tests for the interactive domain validation and approval flow.

Covers:
  - POST /validate-urls endpoint (pre-flight check)
  - Allowlist domains pass without approval
  - Unapproved domains are blocked until user approves
  - approved_domains in PipelineRequest bypasses the block
  - Private/internal IPs are blocked (SSRF)
  - Pipeline policy override: unapproved domain → REQUIRE_APPROVAL
  - Pipeline with approved_domains → ALLOW → EXECUTED
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# /validate-urls endpoint
# ---------------------------------------------------------------------------


def test_validate_urls_allowlist_passes():
    """A URL on the allowlist should return is_allowed=True, is_approved=True."""
    payload = {
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://en.wikipedia.org/wiki/Artificial_intelligence"},
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["can_proceed"] is True
    assert data["blocked_count"] == 0
    assert len(data["urls"]) == 1
    assert data["urls"][0]["is_allowed"] is True
    assert data["urls"][0]["is_approved"] is True


def test_validate_urls_unapproved_blocked():
    """A URL NOT on the allowlist should be blocked."""
    payload = {
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://evil.com/collect"},
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["can_proceed"] is False
    assert data["blocked_count"] == 1
    assert data["urls"][0]["is_allowed"] is False
    assert data["urls"][0]["is_approved"] is False
    assert "not in the allowlist" in data["urls"][0]["warning"]


def test_validate_urls_user_approved_passes():
    """Passing approved_domains in the request should mark the domain approved."""
    payload = {
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://evil.com/collect"},
        "approved_domains": ["evil.com"],
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["can_proceed"] is True
    assert data["blocked_count"] == 0
    assert data["urls"][0]["is_approved"] is True
    assert data["urls"][0]["is_allowed"] is False  # still not on allowlist


def test_validate_urls_private_ip_blocked():
    """Private/internal IPs should be blocked for SSRF protection."""
    payload = {
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "http://127.0.0.1/admin"},
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["can_proceed"] is False
    assert data["urls"][0]["is_allowed"] is False
    assert data["urls"][0]["is_approved"] is False
    assert "private" in data["urls"][0]["warning"].lower() or "blocked" in data["urls"][0]["warning"].lower()


def test_validate_urls_multimodal_args():
    """validate-urls should check audio_url, image_url, and document_url too."""
    payload = {
        "proposed_tool": "analyze_image",
        "tool_args": {
            "image_url": "https://evil.com/photo.jpg",
            "prompt": "Describe",
        },
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["blocked_count"] == 1
    assert data["urls"][0]["hostname"] == "evil.com"


# ---------------------------------------------------------------------------
# Pipeline integration — domain approval affects policy
# ---------------------------------------------------------------------------


def test_pipeline_unapproved_domain_requires_approval():
    """
    A benign fetch_url to an unapproved domain should trigger
    hard BLOCK at tool-stage domain validation.
    """
    payload = {
        "content": "Please fetch the latest news.",
        "source_type": "direct_prompt",
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://evil.com/news"},
    }
    response = client.post("/pipeline", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Policy should hard-BLOCK due to domain validation.
    assert data["policy"]["policy_action"] == "BLOCK"
    assert data["policy"]["requires_approval"] is False
    assert "evil.com" in data["policy"]["policy_reason"]

    # Gateway should be DENIED because policy is not ALLOW/SANITIZE
    assert data["gateway"]["gateway_decision"] == "DENIED"

    # Domain validation should show the blocked URL
    assert len(data["domain_validation"]) == 1
    assert data["domain_validation"][0]["hostname"] == "evil.com"


def test_pipeline_with_approved_domains_executes():
    """
    When the user pre-approves the domain via approved_domains,
    the pipeline should proceed to ALLOW and EXECUTE.
    """
    payload = {
        "content": "Please fetch the latest news.",
        "source_type": "direct_prompt",
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://evil.com/news"},
        "approved_domains": ["evil.com"],
    }
    response = client.post("/pipeline", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Risk should be low (benign input)
    assert data["risk"]["risk_score"] < 15

    # Policy should be ALLOW
    assert data["policy"]["policy_action"] == "ALLOW"
    assert data["policy"]["requires_approval"] is False

    # Gateway should EXECUTE (mock returns simulated content)
    assert data["gateway"]["gateway_decision"] == "EXECUTED"
    assert "MOCK" in data["gateway"]["tool_output"] or "Error" not in data["gateway"]["tool_output"]

    # Domain validation should show user-approved
    dv = data["domain_validation"][0]
    assert dv["is_approved"] is True
    assert dv["is_allowed"] is False  # still not on allowlist


def test_pipeline_allowlist_domain_executes():
    """A fetch_url to an allowlist domain should always execute."""
    payload = {
        "content": "Please fetch the Wikipedia page.",
        "source_type": "direct_prompt",
        "proposed_tool": "fetch_url",
        "tool_args": {"url": "https://en.wikipedia.org/wiki/Artificial_intelligence"},
    }
    response = client.post("/pipeline", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["policy"]["policy_action"] == "ALLOW"
    assert data["gateway"]["gateway_decision"] == "EXECUTED"
    assert data["domain_validation"][0]["is_allowed"] is True


def test_pipeline_no_tool_skips_domain_validation():
    """When no tool is proposed, domain_validation should be empty."""
    payload = {
        "content": "Hello world",
        "source_type": "direct_prompt",
    }
    response = client.post("/pipeline", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["domain_validation"] == []
    assert data["gateway"] is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_validate_urls_no_url_args():
    """A tool without URL args should return empty results."""
    payload = {
        "proposed_tool": "summarize",
        "tool_args": {"text": "Hello"},
    }
    response = client.post("/validate-urls", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["urls"] == []
    assert data["can_proceed"] is True
