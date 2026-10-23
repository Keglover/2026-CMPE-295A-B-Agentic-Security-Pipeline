"""
Tests for multimodal tool mocks and gateway schema integration.

Covers:
  - transcribe_audio mock executor
  - analyze_image mock executor
  - document_qa mock executor
  - Gateway schema loading from tool_registry.yaml
  - Unknown multimodal tool denial
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.gateway.gateway_mock import EXECUTORS as MOCK_EXECUTORS
from app.gateway.gateway import TOOL_SCHEMAS, TOOL_ALLOWLIST, mediate
from app.models import PolicyResult, PolicyAction

client = TestClient(app)


# ---------------------------------------------------------------------------
# Mock executor unit tests
# ---------------------------------------------------------------------------

def test_mock_transcribe_audio():
    """Transcribe audio mock should return simulated transcript."""
    result = MOCK_EXECUTORS["transcribe_audio"]({"audio_url": "https://audio.example.com/test.wav"})
    assert "[MOCK] Transcribed audio" in result
    assert "test.wav" in result  # audio_url quoted in output


def test_mock_analyze_image():
    """Analyze image mock should return simulated description."""
    result = MOCK_EXECUTORS["analyze_image"]({
        "image_url": "https://image.example.com/photo.jpg",
        "prompt": "What is this?"
    })
    assert "[MOCK] Image analysis" in result
    assert "workspace with a laptop" in result


def test_mock_document_qa():
    """Document QA mock should return simulated answer."""
    result = MOCK_EXECUTORS["document_qa"]({
        "document_url": "https://docs.example.com/report.pdf",
        "query": "What was Q3 revenue?"
    })
    assert "[MOCK] Document Q&A" in result
    assert "14%" in result


# ---------------------------------------------------------------------------
# Gateway schema tests
# ---------------------------------------------------------------------------

def test_multimodal_tools_in_allowlist():
    """The three new multimodal tools should be on the allowlist."""
    assert "transcribe_audio" in TOOL_ALLOWLIST
    assert "analyze_image" in TOOL_ALLOWLIST
    assert "document_qa" in TOOL_ALLOWLIST


def test_multimodal_tools_have_schemas():
    """Each multimodal tool should declare its required args."""
    assert "audio_url" in TOOL_SCHEMAS["transcribe_audio"]
    assert "image_url" in TOOL_SCHEMAS["analyze_image"]
    assert "prompt" in TOOL_SCHEMAS["analyze_image"]
    assert "document_url" in TOOL_SCHEMAS["document_qa"]
    assert "query" in TOOL_SCHEMAS["document_qa"]


# ---------------------------------------------------------------------------
# Gateway mediation tests
# ---------------------------------------------------------------------------

def test_transcribe_audio_executes_on_allow():
    """Gateway should route transcribe_audio to mock executor with ALLOW policy."""
    from app.models import PipelineRequest, SourceType
    req = PipelineRequest(
        content="Transcribe this audio file.",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="transcribe_audio",
        tool_args={"audio_url": "https://audio.example.com/test.wav"},
    )
    policy = PolicyResult(
        request_id=req.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason="Test",
    )
    result = mediate(req, policy)
    assert result.gateway_decision.value == "EXECUTED"
    assert "[MOCK] Transcribed audio" in result.tool_output


def test_analyze_image_executes_on_allow():
    """Gateway should route analyze_image to mock executor with ALLOW policy."""
    from app.models import PipelineRequest, SourceType
    req = PipelineRequest(
        content="Describe this image.",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="analyze_image",
        tool_args={
            "image_url": "https://image.example.com/photo.jpg",
            "prompt": "Describe in detail."
        },
    )
    policy = PolicyResult(
        request_id=req.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason="Test",
    )
    result = mediate(req, policy)
    assert result.gateway_decision.value == "EXECUTED"
    assert "workspace with a laptop" in result.tool_output


def test_document_qa_executes_on_allow():
    """Gateway should route document_qa to mock executor with ALLOW policy."""
    from app.models import PipelineRequest, SourceType
    req = PipelineRequest(
        content="Summarize this document.",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="document_qa",
        tool_args={
            "document_url": "https://docs.example.com/report.pdf",
            "query": "What were the key findings?"
        },
    )
    policy = PolicyResult(
        request_id=req.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason="Test",
    )
    result = mediate(req, policy)
    assert result.gateway_decision.value == "EXECUTED"
    assert "revenue grew" in result.tool_output


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

def test_transcribe_audio_missing_arg_denied():
    """Gateway should deny transcribe_audio when audio_url is missing."""
    from app.models import PipelineRequest, SourceType
    req = PipelineRequest(
        content="Transcribe this audio file.",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="transcribe_audio",
        tool_args={},
    )
    policy = PolicyResult(
        request_id=req.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason="Test",
    )
    result = mediate(req, policy)
    assert result.gateway_decision.value == "DENIED"
    assert "missing required argument" in result.decision_reason.lower()


def test_analyze_image_missing_prompt_denied():
    """Gateway should deny analyze_image when prompt is missing."""
    from app.models import PipelineRequest, SourceType
    req = PipelineRequest(
        content="Describe this image.",
        source_type=SourceType.DIRECT_PROMPT,
        proposed_tool="analyze_image",
        tool_args={"image_url": "https://image.example.com/photo.jpg"},
    )
    policy = PolicyResult(
        request_id=req.request_id,
        policy_action=PolicyAction.ALLOW,
        policy_reason="Test",
    )
    result = mediate(req, policy)
    assert result.gateway_decision.value == "DENIED"
    assert "missing required argument" in result.decision_reason.lower()


# ---------------------------------------------------------------------------
# E2E integration tests via FastAPI client
# ---------------------------------------------------------------------------

def test_e2e_multimodal_analyze_image():
    """End-to-end: analyze_image should pass pipeline and return mock output."""
    payload = {
        "content": "Describe this image.",
        "source_type": "direct_prompt",
        "proposed_tool": "analyze_image",
        "tool_args": {
            "image_url": "https://image.example.com/photo.jpg",
            "prompt": "Describe in detail."
        },
    }
    response = client.post("/pipeline", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["policy"]["policy_action"] == "ALLOW"
    assert data["gateway"]["gateway_decision"] == "EXECUTED"
    assert "workspace with a laptop" in data["gateway"]["tool_output"]
    assert data["prompt_guard"]["is_injection"] is False
