import json

import pytest
from pydantic import ValidationError

from promptrail.models import EvaluationRequest, EvaluationResponse


def response_payload(**changes):
    payload = dict(schema_version="1", request_id="test-1", trace_id="trace-1",
                   status="evaluated", policy_action="ALLOW", risk_score=0,
                   execution_requirement="NONE", execution_authorized=False,
                   reason_code="POLICY_ALLOW", reason="Assessment complete.",
                   content_hash="a" * 64, policy_version="1", registry_version="2")
    return payload | changes


@pytest.mark.parametrize("changes", [
    {"content": 123}, {"content": ""}, {"content": "x" * 50001},
    {"request_id": "bad/id"}, {"approved_domains": ["evil.com"]},
    {"policy_action": "ALLOW"}, {"tool_args": {"command": "ls"}},
    {"context": {"platform": 42}},
])
def test_reject_invalid_or_authority_fields(changes):
    with pytest.raises(ValidationError):
        EvaluationRequest.model_validate({"content": "hello"} | changes)


def test_request_roundtrip():
    request = EvaluationRequest(content="list files", proposed_tool="execute_command",
                                tool_args={"command": "ls"})
    assert EvaluationRequest.model_validate_json(request.model_dump_json()) == request


@pytest.mark.parametrize("changes", [
    {"execution_authorized": True}, {"risk_score": "0"}, {"risk_score": 101},
    {"status": "unavailable"}, {"risk_score": None},
    {"policy_action": "BLOCK"}, {"policy_action": "REQUIRE_APPROVAL"},
    {"schema_version": "2"}, {"unexpected": "value"},
])
def test_response_fails_closed(changes):
    with pytest.raises(ValidationError):
        EvaluationResponse.model_validate_json(json.dumps(response_payload(**changes)))


def test_response_has_no_execution_grant():
    result = EvaluationResponse.model_validate_json(json.dumps(response_payload()))
    assert result.execution_authorized is False
