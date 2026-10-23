import json

import httpx
import pytest

from promptrail.client import GatewayClient, request_hash
from promptrail.config import Settings
from promptrail.models import EvaluationRequest


def payload(request, **changes):
    return dict(schema_version="1", request_id=request.request_id, trace_id="trace-1",
        status="evaluated", policy_action="ALLOW", risk_score=0, execution_requirement="NONE",
        execution_authorized=False, reason_code="POLICY_ALLOW", reason="Assessment complete.",
        content_hash=request_hash(request), policy_version="1", registry_version="2") | changes


def call(handler, request=None, token=None):
    request = request or EvaluationRequest(content="hello")
    with GatewayClient(Settings(), token=token, transport=httpx.MockTransport(handler)) as client:
        return client.evaluate(request)


def test_valid_response_and_scoped_credential():
    request = EvaluationRequest(content="hello")
    def handler(incoming):
        assert str(incoming.url) == "http://127.0.0.1:8003/evaluate"
        assert incoming.headers["Authorization"] == "Bearer test-credential"
        assert json.loads(incoming.content)["request_id"] == request.request_id
        return httpx.Response(200, json=payload(request))
    result = call(handler, request, "test-credential")
    assert result.status == "evaluated"
    assert result.execution_authorized is False


@pytest.mark.parametrize("status,code", [(401, "AUTHENTICATION_FAILED"),
    (403, "AUTHENTICATION_FAILED"), (500, "SERVICE_UNAVAILABLE"),
    (302, "SERVICE_UNAVAILABLE"), (404, "SERVICE_UNAVAILABLE")])
def test_http_errors_do_not_allow(status, code):
    result = call(lambda _: httpx.Response(status, text="private server error"))
    assert result.status == "unavailable"
    assert result.reason_code == code
    assert "private server error" not in result.model_dump_json()


@pytest.mark.parametrize("error,code", [(httpx.ConnectError, "SERVICE_UNAVAILABLE"),
                                       (httpx.ReadTimeout, "EVALUATION_TIMEOUT")])
def test_transport_failures(error, code):
    def handler(incoming):
        raise error("private error", request=incoming)
    assert call(handler).reason_code == code


@pytest.mark.parametrize("changes", [{"execution_authorized": True},
    {"risk_score": "0"}, {"status": "unavailable"}, {"schema_version": "2"},
    {"policy_action": "BLOCK"}, {"policy_action": "REQUIRE_APPROVAL"}])
def test_malformed_response_denies(changes):
    request = EvaluationRequest(content="hello")
    result = call(lambda _: httpx.Response(200, json=payload(request, **changes)), request)
    assert result.reason_code == "INVALID_RESPONSE"


@pytest.mark.parametrize("changes", [{"request_id": "other-request"}, {"content_hash": "b" * 64}])
def test_response_bound_to_request(changes):
    request = EvaluationRequest(content="hello")
    result = call(lambda _: httpx.Response(200, json=payload(request, **changes)), request)
    assert result.reason_code == "RESPONSE_MISMATCH"


@pytest.mark.parametrize("body", [b"not json", b"x" * 1048577])
def test_invalid_or_oversized_response(body):
    assert call(lambda _: httpx.Response(200, content=body)).reason_code == "INVALID_RESPONSE"


def test_structured_backend_unavailable():
    request = EvaluationRequest(content="hello")
    result = call(lambda _: httpx.Response(503, json=payload(request, status="unavailable",
        risk_score=None, policy_action="BLOCK", execution_requirement="DENIED",
        reason_code="AUDIT_UNAVAILABLE")), request)
    assert result.reason_code == "AUDIT_UNAVAILABLE"
