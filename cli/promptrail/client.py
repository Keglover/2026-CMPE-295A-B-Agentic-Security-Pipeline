"""Validated, bounded HTTP transport; a transport failure cannot become ALLOW."""

import hashlib
import json
from uuid import uuid4

import httpx
from pydantic import ValidationError

from promptrail.config import Settings
from promptrail.models import EvaluationRequest, EvaluationResponse, ExecutionRequirement, PolicyAction


def request_hash(request: EvaluationRequest) -> str:
    material = json.dumps({"content": request.content, "source_type": request.source_type,
                           "proposed_tool": request.proposed_tool, "tool_args": request.tool_args},
                          sort_keys=True, allow_nan=False)
    return hashlib.sha256(material.encode()).hexdigest()


def unavailable(request: EvaluationRequest, code: str) -> EvaluationResponse:
    try:
        digest = request_hash(request)
    except (ValueError, TypeError):
        digest = hashlib.sha256(b"").hexdigest()
    return EvaluationResponse(schema_version="1", request_id=request.request_id,
        trace_id=str(uuid4()), status="unavailable", policy_action=PolicyAction.BLOCK,
        risk_score=None, execution_requirement=ExecutionRequirement.DENIED,
        execution_authorized=False, reason_code=code,
        reason="Evaluation unavailable; execution is not authorized.", content_hash=digest,
        policy_version="unknown", registry_version="unknown")


class GatewayClient:
    def __init__(self, settings: Settings, *, token: str | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.settings = settings
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        self._client = httpx.Client(timeout=settings.timeout, headers=headers,
                                    follow_redirects=False, trust_env=False, transport=transport)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._client.close()

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        try:
            with self._client.stream("POST", self.settings.gateway_url + "/evaluate",
                                     json=request.model_dump(mode="json")) as response:
                if response.status_code not in {200, 422, 503}:
                    return unavailable(request, "AUTHENTICATION_FAILED" if response.status_code in {401, 403}
                                       else "SERVICE_UNAVAILABLE")
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    data.extend(chunk)
                    if len(data) > 1048576:
                        return unavailable(request, "INVALID_RESPONSE")
                result = EvaluationResponse.model_validate_json(bytes(data))
                if result.request_id != request.request_id or result.content_hash != request_hash(request):
                    return unavailable(request, "RESPONSE_MISMATCH")
                if (response.status_code == 200) != (result.status != "unavailable"):
                    return unavailable(request, "INVALID_RESPONSE")
                return result
        except httpx.TimeoutException:
            return unavailable(request, "EVALUATION_TIMEOUT")
        except httpx.HTTPError:
            return unavailable(request, "SERVICE_UNAVAILABLE")
        except (ValidationError, ValueError, TypeError):
            return unavailable(request, "INVALID_RESPONSE")
