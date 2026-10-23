from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.evaluation.routes import EvaluationRoute
from app.execution.models import ToolCallRequest, ToolCallResponse
from app.execution.service import execute_action, response_for
from app.models import PipelineRequest
from app.gateway import gateway

router = APIRouter(route_class=EvaluationRoute)


@router.get("/tools/requests/{request_id}", tags=["tools"])
def request_status(request_id: str, request: Request):
    """Inspect owned approval state without assessing, queueing or executing a tool."""
    identity = getattr(request.state, "identity", None)
    if identity is None:
        return JSONResponse(status_code=503, content={"reason_code": "AUTHENTICATION_NOT_CONFIGURED"})
    try:
        record = gateway.approval_manager.get_status(request_id)
    except Exception:
        return JSONResponse(status_code=503, content={"reason_code": "APPROVAL_STATE_UNAVAILABLE"})
    if record and record.requester != identity.subject:
        return JSONResponse(status_code=403, content={"reason_code": "APPROVAL_OWNER_MISMATCH"})
    return {"request_id": request_id, "status": record.status.value if record else "not_found",
            "execution_authorized": False}


@router.post("/tools/call", response_model=ToolCallResponse, tags=["tools"])
def call_tool(payload: ToolCallRequest, request: Request):
    identity = getattr(request.state, "identity", None)
    if identity is None:
        return JSONResponse(status_code=503, content={"reason_code": "AUTHENTICATION_NOT_CONFIGURED",
                                                    "execution_authorized": False})
    if identity.kind == "agent" and payload.proposed_tool not in identity.allowed_tools:
        return JSONResponse(status_code=403, content={"reason_code": "AGENT_TOOL_DENIED",
                                                    "execution_authorized": False})
    envelope = PipelineRequest(**payload.model_dump(exclude={"schema_version", "context"}),
                               agent_id=identity.subject)
    result = response_for(*execute_action(envelope))
    return JSONResponse(status_code=503 if result.outcome == "UNAVAILABLE" else 200,
                        content=result.model_dump(mode="json"))
