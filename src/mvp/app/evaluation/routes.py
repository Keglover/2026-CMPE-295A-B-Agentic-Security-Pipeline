"""Dedicated route with sanitized validation failures; legacy routes unchanged."""

from uuid import uuid4

from fastapi import APIRouter
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from app.evaluation.models import EvaluationRequest, EvaluationResponse
from app.evaluation.service import evaluate, persist_result, unavailable


class EvaluationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def sanitized_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                result = persist_result(unavailable(str(uuid4()), "INVALID_REQUEST"))
                return JSONResponse(status_code=503 if result.reason_code == "AUDIT_UNAVAILABLE" else 422,
                                    content=result.model_dump(mode="json"))
        return sanitized_handler


router = APIRouter(route_class=EvaluationRoute)


@router.post("/evaluate", response_model=EvaluationResponse, tags=["evaluation"])
def evaluate_request(request: EvaluationRequest):
    result = evaluate(request)
    if result.status == "unavailable":
        return JSONResponse(status_code=503, content=result.model_dump(mode="json"))
    return result
