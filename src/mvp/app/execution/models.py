from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.evaluation.models import EvaluationRequest, EvaluationResponse


class ToolCallRequest(EvaluationRequest):
    proposed_tool: str = Field(min_length=1, max_length=64)


class ToolCallResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"] = "1"
    evaluation: EvaluationResponse
    outcome: Literal["EXECUTED", "REQUIRE_APPROVAL", "DENIED", "UNAVAILABLE", "EXECUTION_UNKNOWN"]
    reason_code: str = Field(pattern=r"^[A-Z_]+$", max_length=100)
    executor_mode: Literal["MOCK", "SANDBOX"]
    tool_output: Any = None
