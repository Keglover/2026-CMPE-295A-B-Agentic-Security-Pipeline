from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from promptrail.models import EvaluationRequest, EvaluationResponse


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

    @model_validator(mode="after")
    def valid_execution(self):
        if self.outcome == "EXECUTED" and (self.evaluation.status != "evaluated"
                or self.evaluation.policy_action.value in {"BLOCK", "QUARANTINE"}
                or self.evaluation.execution_requirement.value == "DENIED"):
            raise ValueError("Blocked assessment cannot report successful execution")
        return self


class AgentCredential(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    access_token: SecretStr
    token_type: Literal["Bearer"]
    expires_in: int = Field(gt=0, le=300)
    agent_id: str = Field(min_length=1, max_length=128)
    tools: list[str]
    permissions: list[str]


class ApprovalState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str = Field(min_length=1, max_length=128)
    status: Literal["pending", "approved", "rejected", "timed_out", "consumed", "not_found"]
    execution_authorized: Literal[False]


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"] = "1"
    gateway_url: str
    agent_id: str | None = None
    tools: list[str]
    requests: list[ToolCallRequest] = Field(min_length=1, max_length=50)
    next_index: int = Field(ge=0, le=50)
    status: Literal["ready", "approval_required", "uncertain", "complete"] = "ready"

    @model_validator(mode="after")
    def valid_position(self):
        if self.next_index > len(self.requests) or set(self.tools) != {r.proposed_tool for r in self.requests}:
            raise ValueError("Invalid checkpoint position or tool set")
        if len({r.request_id for r in self.requests}) != len(self.requests):
            raise ValueError("Duplicate action IDs")
        return self
