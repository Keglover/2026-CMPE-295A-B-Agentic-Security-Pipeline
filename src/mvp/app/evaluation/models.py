"""Version 1 wire contracts. An assessment never grants execution authority."""

from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


from app.models import PolicyAction


class ExecutionRequirement(str, Enum):
    NONE = "NONE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENIED = "DENIED"


class UserContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    platform: str = Field(max_length=100)
    shell: str | None = Field(default=None, max_length=500)
    working_directory: str | None = Field(default=None, max_length=4096)


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"] = "1"
    request_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1,
                            max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    content: str = Field(min_length=1, max_length=50000)
    source_type: Literal["direct_prompt", "retrieved_content"] = "direct_prompt"
    proposed_tool: str | None = Field(default=None, min_length=1, max_length=64)
    tool_args: dict[str, Any] = Field(default_factory=dict)
    context: UserContext | None = None

    @model_validator(mode="after")
    def arguments_need_tool(self):
        if self.tool_args and not self.proposed_tool:
            raise ValueError("Tool arguments require a proposed tool")
        return self


class EvaluationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1"]
    request_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    status: Literal["evaluated", "rejected", "unavailable"]
    policy_action: PolicyAction
    risk_score: int | None = Field(ge=0, le=100)
    execution_requirement: ExecutionRequirement
    execution_authorized: Literal[False]
    reason_code: str = Field(min_length=1, max_length=100, pattern=r"^[A-Z_]+$")
    reason: str = Field(min_length=1, max_length=1000)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_version: str = Field(min_length=1, max_length=100)
    registry_version: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def consistent_outcome(self):
        if self.status in {"unavailable", "rejected"}:
            if self.policy_action != PolicyAction.BLOCK or self.execution_requirement != ExecutionRequirement.DENIED:
                raise ValueError("Unavailable assessment must deny")
        elif self.risk_score is None:
            raise ValueError("Completed assessment requires a score")
        if self.policy_action in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}:
            if self.execution_requirement != ExecutionRequirement.DENIED:
                raise ValueError("Blocked assessment must deny")
        if self.policy_action == PolicyAction.REQUIRE_APPROVAL:
            if self.execution_requirement != ExecutionRequirement.REQUIRE_APPROVAL:
                raise ValueError("Approval cannot be omitted")
        return self
