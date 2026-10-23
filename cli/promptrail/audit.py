"""Local append-only activity through this client; never an authorization store."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from promptrail.models import EvaluationResponse


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: str = Field(max_length=100)
    request_id: str = Field(max_length=128)
    trace_id: str = Field(max_length=128)
    status: str = Field(max_length=30)
    policy_action: str = Field(max_length=30)
    risk_score: int | None = Field(ge=0, le=100)
    execution_requirement: str = Field(max_length=30)
    reason_code: str = Field(max_length=100)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    outcome: str | None = Field(default=None, max_length=30)
    executor_mode: str | None = Field(default=None, max_length=30)


def append_event(path: Path, result: EvaluationResponse, *, outcome=None, reason_code=None, executor_mode=None) -> None:
    event = AuditEvent(timestamp=datetime.now(timezone.utc).isoformat(),
        **result.model_dump(mode="json", include={"request_id", "trace_id", "status", "policy_action",
            "risk_score", "execution_requirement", "reason_code", "content_hash"}))
    if outcome is not None:
        event.outcome, event.reason_code, event.executor_mode = outcome, reason_code, executor_mode
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
        if hasattr(os, "fchmod"):
            os.fchmod(stream.fileno(), 0o600)
        stream.write(event.model_dump_json() + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_events(path: Path, limit: int = 20) -> tuple[list[AuditEvent], int]:
    from collections import deque
    from pydantic import ValidationError

    events = deque(maxlen=limit)
    skipped = 0
    if not path.exists():
        return [], 0
    with path.open(encoding="utf-8") as stream:
        while line := stream.readline(8193):
            if len(line) > 8192:
                while line and not line.endswith("\n"):
                    line = stream.readline(8193)
                skipped += 1
                continue
            try:
                events.append(AuditEvent.model_validate_json(line))
            except (ValidationError, ValueError):
                skipped += 1
    return list(reversed(events)), skipped
