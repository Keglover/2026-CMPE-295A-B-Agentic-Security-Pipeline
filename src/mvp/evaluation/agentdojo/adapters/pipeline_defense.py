from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

import httpx

try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
    from agentdojo.types import ChatMessage, get_text_content_as_str
except ImportError:  
    BasePipelineElement = object  # type: ignore[misc,assignment]
    EmptyEnv = Env = FunctionsRuntime = ChatMessage = Any  # type: ignore[misc,assignment]

    def get_text_content_as_str(content: Any) -> str:
        return str(content)

_log = logging.getLogger("Pipeline Defense")

class PipelineDefense(BasePipelineElement):
    
    name = "mvp-pipeline-defense"

    def __init__(self, endpoint: str, timeout: float = 10.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def _screen(self, content:str) -> dict[str, Any]:
        response = httpx.post(
            self.endpoint,
            json={"content": content, "source_type": "retrieved_content"},
            timeout=self.timeout,
        )

        response.raise_for_status()
        return response.json()

    def _replacement(content:str, result: dict[str, Any]) -> str:
        policy = result.get("policy", {}).get("policy_action", "BLOCK")
        
        if policy in {"BLOCK", "QUARANTINE"}:
            request_id = result.get("request_id", "unknown")
            return f"<REDACTED request_id {request_id} by MVP pipeline {policy} defense policy>"
        
        if policy == "SANITIZE":
            nomralized = result.get("normalized", {}).get("normalized_content")
            if nomralized is not None:
                return nomralized
        
        return content

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        updated = list(messages)
        traces = list(extra_args.get("pipeline_traces", []))

        for index, message in enumerate(updated):
            if message.get("role") != "tool":
                continue
            content = get_text_content_as_str(message.get("content"))
            try:
                result = self._screen(content)
            except httpx.HTTPError as exc:
                _log.error("MVP pipeline unavailable; failing closed: %s", exc)
                result = {
                    "request_id": "pipeline-unavailable",
                    "policy": {"policy_action": "BLOCK"},
                    "error": f"{type(exc).__name__}: {exc}",
                }
            traces.append(result)
            updated[index] = {**message, "content": self._replacement(content, result)}

        next_args = {**extra_args, "pipeline_traces": traces}
        return query, runtime, env, updated, next_args
