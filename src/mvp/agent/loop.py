"""
Agent loop — the core LLM ↔ pipeline integration.

This module sends user prompts to an LLM, intercepts any tool calls,
routes them through the security pipeline (POST /pipeline), and feeds
results back to the LLM.

The LLM is NOT told about the security pipeline. It proposes tools
normally; interception is transparent.

Usage:
    from agent.loop import run_agent_turn
    result = run_agent_turn("Please summarize this article about AI safety")
"""

from __future__ import annotations

import json
import logging

import httpx
from openai import OpenAI

from agent.config import MAX_ITERATIONS, MODEL, OPENAI_API_KEY, OPENAI_BASE_URL, PIPELINE_URL
from agent.tools import TOOL_DEFINITIONS

_log = logging.getLogger("agent.loop")

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools. "
    "Use the provided tools when the user's request requires them. "
    "If a tool call is blocked, explain to the user that the action "
    "could not be completed and suggest an alternative."
)


def _build_pipeline_request(
    user_content: str,
    tool_name: str,
    tool_args: dict,
    source_type: str = "direct_prompt",
) -> dict:
    """
    Build a PipelineRequest payload from the LLM's tool call.

    Args:
        user_content: The original user prompt (this is what the risk engine scores).
        tool_name: Tool name from the LLM's function call.
        tool_args: Arguments from the LLM's function call.
        source_type: Origin of the content — "direct_prompt" or "retrieved_content".

    Returns:
        dict: JSON-serialisable payload matching PipelineRequest schema.
    """
    return {
        "content": user_content,
        "source_type": source_type,
        "proposed_tool": tool_name,
        "tool_args": tool_args,
    }


def _call_pipeline(payload: dict) -> dict:
    """
    POST a PipelineRequest to the running FastAPI server.

    Args:
        payload: Dict matching PipelineRequest schema.

    Returns:
        dict: Full PipelineResponse from the server.

    Raises:
        httpx.HTTPStatusError: If the server returns a non-2xx status.
        httpx.ConnectError: If the server is not running.
    """
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(PIPELINE_URL, json=payload)
        resp.raise_for_status()
        return resp.json()


def run_agent_turn(
    user_message: str,
    conversation: list[dict] | None = None,
    source_type: str = "direct_prompt",
) -> dict:
    """
    Run one full agent turn: send user message to LLM, handle tool calls
    through the security pipeline, return the final assistant response.

    Args:
        user_message: The user's input prompt.
        conversation: Existing conversation history (list of message dicts).
            If None, starts a fresh conversation.
        source_type: "direct_prompt" or "retrieved_content".

    Returns:
        dict with keys:
            - "reply": The assistant's final text response.
            - "conversation": Updated conversation history.
            - "pipeline_traces": List of pipeline responses for each tool call.
            - "tool_calls_made": Number of tool calls attempted.
            - "tool_calls_blocked": Number of tool calls denied by pipeline.
    """
    client_kwargs: dict = {"api_key": OPENAI_API_KEY}
    if OPENAI_BASE_URL:
        client_kwargs["base_url"] = OPENAI_BASE_URL
    client = OpenAI(**client_kwargs)

    if conversation is None:
        conversation = [{"role": "system", "content": SYSTEM_PROMPT}]

    conversation.append({"role": "user", "content": user_message})

    pipeline_traces: list[dict] = []
    tool_calls_made = 0
    tool_calls_blocked = 0

    for iteration in range(MAX_ITERATIONS):
        _log.info("Agent iteration %d/%d", iteration + 1, MAX_ITERATIONS)

        response = client.chat.completions.create(
            model=MODEL,
            messages=conversation,
            tools=TOOL_DEFINITIONS,
            tool_choice="auto",
        )

        msg = response.choices[0].message

        # --- LLM returned text only: we're done ---
        if not msg.tool_calls:
            assistant_text = msg.content or ""
            conversation.append({"role": "assistant", "content": assistant_text})
            return {
                "reply": assistant_text,
                "conversation": conversation,
                "pipeline_traces": pipeline_traces,
                "tool_calls_made": tool_calls_made,
                "tool_calls_blocked": tool_calls_blocked,
            }

        # --- LLM wants to call tool(s): route through pipeline ---
        conversation.append(msg.model_dump())

        for tool_call in msg.tool_calls:
            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments)
            tool_call_id = tool_call.id
            tool_calls_made += 1

            _log.info(
                "Tool call: %s(%s) — routing through pipeline",
                tool_name,
                tool_args,
            )

            # Build and send through the security pipeline
            payload = _build_pipeline_request(
                user_content=user_message,
                tool_name=tool_name,
                tool_args=tool_args,
                source_type=source_type,
            )

            try:
                pipeline_resp = _call_pipeline(payload)
            except httpx.ConnectError:
                _log.error("Pipeline server not reachable at %s", PIPELINE_URL)
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": "ERROR: Security pipeline is not running.",
                })
                tool_calls_blocked += 1
                continue
            except httpx.HTTPStatusError as exc:
                _log.error("Pipeline returned %d", exc.response.status_code)
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": f"ERROR: Pipeline error ({exc.response.status_code}).",
                })
                tool_calls_blocked += 1
                continue

            pipeline_traces.append(pipeline_resp)

            # Check gateway decision
            gw = pipeline_resp.get("gateway")
            if gw and gw.get("gateway_decision") == "EXECUTED":
                tool_output = gw.get("tool_output", "Tool executed successfully.")
                _log.info("Tool %s EXECUTED", tool_name)
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": str(tool_output),
                })
            else:
                reason = ""
                if gw:
                    reason = gw.get("decision_reason", "Blocked by security policy.")
                else:
                    policy_action = pipeline_resp.get("policy", {}).get("policy_action", "UNKNOWN")
                    reason = f"Policy action: {policy_action}. Tool was not executed."

                _log.warning("Tool %s DENIED: %s", tool_name, reason)
                tool_calls_blocked += 1
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": f"BLOCKED: {reason}",
                })

    # Hit max iterations
    _log.warning("Agent hit max iterations (%d)", MAX_ITERATIONS)
    return {
        "reply": "[Agent reached maximum tool-call iterations]",
        "conversation": conversation,
        "pipeline_traces": pipeline_traces,
        "tool_calls_made": tool_calls_made,
        "tool_calls_blocked": tool_calls_blocked,
    }
