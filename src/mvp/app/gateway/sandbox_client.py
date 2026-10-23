"""HTTP client wrappers for sandboxed tool execution."""

from __future__ import annotations

import os
from typing import Any, Callable

import httpx

from app.gateway.executor_policy import _load_policy
from app.policy.config_loader import load_tool_registry


def _sandbox_default_endpoint() -> str | None:
    env_endpoint = os.getenv("SANDBOX_EXECUTOR_URL", "").strip()
    if env_endpoint:
        return env_endpoint.rstrip("/")
    registry = load_tool_registry()
    sandbox_cfg = registry.get("sandbox", {})
    endpoint = str(sandbox_cfg.get("endpoint", "")).strip()
    return endpoint.rstrip("/") if endpoint else None


def _sandbox_endpoints() -> dict[str, str]:
    registry = load_tool_registry()
    sandbox_cfg = registry.get("sandbox", {})
    endpoints_cfg = sandbox_cfg.get("endpoints", {})

    env_tools = os.getenv("SANDBOX_TOOLS_URL", "").strip()
    env_llm = os.getenv("SANDBOX_LLM_URL", "").strip()

    endpoints: dict[str, str] = {}
    if env_tools:
        endpoints["tools"] = env_tools.rstrip("/")
    if env_llm:
        endpoints["llm"] = env_llm.rstrip("/")

    for key, value in endpoints_cfg.items():
        if key not in endpoints and value:
            endpoints[key] = str(value).rstrip("/")

    return endpoints


def _sandbox_route_for_tool(tool_name: str) -> str:
    registry = load_tool_registry()
    sandbox_cfg = registry.get("sandbox", {})
    routes = sandbox_cfg.get("tool_routes", {})
    route = str(routes.get(tool_name, "tools")).strip().lower()
    return route or "tools"


def _sandbox_endpoint_for_tool(tool_name: str) -> str:
    endpoints = _sandbox_endpoints()
    route = _sandbox_route_for_tool(tool_name)
    if route in endpoints:
        return endpoints[route]

    fallback = _sandbox_default_endpoint()
    if fallback:
        return fallback

    raise RuntimeError(
        f"No sandbox endpoint configured for route '{route}'."
    )


def _client_timeout_for_tool(tool_name: str) -> float:
    """Derive client timeout from execution policy for the given tool."""
    try:
        timeout_sec = float(_load_policy(tool_name).timeout_sec)
        return max(1.0, timeout_sec * 0.95)
    except Exception:
        return 10.0


def build_sandbox_executor(tool_name: str) -> Callable[[dict[str, Any]], str]:
    """Create an executor callable that delegates to the sandbox service."""

    endpoint = _sandbox_endpoint_for_tool(tool_name)
    timeout = _client_timeout_for_tool(tool_name)

    def _execute(args: dict[str, Any]) -> str:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(
                f"{endpoint}/execute/{tool_name}",
                json={"tool_args": args},
            )
            if response.status_code >= 400:
                try:
                    detail = response.json().get("detail", response.text)
                except Exception:
                    detail = response.text
                raise RuntimeError(str(detail))

            data = response.json()
            return str(data.get("result", data.get("output", "")))

    return _execute