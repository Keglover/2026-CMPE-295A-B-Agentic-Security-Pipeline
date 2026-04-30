"""Tests for HTTP sandbox executor client wrappers."""

from __future__ import annotations

import httpx
import pytest

from app.gateway.sandbox_client import build_sandbox_executor


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, str] | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self) -> dict[str, str]:
        return self._payload


class _FakeClient:
    next_response: _FakeResponse | None = None
    expected_url: str | None = None

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url: str, json: dict[str, object]) -> _FakeResponse:
        assert self.expected_url is not None
        assert url == self.expected_url
        assert json["tool_args"]
        assert self.next_response is not None
        return self.next_response


def test_sandbox_executor_returns_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeClient.next_response = _FakeResponse(200, {"output": "saved"})
    _FakeClient.expected_url = "http://sandbox-tools:8001/execute/write_note"
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setenv("SANDBOX_TOOLS_URL", "http://sandbox-tools:8001")
    monkeypatch.setenv("SANDBOX_LLM_URL", "http://sandbox-llm:8003")

    executor = build_sandbox_executor("write_note")

    assert executor({"title": "Test", "body": "hello"}) == "saved"


def test_sandbox_executor_raises_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeClient.next_response = _FakeResponse(400, {"detail": "Error: path traversal detected"})
    _FakeClient.expected_url = "http://sandbox-tools:8001/execute/write_note"
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setenv("SANDBOX_TOOLS_URL", "http://sandbox-tools:8001")
    monkeypatch.setenv("SANDBOX_LLM_URL", "http://sandbox-llm:8003")

    executor = build_sandbox_executor("write_note")

    with pytest.raises(RuntimeError, match="path traversal"):
        executor({"title": "Test", "body": "hello"})


def test_sandbox_executor_routes_llm_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeClient.next_response = _FakeResponse(200, {"output": "summary"})
    _FakeClient.expected_url = "http://tool-runner:8001/execute/summarize"
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setenv("SANDBOX_TOOLS_URL", "http://tool-runner:8001")
    monkeypatch.setenv("SANDBOX_LLM_URL", "http://tool-runner:8001")

    executor = build_sandbox_executor("summarize")

    assert executor({"text": "hello"}) == "summary"