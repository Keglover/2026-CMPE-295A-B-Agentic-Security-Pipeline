"""Tests for the internal sandbox executor service."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.gateway import gateway_real
from app.sandbox import service


client = TestClient(service.app)


def test_write_note_success_stays_in_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_real, "_SANDBOX_DIR", tmp_path)
    monkeypatch.setenv("SANDBOX_ALLOWED_TOOLS", "write_note")

    response = client.post(
        "/execute/write_note",
        json={"tool_args": {"title": "team standup", "body": "hello world"}},
    )

    assert response.status_code == 200
    assert (tmp_path / "team standup.md").exists()


def test_write_note_path_traversal_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway_real, "_SANDBOX_DIR", tmp_path)
    monkeypatch.setenv("SANDBOX_ALLOWED_TOOLS", "write_note")

    response = client.post(
        "/execute/write_note",
        json={"tool_args": {"title": "../escape", "body": "nope"}},
    )

    assert response.status_code == 400
    assert "invalid characters" in response.json()["detail"].lower() or "path traversal" in response.json()["detail"].lower()


def test_fetch_private_ip_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_ALLOWED_TOOLS", "fetch_url")
    response = client.post(
        "/execute/fetch_url",
        json={"tool_args": {"url": "http://127.0.0.1/admin"}},
    )

    assert response.status_code == 400
    assert "private/internal" in response.json()["detail"].lower()


def test_hanging_executor_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SANDBOX_ALLOWED_TOOLS", "search_notes")
    original_executor = service.REAL_EXECUTORS["search_notes"]

    def _slow_executor(args: dict[str, object]) -> str:
        time.sleep(0.2)
        return "done"

    monkeypatch.setitem(service.REAL_EXECUTORS, "search_notes", _slow_executor)
    monkeypatch.setattr(service, "_inner_timeout", lambda tool_name: 0.05)

    response = client.post(
        "/execute/search_notes",
        json={"tool_args": {"query": "standup"}},
    )

    assert response.status_code == 504
    assert "timed out" in response.json()["detail"].lower()

    monkeypatch.setitem(service.REAL_EXECUTORS, "search_notes", original_executor)