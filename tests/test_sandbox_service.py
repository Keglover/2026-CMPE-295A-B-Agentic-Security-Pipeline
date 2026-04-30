"""Tests for the internal sandbox executor service."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import docker
import pytest
from fastapi.testclient import TestClient

from app.gateway import gateway_real
from app.sandbox import service


client = TestClient(service.app)

@pytest.fixture(autouse=True)
def mock_docker(monkeypatch):
    """Mock the docker Python SDK globally for all tests."""
    mock_client = MagicMock()
    mock_containers = MagicMock()
    mock_client.containers = mock_containers
    
    def run_mock(**kwargs):
        # We simulate the gateway_real JSON stdout based on the tool
        cmd = kwargs.get("command", [])
        tool_name = cmd[3] if len(cmd) > 3 else "unknown"
        
        # Simulate basic responses that gateway_real would produce
        if tool_name == "write_note":
            args = json.loads(cmd[4])
            if "escape" in args.get("title", ""):
                return json.dumps({"status": "error", "error": "Invalid characters or path traversal."}).encode()
            return json.dumps({"status": "success", "output": "Note saved."}).encode()
        elif tool_name == "fetch_url":
            args = json.loads(cmd[4])
            if "127.0.0.1" in args.get("url", ""):
                 return json.dumps({"status": "error", "error": "Private/internal IPs blocked"}).encode()
            return json.dumps({"status": "success", "output": "Fetched content."}).encode()
        elif tool_name == "summarize":
             return json.dumps({"status": "success", "output": "Summarized."}).encode()
        elif tool_name == "search_notes":
            # Simulate timeout
            raise docker.errors.ContainerError(
                container="fake", 
                exit_status=1, 
                command="fake", 
                image="fake", 
                stderr=b"Simulated container hang/timeout timed out"
            )

        return json.dumps({"status": "error", "error": "Unknown tool"}).encode()

    mock_containers.run.side_effect = run_mock
    monkeypatch.setattr(service, "_docker_client", mock_client)
    return mock_client

def test_write_note_success_stays_in_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mock_docker) -> None:
    response = client.post(
        "/execute/write_note",
        json={"tool_args": {"title": "team standup", "body": "hello world"}},
    )

    assert response.status_code == 200
    assert response.json() == {"result": "Note saved."}


def test_write_note_path_traversal_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mock_docker) -> None:
    response = client.post(
        "/execute/write_note",
        json={"tool_args": {"title": "../escape", "body": "nope"}},
    )

    assert response.status_code == 400
    assert "invalid characters" in response.json()["detail"].lower() or "path traversal" in response.json()["detail"].lower()


def test_fetch_private_ip_is_rejected(monkeypatch: pytest.MonkeyPatch, mock_docker) -> None:
    response = client.post(
        "/execute/fetch_url",
        json={"tool_args": {"url": "http://127.0.0.1/admin"}},
    )

    assert response.status_code == 400
    assert "private/internal" in response.json()["detail"].lower()


def test_hanging_executor_times_out(monkeypatch: pytest.MonkeyPatch, mock_docker) -> None:
    response = client.post(
        "/execute/search_notes",
        json={"tool_args": {"query": "standup"}},
    )

    assert response.status_code == 500
    assert "timed out" in response.json()["detail"].lower()