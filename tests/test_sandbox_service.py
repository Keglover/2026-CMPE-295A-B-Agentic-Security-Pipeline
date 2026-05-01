"""Tests for the internal sandbox executor service."""

from __future__ import annotations

import json
import os
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
        elif tool_name == "execute_command":
            args = json.loads(cmd[4])
            command = str(args.get("command", ""))
            return json.dumps(
                {
                    "status": "success",
                    "output": f"$ {command}\nexit_code=0\nstdout:\nmocked output",
                }
            ).encode()
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
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert kwargs["user"] == "0:0"
    assert kwargs["network_mode"] == "none"


def test_summarize_short_text_routes_to_control_net(
    monkeypatch: pytest.MonkeyPatch,
    mock_docker,
) -> None:
    monkeypatch.setattr(
        service,
        "load_tool_registry",
        lambda: {
            "sandbox": {
                "summarize": {
                    "local_max_chars": 50,
                    "local_route": "control-net",
                    "cloud_route": "egress-net",
                }
            }
        },
    )

    response = client.post(
        "/execute/summarize",
        json={"tool_args": {"text": "short text"}},
    )

    assert response.status_code == 200
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert kwargs["network"] == service.CONTROL_NET_NAME
    assert kwargs["environment"]["LLM_MODEL"] == os.getenv("LLM_MODEL_LOCAL", "qwen2.5:7b")


def test_summarize_long_text_routes_to_egress_net(
    monkeypatch: pytest.MonkeyPatch,
    mock_docker,
) -> None:
    monkeypatch.setattr(
        service,
        "load_tool_registry",
        lambda: {
            "sandbox": {
                "summarize": {
                    "local_max_chars": 5,
                    "local_route": "control-net",
                    "cloud_route": "egress-net",
                }
            }
        },
    )

    response = client.post(
        "/execute/summarize",
        json={"tool_args": {"text": "this is definitely longer than five"}},
    )

    assert response.status_code == 200
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert kwargs["network"] == service.EGRESS_NET_NAME
    assert kwargs["environment"]["LLM_MODEL"] == os.getenv("LLM_MODEL_CLOUD", os.getenv("LLM_MODEL", "qwen2.5:7b"))


def test_summarize_routes_can_be_overridden_by_registry(
    monkeypatch: pytest.MonkeyPatch,
    mock_docker,
) -> None:
    monkeypatch.setattr(
        service,
        "load_tool_registry",
        lambda: {
            "sandbox": {
                "summarize": {
                    "local_max_chars": 100,
                    "local_route": "egress-net",
                    "cloud_route": "control-net",
                }
            }
        },
    )

    response = client.post(
        "/execute/summarize",
        json={"tool_args": {"text": "small"}},
    )

    assert response.status_code == 200
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert kwargs["network"] == service.EGRESS_NET_NAME


def test_write_note_uses_and_cleans_job_scratch_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_docker,
) -> None:
    monkeypatch.setattr(service, "JOB_SCRATCH_ROOT", str(tmp_path))

    response = client.post(
        "/execute/write_note",
        json={"tool_args": {"title": "cleanup-check", "body": "hello"}},
    )

    assert response.status_code == 200
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert "volumes" in kwargs
    assert kwargs["user"] == "0:0"
    assert kwargs["network_mode"] == "none"
    assert list(tmp_path.iterdir()) == []


def test_execute_command_uses_scratch_workspace_and_no_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_docker,
) -> None:
    monkeypatch.setattr(service, "JOB_SCRATCH_ROOT", str(tmp_path))

    response = client.post(
        "/execute/execute_command",
        json={"tool_args": {"command": "echo hello"}},
    )

    assert response.status_code == 200
    kwargs = mock_docker.containers.run.call_args.kwargs
    assert kwargs["network_mode"] == "none"
    assert "volumes" in kwargs

    mount_cfg = next(iter(kwargs["volumes"].values()))
    assert mount_cfg["bind"] == "/tmp/job"

    cmd = kwargs["command"]
    parsed_args = json.loads(cmd[4])
    assert parsed_args["working_dir"] == "/tmp/job"
    assert list(tmp_path.iterdir()) == []
