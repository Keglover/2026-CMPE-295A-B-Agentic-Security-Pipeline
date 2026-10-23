"""Restarts preserve identity and one-use review state without reviving expired authority."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.approval.durable import SQLiteApprovalManager
from app.approval.workflow import ApprovalStatus
from app.auth.agents import durable_identity
from app.auth.oidc import AuthenticationError
from tests.test_authentication import signing_key, oidc, protected_api
from tests.test_runner_capabilities import keys
from tests.test_agent_tokens import header


def queue(manager):
    return manager.submit("durable-action", 10, [], "execute_command", action_hash="a" * 64,
                          requester="agent:alice", action_details={"tool_args": {"command": "echo hello"}})


def test_pending_and_approved_survive_new_manager(tmp_path):
    path = tmp_path / "state.sqlite3"
    first = SQLiteApprovalManager(path)
    record = queue(first)
    second = SQLiteApprovalManager(path)
    assert second.get_status(record.request_id).action_details == record.action_details
    assert second.approve(record.request_id, approved_by="reviewer")
    third = SQLiteApprovalManager(path)
    assert third.get_status(record.request_id).resolved_by == "reviewer"
    assert third.consume(record.request_id, "a" * 64, "agent:alice")
    assert not SQLiteApprovalManager(path).consume(record.request_id, "a" * 64, "agent:alice")
    assert path.stat().st_mode & 0o777 == 0o600


def test_expired_review_is_not_revived_after_restart(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    record = queue(SQLiteApprovalManager(path))
    monkeypatch.setattr("app.approval.workflow.time.time", lambda: record.expires_at + 1)
    restored = SQLiteApprovalManager(path)
    assert restored.approve(record.request_id) is None
    assert restored.get_status(record.request_id).status == ApprovalStatus.TIMED_OUT
    assert not restored.consume(record.request_id, "a" * 64, "agent:alice")
    assert queue(restored).status == ApprovalStatus.TIMED_OUT


def test_long_pending_pause_does_not_extend_approved_authority(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite3"
    manager = SQLiteApprovalManager(path, timeout_seconds=604800, approved_timeout_seconds=300)
    record = queue(manager)
    now = [record.created_at + 86400]
    monkeypatch.setattr("app.approval.workflow.time.time", lambda: now[0])
    restored = SQLiteApprovalManager(path, timeout_seconds=604800, approved_timeout_seconds=300)
    assert restored.get_status(record.request_id).status == ApprovalStatus.PENDING
    approved = restored.approve(record.request_id, approved_by="reviewer")
    assert approved.expires_at == now[0] + 300
    now[0] += 301
    assert not restored.consume(record.request_id, "a" * 64, "agent:alice")
    assert restored.get_status(record.request_id).status == ApprovalStatus.TIMED_OUT


def test_multiple_managers_cannot_consume_one_approval_twice(tmp_path):
    path = tmp_path / "state.sqlite3"
    manager = SQLiteApprovalManager(path)
    queue(manager)
    manager.approve("durable-action")
    def consume(_):
        return SQLiteApprovalManager(path).consume("durable-action", "a" * 64, "agent:alice")
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(8))) == 1


def test_changed_action_or_identity_cannot_replace_durable_record(tmp_path):
    manager = SQLiteApprovalManager(tmp_path / "state.sqlite3")
    queue(manager)
    with pytest.raises(ValueError, match="APPROVAL_ACTION_MISMATCH"):
        manager.submit("durable-action", 0, [], action_hash="b" * 64, requester="mallory")
    assert manager.get_status("durable-action").requester == "agent:alice"


def test_corrupt_or_symlinked_state_fails_closed(tmp_path):
    path = tmp_path / "state.sqlite3"
    queue(SQLiteApprovalManager(path))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE approvals SET record='corrupted'")
    with pytest.raises(ValueError):
        SQLiteApprovalManager(path).consume("durable-action", "a" * 64, "agent:alice")
    link = tmp_path / "link.sqlite3"
    link.symlink_to(path)
    with pytest.raises(OSError):
        SQLiteApprovalManager(link).get_status("durable-action")


def test_durable_identity_keeps_parent_and_tools_binding(tmp_path):
    path = tmp_path / "state.sqlite3"
    agent = durable_identity(path, "alice", ["summarize"])
    assert durable_identity(path, "alice", ["summarize"], agent) == agent
    with pytest.raises(AuthenticationError):
        durable_identity(path, "mallory", ["summarize"], agent)
    with pytest.raises(AuthenticationError):
        durable_identity(path, "alice", ["execute_command"], agent)
    assert "access_token" not in path.read_bytes().decode(errors="ignore")


def test_same_subject_in_another_issuer_cannot_adopt_identity(tmp_path):
    path = tmp_path / "state.sqlite3"
    parent = json.dumps(["https://issuer-a.test", "alice"])
    agent = durable_identity(path, parent, ["summarize"])
    with pytest.raises(AuthenticationError):
        durable_identity(path, json.dumps(["https://issuer-b.test", "alice"]), ["summarize"], agent)


def test_fresh_user_login_renews_same_agent_after_server_memory_loss(protected_api, keys, tmp_path, monkeypatch):
    from app.auth import agents
    monkeypatch.setenv("JEV_GATEWAY_STATE_DB", str(tmp_path / "state.sqlite3"))
    api, token = protected_api
    first = api.post("/auth/agent-token", headers=header(token), json={"tools": ["summarize"]}).json()
    monkeypatch.setattr(agents, "_sessions", {})
    resumed = api.post("/auth/agent-token", headers=header(token),
                       json={"tools": ["summarize"], "agent_id": first["agent_id"]})
    assert resumed.status_code == 200 and resumed.json()["agent_id"] == first["agent_id"]
    assert api.post("/auth/agent-token", headers=header(token, sub="other"),
                    json={"tools": ["summarize"], "agent_id": first["agent_id"]}).status_code == 403


def test_approval_status_is_owned_and_never_dispatches(protected_api, keys, monkeypatch):
    from app.gateway import gateway
    from app.approval.workflow import ApprovalManager
    manager = ApprovalManager()
    monkeypatch.setattr(gateway, "approval_manager", manager)
    api, token = protected_api
    first = api.post("/auth/agent-token", headers=header(token), json={"tools": ["execute_command"]}).json()
    agent_headers = {"Authorization": "Bearer " + first["access_token"]}
    manager.submit("owned", 0, [], "execute_command", action_hash="a" * 64, requester=first["agent_id"])
    monkeypatch.setattr(gateway, "mediate", lambda *a: pytest.fail("Status must not dispatch"))
    assert api.get("/tools/requests/owned").status_code == 401
    status = api.get("/tools/requests/owned", headers=agent_headers)
    assert status.json() == {"request_id": "owned", "status": "pending", "execution_authorized": False}
    other = api.post("/auth/agent-token", headers=header(token, sub="other"), json={"tools": ["execute_command"]}).json()
    assert api.get("/tools/requests/owned", headers={"Authorization": "Bearer " + other["access_token"]}).status_code == 403
