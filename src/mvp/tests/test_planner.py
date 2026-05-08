"""
Tests for the Planner Engine and dynamic tool selection.
"""
from app.planner import engine
from app.models import PlannerRequest, PolicyAction
from app.planner.engine import get_planner

def test_mock_planner_summarize():
    planner = get_planner()
    req = PlannerRequest(
        task_description="Please summarize this document",
        available_tools={"summarize": {}, "write_note": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-1"
    )
    res = planner.plan(req)
    
    assert res.tool_name == "summarize"
    assert "text" in res.tool_args
    assert res.tool_args["text"] == "Please summarize this document"

def test_mock_planner_write_note():
    planner = get_planner()
    req = PlannerRequest(
        task_description="write a note about the meeting",
        available_tools={"summarize": {}, "write_note": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-2"
    )
    res = planner.plan(req)
    
    assert res.tool_name == "write_note"
    assert "title" in res.tool_args
    assert "body" in res.tool_args
    assert res.tool_args["body"] == "write a note about the meeting"

def test_mock_planner_unknown_tool():
    planner = get_planner()
    req = PlannerRequest(
        task_description="do something that we don't have a tool for",
        available_tools={"summarize": {}, "write_note": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-3"
    )
    res = planner.plan(req)
    
    assert res.tool_name == "unknown"
    assert res.tool_args == {}

def test_mock_planner_fake_tool_hallucination():
    planner = get_planner()
    req = PlannerRequest(
        task_description="Please hallucinate a tool for me",
        available_tools={"summarize": {}, "write_note": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-4"
    )
    res = planner.plan(req)
    
    assert res.tool_name == "fake_tool"


def test_mock_planner_execute_command_intent(monkeypatch):
    monkeypatch.setattr(
        engine,
        "_planner_generate_command",
        lambda host, model, task: "echo generated-by-ollama",
    )

    planner = get_planner()
    req = PlannerRequest(
        task_description="Run command: echo hello",
        available_tools={"execute_command": {}, "summarize": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-5"
    )
    res = planner.plan(req)

    assert res.tool_name == "execute_command"
    assert "command" in res.tool_args
    assert res.tool_args["command"] == "echo generated-by-ollama"


def test_mock_planner_dmesg_python_program_prompt_maps_to_command(monkeypatch):
    monkeypatch.setattr(engine, "_planner_generate_command", lambda host, model, task: None)

    planner = get_planner()
    req = PlannerRequest(
        task_description="Write and execute a python program that prints the output of executing the dmesg command",
        available_tools={"execute_command": {}, "summarize": {}},
        risk_score=0,
        policy_action=PolicyAction.ALLOW,
        request_id="test-req-6"
    )
    res = planner.plan(req)

    assert res.tool_name == "execute_command"
    command = str(res.tool_args.get("command", ""))
    assert "python -c" in command
    assert "dmesg" in command


def test_execute_command_prefers_cloud_then_local_fallback(monkeypatch):
    calls: list[str] = []

    def fake_generate(host: str, model: str, task: str) -> str | None:
        calls.append(host)
        if host == engine._PLANNER_OLLAMA_CLOUD_HOST:
            return None
        return "echo local-fallback"

    monkeypatch.setattr(engine, "_planner_generate_command", fake_generate)

    command = engine.MockPlanner._extract_execute_command("Run command to print hello")

    assert command == "echo local-fallback"
    assert calls[0] == engine._PLANNER_OLLAMA_CLOUD_HOST
    assert calls[1] == engine._PLANNER_OLLAMA_LOCAL_HOST

