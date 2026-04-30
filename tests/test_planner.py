"""
Tests for the Planner Engine and dynamic tool selection.
"""
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

