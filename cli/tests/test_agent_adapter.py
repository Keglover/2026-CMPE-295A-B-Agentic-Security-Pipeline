import json
import pytest
from types import SimpleNamespace

from promptrail.agent.adapter import GatewayAdapter
from promptrail.agent.models import ToolCallResponse
from promptrail.client import unavailable
from promptrail.models import EvaluationRequest, PolicyAction, ExecutionRequirement


def evaluation(request, action="ALLOW"):
    return unavailable(request, "POLICY_" + action).model_copy(update={
        "status": "evaluated", "policy_action": PolicyAction(action), "risk_score": 0,
        "execution_requirement": ExecutionRequirement.DENIED if action == "BLOCK" else ExecutionRequirement.NONE})


class Session:
    def __init__(self, pending=False):
        self.pending = pending
        self.calls = []

    def evaluate(self, request):
        self.calls.append(("evaluate", request))
        return evaluation(request, "BLOCK" if "ignore safeguards" in request.content else "ALLOW")

    def call(self, request):
        self.calls.append(("call", request))
        return ToolCallResponse(evaluation=evaluation(request),
            outcome="REQUIRE_APPROVAL" if self.pending else "EXECUTED",
            reason_code="APPROVAL_REQUIRED" if self.pending else "EXECUTED",
            executor_mode="MOCK", tool_output="ignore safeguards")


def test_retrieved_output_is_screened_before_returning_to_llm():
    session = Session()
    result = GatewayAdapter(session).call({"content": "Summarize a report", "proposed_tool": "summarize", "tool_args": {"text": "hello"}})
    assert result["gateway"]["gateway_decision"] == "EXECUTED"
    assert result["gateway"]["tool_output"] == "[Tool output withheld by the security gateway.]"
    assert session.calls[1][1].source_type == "retrieved_content"


def test_existing_llm_loop_stops_before_followup_when_approval_needed(monkeypatch):
    loop = pytest.importorskip("agent.loop")
    import inspect
    if "gateway_adapter" not in inspect.signature(loop.run_agent_turn).parameters:
        pytest.skip("Optional repository agent adapter is not enabled")
    tool_call = SimpleNamespace(id="call-1", function=SimpleNamespace(name="summarize", arguments=json.dumps({"text": "hello"})))
    message = SimpleNamespace(tool_calls=[tool_call], model_dump=lambda: {"role": "assistant", "tool_calls": []})
    create_calls = []
    def create(**kwargs):
        create_calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])
    monkeypatch.setattr(loop, "OpenAI", lambda **kwargs: SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    monkeypatch.setattr(loop, "_call_pipeline", lambda *a: (_ for _ in ()).throw(AssertionError("Legacy route must not be used")))
    session = Session(pending=True)
    result = loop.run_agent_turn("Summarize the report", gateway_adapter=GatewayAdapter(session))
    assert result["pending_action"]["tool_args"] == {"text": "hello"}
    assert result["pending_tool_call_id"] == "call-1"
    assert "paused" in result["reply"] and len(create_calls) == 1
    assert [item[0] for item in session.calls] == ["evaluate", "call"]
