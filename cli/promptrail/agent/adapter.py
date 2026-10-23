"""Bridge the repository's LLM loop to the authenticated gateway session."""
from promptrail.agent.models import ToolCallRequest
from promptrail.models import EvaluationRequest


class GatewayAdapter:
    def __init__(self, session):
        self.session = session

    def screen(self, content, source_type="direct_prompt"):
        result = self.session.evaluate(EvaluationRequest(content=content, source_type=source_type))
        # Inspection returns no redacted text. Never send unredacted SANITIZE input to the LLM.
        allow = result.status == "evaluated" and result.policy_action.value == "ALLOW"
        return {"request_id": result.request_id, "policy": {"policy_action": "ALLOW" if allow else "BLOCK",
                "policy_reason": result.reason_code}, "risk": {"risk_score": result.risk_score},
                "summary": result.reason_code}

    def call(self, payload):
        request = ToolCallRequest.model_validate(payload)
        result = self.session.call(request)
        output = result.tool_output
        if result.outcome == "EXECUTED" and output is not None:
            screened = self.screen(str(output)[:50000], source_type="retrieved_content")
            if screened["policy"]["policy_action"] != "ALLOW":
                output = "[Tool output withheld by the security gateway.]"
        return {"request_id": request.request_id,
                "policy": {"policy_action": result.evaluation.policy_action.value},
                "risk": {"risk_score": result.evaluation.risk_score},
                "gateway": {"gateway_decision": "EXECUTED" if result.outcome == "EXECUTED" else "DENIED",
                            "decision_reason": result.reason_code, "tool_output": output},
                "pending_action": request.model_dump(mode="json") if result.outcome == "REQUIRE_APPROVAL" else None}
