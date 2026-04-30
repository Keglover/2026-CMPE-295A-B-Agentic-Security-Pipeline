"""
Planner Stage for extracting intent and selecting a tool dynamically.

This serves as the core orchestration logic for selecting tools when the caller
does not pass a specific `proposed_tool` but provides an intent or task.
"""

from abc import ABC, abstractmethod
from typing import Any
import logging

from app.models import PlannerRequest, PlannerResponse, PolicyAction

logger = logging.getLogger(__name__)

class BasePlanner(ABC):
    """
    Abstract base class for all Planners.
    Guarantees standard input and output models.
    """

    @abstractmethod
    def plan(self, request: PlannerRequest) -> PlannerResponse:
        """
        Produce a plan (tool + args) given the prompt and available tools.
        """
        pass

class MockPlanner(BasePlanner):
    """
    Mock implementation of a Planner. Simulates LLM execution by doing
    basic keyword or heuristic mapping. Later swapped out with OllamaPlanner.
    """

    def plan(self, request: PlannerRequest) -> PlannerResponse:
        logger.info(
            "mock_planner.planning",
            request_id=request.request_id,
            action=request.policy_action.value
        )
        task = request.task_description.lower()
        tool_name = "unknown"
        tool_args = {}
        rationale = "No suitable tool found"

        # Trivial intent matching
        if "summarize" in task or "summary" in task:
            tool_name = "summarize"
            tool_args = {"text": request.task_description}
            rationale = "Task matched keyword 'summarize'."
        elif "note" in task and ("write" in task or "create" in task or "save" in task):
            tool_name = "write_note"
            tool_args = {"title": "Planner Note", "body": request.task_description}
            rationale = "Task matched 'write note'."
        elif "note" in task and ("search" in task or "find" in task):
            tool_name = "search_notes"
            tool_args = {"query": request.task_description}
            rationale = "Task matched 'search note'."
        elif "fetch" in task or "http" in task or "url" in task or ("get" in task and "http" in task):
            tool_name = "fetch_url"
            # Attempt basic extraction of URL
            words = task.split()
            url = next((w for w in words if w.startswith("http")), "http://example.com")
            tool_args = {"url": url}
            rationale = "Task matched 'fetch' or 'url'."
        elif "hallucinate" in task:
            tool_name = "fake_tool"
            tool_args = {}
            rationale = "Intentional hallucination for testing."

        if tool_name not in request.available_tools and tool_name != "fake_tool":
            tool_name = "unknown"

        return PlannerResponse(
            tool_name=tool_name,
            tool_args=tool_args,
            rationale=rationale,
            request_id=request.request_id
        )

# Factory or registry
def get_planner() -> BasePlanner:
    """Returns the configured planner instance."""
    # We can inject configuration here later to switch to Ollama
    return MockPlanner()
