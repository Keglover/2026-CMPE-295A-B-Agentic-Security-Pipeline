from __future__ import annotations

from typing import Any

def build_ollama_llm(
    model: str,
    base_url: str = "http://localhost:11434/v1",
    model_id: str | None = None,
) -> Any:
    """Return AgentDojo's local LLM element backed by Ollama.

    AgentDojo's ``LocalLLM`` uses the text-based function-call format expected
    by its tool execution loop.  Ollama exposes the same chat-completions
    transport, so no second agent implementation is needed here.
    """

    try:
        from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "AgentDojo is required for the benchmark. Install evaluation/agentdojo/requirements-eval.txt. \
            If you have already installed it, ensure that it is available in your PYTHONPATH."
        ) from exc

    client = openai.OpenAI(api_key="ollama", base_url=base_url.rstrip("/"))
    return LocalLLM(client=client, model=model_id or model, temperature=0.0, top_p=0.9)
