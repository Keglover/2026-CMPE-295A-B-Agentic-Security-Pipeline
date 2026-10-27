from __future__ import annotations
from typing import Any
from .ollama_llm import build_ollama_llm
from .pipeline_defense import PipelineDefense

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor

def build_pipeline(*, model: str, model_id: str | None,
                   ollama_base_url: str, defense_endpoint: str,
                   use_defense: bool) -> Any:

    llm = build_ollama_llm(model=model, model_id=model_id, ollama_base_url=ollama_base_url)
    loop_elements = [ToolsExecutor()]
    
    if use_defense:
        loop_elements.append(PipelineDefense(defense_endpoint=defense_endpoint))

    loop_elements.append(llm)

    pipeline = AgentPipeline(
        [
            SystemMessage(""),
            InitQuery(),
            llm,
            ToolsExecutionLoop(*loop_elements),
        ]
    )

    pipeline.name = f"ollama-{model_id or model}-{'mvp-pipeline' if use_defense else 'no-defense'}"
    return pipeline
