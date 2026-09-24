import asyncio

class AgentPipelineTarget(...):
    async def send_prompt_async(self, prompt_request):
        result = await asyncio.to_thread(
            run_agent_turn,
            prompt_text,
        )

        return {
            "response": result["reply"],
            "metadata": {
                "prompt_blocked": result["prompt_blocked"],
                "tool_calls_made": result["tool_calls_made"],
                "tool_calls_blocked": result["tool_calls_blocked"],
                "pipeline_traces": result["pipeline_traces"],
            },
        }