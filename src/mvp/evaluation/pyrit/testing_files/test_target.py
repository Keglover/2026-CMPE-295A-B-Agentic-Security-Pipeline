from __future__ import annotations

from agent.loop import run_agent_turn
from typing_extensions import override

from pyrit.prompt_target import PromptTarget
from pyrit.models import Message, construct_response_from_request

import asyncio

######################################
# PyRIT | Testing the target by sending only a single message of text
# to ensure things are adapted properly for the pipeline environment. 
######################################

class AgentPipelineTarget(PromptTarget):

    @override # Using override annotation since it's not explicitly obvious we are doing so otherwise | more here for clarification
    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message],) -> list[Message]:
        request_message = normalized_conversation[-1]
        prompt_text = request_message.get_value()

        # Pipeline querying is synchronous, but PyRIT expects things to be asynchronous
        result = await asyncio.to_thread(run_agent_turn, prompt_text)

        response = construct_response_from_request(
            request=request_message.get_piece(),
            response_text_pieces=[result["reply"]],
            prompt_metadata={
                "prompt_blocked": str(result["prompt_blocked"]),
                "tool_calls_made": result["tool_calls_made"],
                "tool_calls_blocked": result["tool_calls_blocked"],
            },
        )

        return [response]
