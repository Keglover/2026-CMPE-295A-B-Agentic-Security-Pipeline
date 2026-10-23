#!/usr/bin/env python3
"""Check model generation with a public greeting; never log credentials or run tools."""
import argparse
import os
from pathlib import Path

from promptrail.agent.client import SecurityException
from promptrail.agent.conversation import ConversationCheckpoint
from promptrail.agent.model_client import ModelClient
from promptrail.agent.model_config import model_values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("auth/.env.models"))
    args = parser.parse_args()
    try:
        values = model_values(args.config)
        public = lambda name: os.environ.get(name) or values.get(name)
        checkpoint = ConversationCheckpoint(gateway_url="http://127.0.0.1:8003", tools=["summarize"],
            prompt="Hello!", model_protocol=public("JEV_MODEL_PROTOCOL") or "ollama",
            model_url=public("JEV_MODEL_URL"), model_name=public("JEV_MODEL_NAME"), model_env_file=str(args.config),
            fallback_url=public("JEV_FALLBACK_MODEL_URL"), fallback_model=public("JEV_FALLBACK_MODEL_NAME") or None)
        with ModelClient(checkpoint) as client:
            reply = client.complete([{"role": "user", "content": "Hello!"}], [])
            if reply.tool_calls:
                raise SecurityException("UNEXPECTED_MODEL_TOOL_PROPOSAL")
            print(f"Model check passed: {client.last_endpoint} returned a complete reply. No tool was called.")
        return 0
    except SecurityException as exc:
        print("Model check stopped: " + exc.code)
    except (ValueError, OSError, TypeError):
        print("Model check stopped: invalid or unavailable private configuration.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
