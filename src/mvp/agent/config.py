"""
Agent configuration — API keys, model selection, pipeline URL.

All secrets are read from environment variables. Never hardcode keys.

Supported providers (all use the openai Python package):
  OpenAI:      export OPENAI_API_KEY=sk-...  (default, uses gpt-4o-mini)
  Together AI: export OPENAI_API_KEY=... OPENAI_BASE_URL=https://api.together.xyz/v1 AGENT_MODEL=Qwen/Qwen2.5-72B-Instruct
  Fireworks:   export OPENAI_API_KEY=... OPENAI_BASE_URL=https://api.fireworks.ai/inference/v1 AGENT_MODEL=accounts/fireworks/models/qwen2p5-72b-instruct
  Ollama:      export OPENAI_API_KEY=ollama OPENAI_BASE_URL=http://localhost:11434/v1 AGENT_MODEL=qwen2.5:7b
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Reason: load .env from the mvp/ root so secrets are picked up automatically
# without needing to `export` them manually in every terminal session.
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_path)

# LLM provider settings — swap models by changing env vars, no code changes
OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str | None = os.environ.get("OPENAI_BASE_URL") or None
MODEL: str = os.environ.get("AGENT_MODEL", "gpt-4o-mini")

# Pipeline connection — the FastAPI server must be running
PIPELINE_URL: str = os.environ.get("PIPELINE_URL", "http://localhost:8000/pipeline")

# Safety cap: max tool-call round-trips before the agent stops
MAX_ITERATIONS: int = int(os.environ.get("AGENT_MAX_ITERATIONS", "5"))
