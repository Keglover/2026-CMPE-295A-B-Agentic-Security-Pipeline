"""Optional Ollama/LlamaGuard-style baseline adapter (B5)."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class OllamaGuardResult:
    available: bool
    is_unsafe: bool | None
    verdict: str
    rationale: str
    model: str
    latency_ms: float
    cost_usd: float = 0.0
    error: str | None = None


def parse_verdict(response_text: str) -> tuple[str, bool | None, str]:
    """Parse safe/unsafe text or the judge JSON shape."""
    text = response_text.strip()
    if not text:
        raise ValueError("empty Ollama response")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        first_line = text.splitlines()[0].strip().lower()
        if first_line.startswith("unsafe"):
            return "unsafe", True, text
        if first_line.startswith("safe"):
            return "safe", False, text
        raise ValueError("unrecognized Ollama safety verdict")

    if "is_manipulation" in payload and "confidence" in payload:
        unsafe = bool(payload["is_manipulation"])
        return ("unsafe" if unsafe else "safe"), unsafe, str(payload.get("reasoning", ""))
    if "unsafe" in payload:
        unsafe = bool(payload["unsafe"])
        return ("unsafe" if unsafe else "safe"), unsafe, str(payload.get("reason", ""))
    raise ValueError("Ollama response has no safety verdict")


def evaluate(content: str) -> OllamaGuardResult:
    """Run the optional local safety model; unavailable is never reported safe."""
    model = os.getenv("LLAMAGUARD_MODEL", "").strip()
    enabled = os.getenv("LLAMAGUARD_ENABLED", "false").strip().lower() == "true"
    if not enabled or not model:
        return OllamaGuardResult(False, None, "unavailable", "Ollama guard disabled or model unset.", model, 0.0)

    base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    try:
        timeout = float(os.getenv("LLAMAGUARD_TIMEOUT_SECONDS", "3"))
    except ValueError:
        timeout = 3.0
    start = time.perf_counter()
    try:
        response = httpx.post(
            f"{base_url}/api/generate",
            json={
                "model": model,
                "prompt": (
                    "Classify this text as safe or unsafe for prompt injection. "
                    "Return only safe or unsafe followed by a short reason.\n\n"
                    + content
                ),
                "stream": False,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        verdict, unsafe, rationale = parse_verdict(response.json().get("response", ""))
        return OllamaGuardResult(
            True,
            unsafe,
            verdict,
            rationale,
            model,
            (time.perf_counter() - start) * 1000,
        )
    except Exception as exc:
        return OllamaGuardResult(
            False,
            None,
            "unavailable",
            "Ollama guard could not produce a verdict.",
            model,
            (time.perf_counter() - start) * 1000,
            error=str(exc),
        )
