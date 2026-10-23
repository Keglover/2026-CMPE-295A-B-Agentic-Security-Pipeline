"""
Prompt Guard -- Pre-processor gatekeeper for prompt injection and jailbreak detection.

Project Plan Ref: Phase 4 -- Safety Model Integration

This module implements a two-tier detection strategy:
  1. Rule-based guard  (always on, zero latency) -- detects obvious injection patterns
  2. Model-based guard (optional, when transformers is installed) -- runs Llama-Prompt-Guard-2-86M

The rule-based layer provides immediate protection without any model loading.
The model layer can be enabled by installing ``transformers`` and setting
``PROMPT_GUARD_MODEL`` to a HuggingFace model ID (e.g. ``meta-llama/Prompt-Guard-86M``).

Design principle: fail-open on model errors. If the classifier cannot load or
raises an exception, we fall back to the rule-based guard so the pipeline never
blocks legitimate traffic due to infra issues.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

from app.models import PromptGuardResult

_log = logging.getLogger("prompt_guard")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Model ID for the optional HF transformers classifier.
_PROMPT_GUARD_MODEL = os.getenv("PROMPT_GUARD_MODEL", "").strip()

# Confidence threshold above which we treat a prediction as "injection".
# The Prompt Guard model is a binary classifier (injection vs benign).
_INJECTION_THRESHOLD = float(os.getenv("PROMPT_GUARD_THRESHOLD", "0.5"))

# ---------------------------------------------------------------------------
# Rule-based guard -- fast, deterministic, always available
# ---------------------------------------------------------------------------

_RULE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
            re.IGNORECASE,
        ),
    ),
    (
        "JAILBREAK_DELIMITER",
        re.compile(
            r"(\n\n|###|---|\*\*\*)\s*(user|assistant|system)\s*:\s*",
            re.IGNORECASE,
        ),
    ),
    (
        "PROMPT_LEAKING",
        re.compile(
            r"(repeat|print|output|display|return).{0,30}(system prompt|your instructions?|your context|everything above)",
            re.IGNORECASE,
        ),
    ),
    (
        "ROLEPLAY_JAILBREAK",
        re.compile(
            r"(pretend you are|act as (if you (are|were)|a)|roleplay as|you are now a)",
            re.IGNORECASE,
        ),
    ),
    (
        "DELIMITER_INJECTION",
        re.compile(r"`\s*\{\s*\}\s*`|<\|im_start\|>|<\|endoftext\|>", re.IGNORECASE),
    ),
    (
        "BASE64_OBFUSCATION",
        re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
    ),
]


def _rule_based_detect(content: str) -> tuple[bool, float, str | None, str]:
    """
    Run the lightweight rule-based guard.

    Returns:
        (is_injection, confidence, injection_type, rationale)
    """
    max_confidence = 0.0
    matched_types: list[str] = []

    for injection_type, pattern in _RULE_PATTERNS:
        if pattern.search(content):
            matched_types.append(injection_type)
            # Each rule match adds to confidence linearly (capped at 0.95)
            max_confidence = min(0.95, max_confidence + 0.25)

    if matched_types:
        return (
            True,
            max_confidence,
            matched_types[0],
            f"Rule-based guard detected {len(matched_types)} pattern(s): {', '.join(matched_types)}.",
        )

    return False, 0.0, None, "No prompt injection patterns detected by rule-based guard."


# ---------------------------------------------------------------------------
# Model-based guard -- optional, uses transformers when available
# ---------------------------------------------------------------------------

class _ModelGuard:
    """
    Lazy-initialized wrapper around a HuggingFace transformers classifier.

    The model is loaded on first use so that pipeline startup is not blocked
    by a heavy download.  If ``transformers`` is not installed or the model
    fails to load, the guard silently falls back to rule-based detection.
    """

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        self._tokenizer: Any | None = None
        self._model: Any | None = None
        self._load_error: str | None = None

    def _ensure_loaded(self) -> bool:
        """Load model/tokenizer if not already loaded. Returns True on success."""
        if self._model is not None and self._tokenizer is not None:
            return True
        if self._load_error is not None:
            return False

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError:
            self._load_error = "transformers library not installed"
            _log.warning("Prompt Guard model disabled: %s", self._load_error)
            return False

        try:
            _log.info("Loading Prompt Guard model: %s", self.model_id)
            token = os.getenv("HF_TOKEN", "").strip() or None
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id, token=token)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id, token=token)
            _log.info("Prompt Guard model loaded successfully")
            return True
        except Exception as exc:
            self._load_error = str(exc)
            _log.warning("Failed to load Prompt Guard model: %s", self._load_error)
            return False

    def predict(self, text: str) -> tuple[bool, float, str | None, str]:
        """
        Run model inference on *text* and return detection result.

        Falls back to rule-based detection if the model is unavailable.
        """
        if not self._ensure_loaded():
            # Model not available -- fall back to rules
            return _rule_based_detect(text)

        try:
            import torch

            inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                logits = self._model(**inputs).logits
                probabilities = torch.softmax(logits, dim=-1)
                # Binary classifier: class 0 = benign, class 1 = injection
                injection_prob = float(probabilities[0][1])

            is_injection = injection_prob >= _INJECTION_THRESHOLD
            injection_type = "INJECTION" if is_injection else "BENIGN"
            rationale = (
                f"Model prediction: injection_prob={injection_prob:.4f} "
                f"(threshold={_INJECTION_THRESHOLD}). "
                f"Result: {'INJECTION' if is_injection else 'BENIGN'}."
            )
            return is_injection, injection_prob, injection_type, rationale
        except Exception as exc:
            _log.warning("Model inference failed, falling back to rules: %s", exc)
            return _rule_based_detect(text)


# Singleton model guard -- created lazily on first detect() call
_model_guard: _ModelGuard | None = None


def _get_model_guard() -> _ModelGuard | None:
    global _model_guard
    if _model_guard is None and _PROMPT_GUARD_MODEL:
        _model_guard = _ModelGuard(_PROMPT_GUARD_MODEL)
    return _model_guard


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(request_id: str, content: str) -> PromptGuardResult:
    """
    Run the Prompt Guard on *content*.

    If a model is configured (via PROMPT_GUARD_MODEL env var) and
    ``transformers`` is installed, the model is used. Otherwise the
    lightweight rule-based guard is used.

    Args:
        request_id: Forwarded from the original request.
        content: The text to evaluate.

    Returns:
        PromptGuardResult with detection outcome.
    """
    guard = _get_model_guard()

    if guard is not None:
        is_injection, confidence, injection_type, rationale = guard.predict(content)
    else:
        # No model configured -- use rule-based guard exclusively
        is_injection, confidence, injection_type, rationale = _rule_based_detect(content)

    return PromptGuardResult(
        request_id=request_id,
        is_injection=is_injection,
        confidence=round(confidence, 4),
        injection_type=injection_type,
        rationale=rationale,
    )


def is_enabled() -> bool:
    """Return True when either model or rule-based guard is active."""
    return True  # Rule-based guard is always enabled
