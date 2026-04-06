"""
Risk Engine module.

Responsibility: Analyse normalized text and produce a structured risk score
(0-100), one or more attack categories, the matched signals, and a plain-
English rationale.

Design: Rules-first for MVP (fast, deterministic, transparent).
An ML classifier extension point is left in place for Sprint 2+.

The four attack families covered:
  - INSTRUCTION_OVERRIDE  — attempts to replace the agent's system prompt
  - DATA_EXFILTRATION     — attempts to leak data out of the agent's context
  - TOOL_COERCION         — attempts to force specific tool calls
  - OBFUSCATION           — encoding tricks that hide the above
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import NormalizedInput, RiskCategory, RiskResult


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """
    A single detection rule.

    Args:
        name (str): Human-readable signal label shown in matched_signals.
        pattern (re.Pattern): Compiled regex to test against content.
        category (RiskCategory): Attack family this rule belongs to.
        score_contribution (int): Points added to risk_score when matched.
    """

    name: str
    pattern: re.Pattern[str]
    category: RiskCategory
    score_contribution: int


# ---------------------------------------------------------------------------
# Rule registry
# Patterns are case-insensitive; adjust flags below as rules grow.
# ---------------------------------------------------------------------------

_FLAGS = re.IGNORECASE | re.DOTALL

RULES: list[Rule] = [
    # --- INSTRUCTION_OVERRIDE ---
    Rule(
        name="ignore_previous_instructions",
        pattern=re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
            _FLAGS,
        ),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=40,
    ),
    Rule(
        name="forget_instructions",
        pattern=re.compile(r"forget\s+(everything|all|prior|previous)", _FLAGS),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=35,
    ),
    Rule(
        name="new_system_prompt",
        pattern=re.compile(
            r"(your\s+new\s+instructions?|new\s+system\s+prompt|you\s+are\s+now\s+a)",
            _FLAGS,
        ),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=40,
    ),
    Rule(
        name="jailbreak_roleplay",
        pattern=re.compile(
            r"(pretend\s+you\s+are|act\s+as\s+(if\s+you\s+(are|were)|a)|roleplay\s+as)",
            _FLAGS,
        ),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=25,
    ),
    Rule(
        name="policy_evasion_language",
        pattern=re.compile(
            r"(without\s+(restriction|filter|limitation)|"
            r"no\s+(rules|limits|guardrails))",
            _FLAGS,
        ),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=35,
    ),
    Rule(
        name="persist_context",
        pattern=re.compile(
            r"(remember|store|persist|retain).{0,40}"
            r"(this session|conversation|context|instructions?)",
            _FLAGS,
        ),
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        score_contribution=45,
    ),
    # --- DATA_EXFILTRATION ---
    Rule(
        name="system_prompt_probe",
        pattern=re.compile(
            r"(what\s+are\s+your\s+(instructions|rules|system\s+prompt)|"
            r"how\s+were\s+you\s+configured)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=35,
    ),
    Rule(
        name="send_to_external_url",
        pattern=re.compile(
            r"(send|post|upload|exfiltrate|leak).{0,40}(http|https|ftp)://",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=50,
    ),
    Rule(
        name="fetch_and_send",
        pattern=re.compile(
            r"(fetch|retrieve).{0,40}(then|and).{0,40}(send|email|post|upload)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=45,
    ),
    Rule(
        name="repeat_context_verbatim",
        pattern=re.compile(
            r"(repeat|print|output|display|return).{0,30}"
            r"(system prompt|your instructions?|your context|everything above)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=35,
    ),
    Rule(
    name="reveal_chain_of_thought",
    pattern=re.compile(
            r"(show\s+your\s+(reasoning|chain\s+of\s+thought)|"
            r"explain\s+step\s+by\s+step\s+in\s+detail)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=25,
    ),
    Rule(
    name="sensitive_data_request",
    pattern=re.compile(
            r"(show|send|expose|leak|give).{0,20}"
            r"(api\s*key|password|secret|token|credentials|private\s+key)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=45,
    ),
    Rule(
        name="local_file_access",
        pattern=re.compile(
                r"(/etc/passwd|\.env|config\.json|id_rsa|ssh\s+key)",
                _FLAGS,
            ),
            category=RiskCategory.DATA_EXFILTRATION,
            score_contribution=50,
    ),
    Rule(
        name="extract_full_conversation",
        pattern=re.compile(
            r"(dump|export|get).{0,30}(conversation|chat\s+history|logs?)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=40,
    ),
    Rule(
        name="data_dredge",
        pattern=re.compile(
            r"(print|output|export|list).{0,40}"
            r"(all|every|complete).{0,30}"
            r"(passwords?|secrets?|tokens?|credentials?|files?|database|logs)",
            _FLAGS,
        ),
        category=RiskCategory.DATA_EXFILTRATION,
        score_contribution=55,
    ),
    # --- TOOL_COERCION ---
    Rule(
        name="force_tool_call",
        pattern=re.compile(
            r"(you must|you should|immediately|right now).{0,30}"
            r"(call|execute|run|invoke|use).{0,20}(tool|function|api|command)",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=40,
    ),
    Rule(
        name="bypass_gateway",
        pattern=re.compile(
            r"(bypass|skip|ignore|circumvent).{0,30}"
            r"(gateway|security|check|filter|policy|restriction)",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=55,
    ),
    Rule(
        name="delete_files",
        pattern=re.compile(
            r"(delete|remove|wipe|erase|destroy).{0,30}(all\s+files?|everything|database|logs?)",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=60,
    ),
    Rule(
    name="specific_tool_targeting",
        pattern=re.compile(
            r"(use|call|invoke).{0,20}(fetch_url|write_note|search_notes|summarize)",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=45,
    ),
    Rule(
    name="malicious_tool_arguments",
        pattern=re.compile(
            r"(url\s*=\s*https?://[^\s]+|command\s*=\s*\w+|exec\s*\()",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=40,
    ),
    Rule(
        name="execute_shell",
        pattern=re.compile(
            r"(run|execute|spawn|launch).{0,30}"
            r"(bash|sh|cmd|powershell|terminal|shell)",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=55,
    ),
    Rule(
        name="chain_injection",
        pattern=re.compile(
            r"(first|then|after that|next).{0,40}"
            r"(ignore|bypass|override).*instructions?",
            _FLAGS,
        ),
        category=RiskCategory.TOOL_COERCION,
        score_contribution=45,
    ),
    # --- OBFUSCATION ---
    Rule(
        name="stealth_obfuscation_combo",
        pattern=re.compile(
            r"([A-Za-z0-9+/]{20,}={0,2}).*(\\u[0-9a-fA-F]{4}).*(0x[0-9a-fA-F]{2,})",
            _FLAGS,
        ),
        category=RiskCategory.OBFUSCATION,
        score_contribution=35,
    ),
    Rule(
        name="base64_like_blob",
        # A run of 40+ base64 chars with no spaces is suspicious in prompt context
        pattern=re.compile(r"[A-Za-z0-9+/]{40,}={0,2}", _FLAGS),
        category=RiskCategory.OBFUSCATION,
        score_contribution=20,
    ),
    Rule(
        name="unicode_escape_sequence",
        pattern=re.compile(r"(\\u[0-9a-fA-F]{4}){3,}", _FLAGS),
        category=RiskCategory.OBFUSCATION,
        score_contribution=20,
    ),
    Rule(
        name="hex_encoded_content",
        pattern=re.compile(r"(0x[0-9a-fA-F]{2,}\s*){4,}", _FLAGS),
        category=RiskCategory.OBFUSCATION,
        score_contribution=20,
    ),
    Rule(
        name="mixed_encoding",
        pattern=re.compile(
            r"(%[0-9a-fA-F]{2}){5,}",
            _FLAGS,
        ),
        category=RiskCategory.OBFUSCATION,
        score_contribution=25,
    ),
    Rule(
    name="fragmented_injection",
        pattern=re.compile(
            r"(ignore.{0,10}\n.{0,10}instructions)",
            _FLAGS,
        ),
        category=RiskCategory.OBFUSCATION,
        score_contribution=25,
    ),
]

# ---------------------------------------------------------------------------
# LLM/ML hooks
# ---------------------------------------------------------------------------

def _ml_risk_score(normalized: NormalizedInput) -> int:
    """
    Sprint 2+ ML signal hook.

    Future:
      - feature extraction from text
      - anomaly detection / classifier

    For now: deterministic stub
    """
    return 0


def _llm_risk_score(normalized: NormalizedInput) -> int:
    """
    Optional LLM classifier hook.

    Future:
      - call LLM endpoint
      - map label → score

    For now: deterministic stub
    """
    return 0

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _cap_score(raw: int) -> int:
    """Clamp score to the 0-100 range."""
    return max(0, min(100, raw))


def score(normalized: NormalizedInput) -> RiskResult:
    """
    Run all rules against the normalized content and produce a risk result.

    Rules are additive: multiple matches accumulate. Score is capped at 100.
    The highest-contribution category becomes the primary category label.

    Args:
        normalized (NormalizedInput): Output from the normalize stage.

    Returns:
        RiskResult: Structured risk assessment ready for the policy engine.
    """
    text = normalized.normalized_content or ""
    if not text.strip():
        return RiskResult(
            request_id=normalized.request_id,
            risk_score=0,
            risk_categories=[RiskCategory.BENIGN],
            matched_signals=[],
            rationale="Empty input. No risk detected.",
        )
    total_score = 0
    matched_signals: list[str] = []
    detected_categories: dict[RiskCategory, int] = {}

    for rule in RULES:
        if rule.pattern.search(text):
            matched_signals.append(rule.name)
            total_score += rule.score_contribution
            detected_categories[rule.category] = (
                detected_categories.get(rule.category, 0) + rule.score_contribution
            )

    capped = _cap_score(total_score)

    ml_score = _ml_risk_score(normalized)
    llm_score = _llm_risk_score(normalized)

    # Add model signals (traceability)
    if ml_score > 0:
        matched_signals.append("ml_model_signal")

    if llm_score > 0:
        matched_signals.append("llm_model_signal")

    # Deterministic override: rules always win at high risk
    if capped >= 90:
        final_score = capped
    else:
        final_score = _cap_score(max(capped, ml_score, llm_score))

    if not detected_categories:
        if final_score > 0:
            categories = [RiskCategory.OBFUSCATION]  # fallback risk class
            rationale = "Model-based signal detected potential risk."
        else:
            categories = [RiskCategory.BENIGN]
            rationale = "No attack signals detected. Input appears safe."
    else:
        # Sort categories by cumulative contribution (highest first)
        categories = sorted(
            detected_categories.keys(),
            key=lambda c: detected_categories[c],
            reverse=True,
        )
        top = categories[0].value
        rationale = (
            f"Detected {len(matched_signals)} signal(s). "
            f"Primary threat category: {top}. "
            f"Matched: {', '.join(matched_signals)}."
        )
        
    if final_score != capped:
        rationale += f" Model-based adjustment used (ML={ml_score}, LLM={llm_score})."

    return RiskResult(
        request_id=normalized.request_id,
        risk_score=final_score,
        risk_categories=categories,
        matched_signals=matched_signals,
        rationale=rationale,
    )
