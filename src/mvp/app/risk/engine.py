"""
Risk Engine module.

Responsibility: Analyse normalized text and produce a structured risk score
(0-100), one or more attack categories, the matched signals, and a plain-
English rationale.

Design: Rules-first for MVP (fast, deterministic, transparent).
An ML classifier extension point is left in place for Sprint 2+.

The four regex attack families covered:
  - INSTRUCTION_OVERRIDE  — attempts to replace the agent's system prompt
  - DATA_EXFILTRATION     — attempts to leak data out of the agent's context
  - TOOL_COERCION         — attempts to force specific tool calls
  - OBFUSCATION           — encoding tricks that hide the above

Additionally, LLM_FLAGGED records a positive or fail-closed verdict from the
optional LLM judge (matched_signals distinguish escalation vs failure).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from app.models import NormalizedInput, RiskCategory, RiskResult

try:
    from app.risk.jev import run_jev_sync
except ModuleNotFoundError:
    run_jev_sync = None

try:
    from app.risk.llm_judge import run_judge_sync
except ModuleNotFoundError:
    run_judge_sync = None

judge = run_jev_sync
fallback_judge = run_judge_sync


def llm_judge_enabled() -> bool:
    """Read the LLM judge toggle at call time so CLI runs can flip it safely."""
    return os.getenv("LLM_JUDGE_ENABLED", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    """
    A single regex rule for detecting prompt injection.
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

JUDGE_BAND_LOW: int = 15
JUDGE_BAND_HIGH: int = 60
JUDGE_CONFIDENCE_MIN: float = 0.7
JUDGE_ESCALATION_SCORE: int = 70
JUDGE_FAILURE_SCORE: int = 80


def build_rules(category: RiskCategory, *specs: tuple[str, str, int]) -> list[Rule]:
    """Build rules from compact (name, pattern, score) specifications."""
    return [Rule(name, re.compile(pattern, _FLAGS), category, score)
          for name, pattern, score in specs]


RULES: list[Rule] = sum([
    build_rules(RiskCategory.INSTRUCTION_OVERRIDE,
       ("ignore_previous_instructions", r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", 40),
       ("forget_instructions", r"forget\s+(everything|all|prior|previous)", 35),
       ("new_system_prompt", r"(your\s+new\s+instructions?|new\s+system\s+prompt|you\s+are\s+now\s+a)", 40),
       ("jailbreak_roleplay", r"(pretend\s+you\s+are|act\s+as\s+(if\s+you\s+(are|were)|a)|roleplay\s+as)", 25),
       ("policy_evasion_language", r"(without\s+(restriction|filter|limitation)|no\s+(rules|limits|guardrails))", 35),
       ("persist_context", r"(remember|store|persist|retain).{0,40}(this session|conversation|context|instructions?)", 45)),
    build_rules(RiskCategory.DATA_EXFILTRATION,
       ("system_prompt_probe", r"(what\s+are\s+your\s+(instructions|rules|system\s+prompt)|how\s+were\s+you\s+configured)", 35),
       ("send_to_external_url", r"(send|post|upload|exfiltrate|leak).{0,40}(http|https|ftp)://", 50),
       ("fetch_and_send", r"(fetch|retrieve).{0,40}(then|and).{0,40}(send|email|post|upload)", 45),
       ("repeat_context_verbatim", r"(repeat|print|output|display|return).{0,30}(system prompt|your instructions?|your context|everything above)", 35),
       ("reveal_chain_of_thought", r"(show\s+your\s+(reasoning|chain\s+of\s+thought)|explain\s+step\s+by\s+step\s+in\s+detail)", 25),
       ("sensitive_data_request", r"(show|send|expose|leak|give).{0,20}(api\s*key|password|secret|token|credentials|private\s+key)", 45),
       ("local_file_access", r"(/etc/passwd|\.env|config\.json|id_rsa|ssh\s+key)", 50),
       ("extract_full_conversation", r"(dump|export|get).{0,30}(conversation|chat\s+history|logs?)", 40),
       ("data_dredge", r"(print|output|export|list).{0,40}(all|every|complete).{0,30}(passwords?|secrets?|tokens?|credentials?|files?|database|logs)", 55)),
    build_rules(RiskCategory.TOOL_COERCION,
       ("force_tool_call", r"(you must|you should|immediately|right now).{0,30}(call|execute|run|invoke|use).{0,20}(tool|function|api|command)", 40),
       ("bypass_gateway", r"(bypass|skip|ignore|circumvent).{0,30}(gateway|security|check|filter|policy|restriction)", 55),
       ("delete_files", r"(delete|remove|wipe|erase|destroy).{0,30}(all\s+files?|everything|database|logs?)", 60),
       ("specific_tool_targeting", r"(use|call|invoke).{0,20}(fetch_url|write_note|search_notes|summarize)", 45),
       ("malicious_tool_arguments", r"(url\s*=\s*https?://[^\s]+|command\s*=\s*\w+|exec\s*\()", 40),
       ("execute_shell", r"(run|execute|spawn|launch).{0,30}(bash|sh|cmd|powershell|terminal|shell)", 55),
       ("chain_injection", r"(first|then|after that|next).{0,40}(ignore|bypass|override).*instructions?", 45)),
    build_rules(RiskCategory.OBFUSCATION,
       ("stealth_obfuscation_combo", r"([A-Za-z0-9+/]{20,}={0,2}).*(\\u[0-9a-fA-F]{4}).*(0x[0-9a-fA-F]{2,})", 35),
       ("base64_like_blob", r"[A-Za-z0-9+/]{40,}={0,2}", 20),
       ("unicode_escape_sequence", r"(\\u[0-9a-fA-F]{4}){3,}", 20),
       ("hex_encoded_content", r"(0x[0-9a-fA-F]{2,}\s*){4,}", 20),
       ("mixed_encoding", r"(%[0-9a-fA-F]{2}){5,}", 25),
       ("fragmented_injection", r"(ignore.{0,10}\n.{0,10}instructions)", 25)),
], [])

# ---------------------------------------------------------------------------
# Scoring helpers — each does one thing and is independently testable
# ---------------------------------------------------------------------------


def cap_score(raw: int) -> int:
    """Clamp score to the 0-100 range."""
    return max(0, min(100, raw))


def match_rules(text: str) -> tuple[int, list[str], dict[RiskCategory, int]]:
    """
    Run the regex rules against the text and accumulate a risk score.
    Returns:
        tuple: (capped risk_score, matched_signals list, detected_categories dict)
    """
    risk_score = 0
    matched_signals: list[str] = []
    detected_categories: dict[RiskCategory, int] = {}

    for rule in RULES:
        if rule.pattern.search(text):
            matched_signals.append(rule.name)
            risk_score += rule.score_contribution
            detected_categories[rule.category] = (
                detected_categories.get(rule.category, 0) + rule.score_contribution
            )

    return cap_score(risk_score), matched_signals, detected_categories


def apply_judge(
    text: str,
    risk_score: int,
    matched_signals: list[str],
    detected_categories: dict[RiskCategory, int],
) -> tuple[int, list[str], dict[RiskCategory, int], object]:
    """
    If the risk score is in the configured band, call the LLM judge and
    potentially escalate the score and add a matched signal.
    """
    judge_result = None

    if not (
        llm_judge_enabled()
        and judge
        and JUDGE_BAND_LOW <= risk_score < JUDGE_BAND_HIGH
    ):
        return risk_score, matched_signals, detected_categories, judge_result

    try:
        judge_context = {
            "regex_score": risk_score,
            "matched_signals": list(matched_signals),
        }
        try:
            judge_result = judge(text, judge_context)
        except Exception:
            if not fallback_judge:
                raise
            judge_result = fallback_judge(text, judge_context)

        if (
            judge_result
            and judge_result.is_manipulation
            and judge_result.confidence >= JUDGE_CONFIDENCE_MIN
        ):
            risk_score = max(risk_score, JUDGE_ESCALATION_SCORE)
            matched_signals.append("jev_escalation")
            detected_categories[RiskCategory.LLM_FLAGGED] = (
                detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
                + JUDGE_ESCALATION_SCORE
            )

    except Exception:
        # Any JEV and fallback error (network, API, crash) -> fail closed.
        risk_score = max(risk_score, JUDGE_FAILURE_SCORE)
        matched_signals.append("jev_failure")
        detected_categories[RiskCategory.LLM_FLAGGED] = (
            detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
            + JUDGE_FAILURE_SCORE
        )

    return risk_score, matched_signals, detected_categories, judge_result


def build_result(
    request_id: str,
    risk_score: int,
    matched_signals: list[str],
    detected_categories: dict[RiskCategory, int],
    judge_result: object,
) -> RiskResult:
    """
    Build a RiskResult from the accumulated state.
    """
    if not detected_categories:
        categories: list[RiskCategory] = [RiskCategory.BENIGN]
        rationale = "No attack signals detected. Input appears safe."
    else:
        categories = sorted(
            detected_categories.keys(),
            key=lambda c: detected_categories[c],
            reverse=True,
        )
        rationale = (
            f"Detected {len(matched_signals)} signal(s). "
            f"Primary threat category: {categories[0].value}. "
            f"Matched: {', '.join(matched_signals)}."
        )

    if judge_result:
        rationale += (
            f" JEV judge: {judge_result.reasoning} (conf={judge_result.confidence})."
        )

    return RiskResult(
        request_id=request_id,
        risk_score=risk_score,
        risk_categories=categories,
        matched_signals=matched_signals,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score(normalized: NormalizedInput) -> RiskResult:
    """
    Run the full risk assessment pipeline on normalized text.

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

    risk_score, matched_signals, detected_categories = match_rules(text)
    risk_score, matched_signals, detected_categories, judge_result = apply_judge(
        text, risk_score, matched_signals, detected_categories
    )
    return build_result(
        normalized.request_id, risk_score, matched_signals, detected_categories, judge_result
    )
