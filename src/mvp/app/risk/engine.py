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

import re
import os
import asyncio
from dataclasses import dataclass

from app.models import NormalizedInput, RiskCategory, RiskResult

try:
    from app.risk.llm_judge import judge
except ModuleNotFoundError:
    # Reason: graceful degradation when LLM dependencies (openai, httpx) are
    # not installed. Any other import failure (typo, syntax error, etc.) is
    # a real bug and should crash loudly at startup.
    judge = None


def _llm_judge_enabled() -> bool:
    """Read the LLM judge toggle at call time so CLI runs can flip it safely."""
    return os.getenv("LLM_JUDGE_ENABLED", "false").lower() == "true"


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

# ---------------------------------------------------------------------------
# LLM judge policy constants
# These define when we consult the LLM judge and how much we trust its verdict.
# Changes here alter security behaviour — review carefully and keep in sync
# with the thresholds in app/policy/engine.py.
# ---------------------------------------------------------------------------

# Score band in which rule-based matching is ambiguous enough to warrant a
# second opinion from the LLM judge. Below LOW, regex is confident the input
# is benign — skip the (paid) LLM call. At/above HIGH, regex is already
# confident the input is hostile — also skip the call.
JUDGE_BAND_LOW: int = 0
JUDGE_BAND_HIGH: int = 60

# Minimum confidence the judge must report before we trust its verdict
# enough to escalate. Below this, we treat the judge as uncertain and
# leave the rule-based score untouched.
JUDGE_CONFIDENCE_MIN: float = 0.7

# Score we promote the request to when the judge positively confirms
# manipulation. Chosen to land in the QUARANTINE band (60-79) in
# policy/engine.py — denied execution, flagged for review.
JUDGE_ESCALATION_SCORE: int = 70

# Fail-closed score when the judge call itself errors out.
# Chosen to cross the BLOCK_THRESHOLD (80) in policy/engine.py so a
# broken safety net hard-blocks the request rather than quietly allowing
# it. Reason: "we couldn't check" is worse than "we checked and it said yes."
JUDGE_FAILURE_SCORE: int = 80


RULES: list[Rule] = [
    # ---------------- INSTRUCTION_OVERRIDE ----------------
    Rule("ignore_previous_instructions",
         re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 40),

    Rule("forget_instructions",
         re.compile(r"forget\s+(everything|all|prior|previous)", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 35),

    Rule("new_system_prompt",
         re.compile(r"(your\s+new\s+instructions?|new\s+system\s+prompt|you\s+are\s+now\s+a)", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 40),

    Rule("jailbreak_roleplay",
         re.compile(r"(pretend\s+you\s+are|act\s+as\s+(if\s+you\s+(are|were)|a)|roleplay\s+as)", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 25),

    Rule("policy_evasion_language",
         re.compile(r"(without\s+(restriction|filter|limitation)|no\s+(rules|limits|guardrails))", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 35),

    Rule("persist_context",
         re.compile(r"(remember|store|persist|retain).{0,40}(this session|conversation|context|instructions?)", _FLAGS),
         RiskCategory.INSTRUCTION_OVERRIDE, 45),

    # ---------------- DATA_EXFILTRATION ----------------
    Rule("system_prompt_probe",
         re.compile(r"(what\s+are\s+your\s+(instructions|rules|system\s+prompt)|how\s+were\s+you\s+configured)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 35),

    Rule("send_to_external_url",
         re.compile(r"(send|post|upload|exfiltrate|leak).{0,40}(http|https|ftp)://", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 50),

    Rule("fetch_and_send",
         re.compile(r"(fetch|retrieve).{0,40}(then|and).{0,40}(send|email|post|upload)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 45),

    Rule("repeat_context_verbatim",
         re.compile(r"(repeat|print|output|display|return).{0,30}(system prompt|your instructions?|your context|everything above)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 35),

    Rule("reveal_chain_of_thought",
         re.compile(r"(show\s+your\s+(reasoning|chain\s+of\s+thought)|explain\s+step\s+by\s+step\s+in\s+detail)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 25),

    Rule("sensitive_data_request",
         re.compile(r"(show|send|expose|leak|give).{0,20}(api\s*key|password|secret|token|credentials|private\s+key)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 45),

    Rule("local_file_access",
         re.compile(r"(/etc/passwd|\.env|config\.json|id_rsa|ssh\s+key)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 50),

    Rule("extract_full_conversation",
         re.compile(r"(dump|export|get).{0,30}(conversation|chat\s+history|logs?)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 40),

    Rule("data_dredge",
         re.compile(r"(print|output|export|list).{0,40}(all|every|complete).{0,30}(passwords?|secrets?|tokens?|credentials?|files?|database|logs)", _FLAGS),
         RiskCategory.DATA_EXFILTRATION, 55),

    # ---------------- TOOL_COERCION ----------------
    Rule("force_tool_call",
         re.compile(r"(you must|you should|immediately|right now).{0,30}(call|execute|run|invoke|use).{0,20}(tool|function|api|command)", _FLAGS),
         RiskCategory.TOOL_COERCION, 40),

    Rule("bypass_gateway",
         re.compile(r"(bypass|skip|ignore|circumvent).{0,30}(gateway|security|check|filter|policy|restriction)", _FLAGS),
         RiskCategory.TOOL_COERCION, 55),

    Rule("delete_files",
         re.compile(r"(delete|remove|wipe|erase|destroy).{0,30}(all\s+files?|everything|database|logs?)", _FLAGS),
         RiskCategory.TOOL_COERCION, 60),

    Rule("specific_tool_targeting",
         re.compile(r"(use|call|invoke).{0,20}(fetch_url|write_note|search_notes|summarize)", _FLAGS),
         RiskCategory.TOOL_COERCION, 45),

    Rule("malicious_tool_arguments",
         re.compile(r"(url\s*=\s*https?://[^\s]+|command\s*=\s*\w+|exec\s*\()", _FLAGS),
         RiskCategory.TOOL_COERCION, 40),

    Rule("execute_shell",
         re.compile(r"(run|execute|spawn|launch).{0,30}(bash|sh|cmd|powershell|terminal|shell)", _FLAGS),
         RiskCategory.TOOL_COERCION, 55),

    Rule("chain_injection",
         re.compile(r"(first|then|after that|next).{0,40}(ignore|bypass|override).*instructions?", _FLAGS),
         RiskCategory.TOOL_COERCION, 45),

    # ---------------- OBFUSCATION ----------------
    Rule("stealth_obfuscation_combo",
         re.compile(r"([A-Za-z0-9+/]{20,}={0,2}).*(\\u[0-9a-fA-F]{4}).*(0x[0-9a-fA-F]{2,})", _FLAGS),
         RiskCategory.OBFUSCATION, 35),

    Rule("base64_like_blob",
         re.compile(r"[A-Za-z0-9+/]{40,}={0,2}", _FLAGS),
         RiskCategory.OBFUSCATION, 20),

    Rule("unicode_escape_sequence",
         re.compile(r"(\\u[0-9a-fA-F]{4}){3,}", _FLAGS),
         RiskCategory.OBFUSCATION, 20),

    Rule("hex_encoded_content",
         re.compile(r"(0x[0-9a-fA-F]{2,}\s*){4,}", _FLAGS),
         RiskCategory.OBFUSCATION, 20),

    Rule("mixed_encoding",
         re.compile(r"(%[0-9a-fA-F]{2}){5,}", _FLAGS),
         RiskCategory.OBFUSCATION, 25),

    Rule("fragmented_injection",
         re.compile(r"(ignore.{0,10}\n.{0,10}instructions)", _FLAGS),
         RiskCategory.OBFUSCATION, 25),
]

# Scoring

def _cap_score(raw: int) -> int:
    """Clamp score to the 0-100 range."""
    return max(0, min(100, raw))


def score(normalized: NormalizedInput) -> RiskResult:
    """
    Run all rules against the normalized content and produce a risk result.

    Rules are additive: multiple matches accumulate. Score is capped at 100.
    The highest-contribution category becomes the primary category label.
    When the LLM judge runs in the ambiguous band, it may add LLM_FLAGGED
    alongside regex-derived categories; see matched_signals for details.

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

    risk_score = 0
    matched_signals: list[str] = []
    detected_categories: dict[RiskCategory, int] = {}

    # ---------------- RULE MATCHING ----------------
    for rule in RULES:
        if rule.pattern.search(text):
            matched_signals.append(rule.name)
            risk_score += rule.score_contribution
            detected_categories[rule.category] = (
                detected_categories.get(rule.category, 0) + rule.score_contribution
            )

    risk_score = _cap_score(risk_score)

    # ---------------- LLM JUDGE (AMBIGUOUS BAND) ----------------
    judge_result = None

    if _llm_judge_enabled() and judge and JUDGE_BAND_LOW <= risk_score < JUDGE_BAND_HIGH:
        try:
            judge_result = asyncio.run(judge(text))

            if (
                judge_result
                and judge_result.is_manipulation
                and judge_result.confidence >= JUDGE_CONFIDENCE_MIN
            ):
                risk_score = max(risk_score, JUDGE_ESCALATION_SCORE)
                matched_signals.append("llm_judge_escalation")
                # Reason: keep category ledger aligned with score so we never
                # mislabel LLM-only signals as OBFUSCATION; distinguish via signal.
                detected_categories[RiskCategory.LLM_FLAGGED] = (
                    detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
                    + JUDGE_ESCALATION_SCORE
                )

        except Exception as e:
            if "Event loop is closed" not in str(e):
                risk_score = max(risk_score, JUDGE_FAILURE_SCORE)
                matched_signals.append("llm_judge_failure")
                detected_categories[RiskCategory.LLM_FLAGGED] = (
                    detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
                    + JUDGE_FAILURE_SCORE
                )

    # ---------------- CATEGORY + RATIONALE ----------------
    if not detected_categories:
        categories = [RiskCategory.BENIGN]
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

    # Add judge reasoning
    if judge_result:
        rationale += f" LLM judge: {judge_result.reasoning} (conf={judge_result.confidence})."

    return RiskResult(
        request_id=normalized.request_id,
        risk_score=risk_score,
        risk_categories=categories,
        matched_signals=matched_signals,
        rationale=rationale,
    )
