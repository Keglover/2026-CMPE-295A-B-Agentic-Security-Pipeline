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

import asyncio
import concurrent.futures
import os
import re
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

# ---------------------------------------------------------------------------
# Scoring helpers — each does one thing and is independently testable
# ---------------------------------------------------------------------------


def _cap_score(raw: int) -> int:
    """Clamp score to the 0-100 range."""
    return max(0, min(100, raw))


def _match_rules(text: str) -> tuple[int, list[str], dict[RiskCategory, int]]:
    """
    Run all regex rules against text and accumulate score and category weights.

    Args:
        text (str): Normalized input to scan.

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

    return _cap_score(risk_score), matched_signals, detected_categories


def _run_judge_safely(coro) -> object:
    """
    Run an async coroutine safely regardless of whether an event loop is
    already running in the calling thread.

    When called from a sync context (normal FastAPI `def` route, CLI) there
    is no running loop, so asyncio.run() creates a fresh one as usual.

    When called from an async context (async route, pytest-asyncio) asyncio.run()
    would raise RuntimeError. Instead we submit the coroutine to a one-shot
    thread that gets its own event loop, avoiding any conflict.

    Args:
        coro: An awaitable coroutine (e.g. judge(text)).

    Returns:
        Whatever the coroutine returns.
    """
    try:
        asyncio.get_running_loop()
        # A loop is already running — use a dedicated thread.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # No running loop — asyncio.run() is safe.
        return asyncio.run(coro)


def _apply_judge(
    text: str,
    risk_score: int,
    matched_signals: list[str],
    detected_categories: dict[RiskCategory, int],
) -> tuple[int, list[str], dict[RiskCategory, int], object]:
    """
    Optionally invoke the LLM judge when the score is in the ambiguous band.

    Mutates copies of matched_signals and detected_categories (passed by ref).
    On judge confirmation, promotes risk_score and records LLM_FLAGGED.
    On any judge failure, fails closed at JUDGE_FAILURE_SCORE.

    Args:
        text (str): Normalized input text.
        risk_score (int): Score after regex matching.
        matched_signals (list[str]): Accumulated signal names (mutated).
        detected_categories (dict): Category weight ledger (mutated).

    Returns:
        tuple: (updated risk_score, matched_signals, detected_categories, judge_result)
    """
    judge_result = None

    if not (_llm_judge_enabled() and judge and JUDGE_BAND_LOW <= risk_score < JUDGE_BAND_HIGH):
        return risk_score, matched_signals, detected_categories, judge_result

    try:
        # Pass judge(text) as the coroutine so monkeypatching `judge` in tests
        # is reflected here without a separate global lookup.
        judge_result = _run_judge_safely(judge(text))

        if (
            judge_result
            and judge_result.is_manipulation
            and judge_result.confidence >= JUDGE_CONFIDENCE_MIN
        ):
            risk_score = max(risk_score, JUDGE_ESCALATION_SCORE)
            matched_signals.append("llm_judge_escalation")
            # Reason: keep category ledger aligned with score so audit tooling
            # can filter by category without also reading matched_signals.
            detected_categories[RiskCategory.LLM_FLAGGED] = (
                detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
                + JUDGE_ESCALATION_SCORE
            )

    except Exception:
        # Any judge error (network, API, crash) → fail closed. The "Event loop
        # is closed" string filter from the original code is no longer needed
        # because _run_judge_safely handles the event-loop conflict explicitly.
        risk_score = max(risk_score, JUDGE_FAILURE_SCORE)
        matched_signals.append("llm_judge_failure")
        detected_categories[RiskCategory.LLM_FLAGGED] = (
            detected_categories.get(RiskCategory.LLM_FLAGGED, 0)
            + JUDGE_FAILURE_SCORE
        )

    return risk_score, matched_signals, detected_categories, judge_result


def _build_result(
    request_id: str,
    risk_score: int,
    matched_signals: list[str],
    detected_categories: dict[RiskCategory, int],
    judge_result: object,
) -> RiskResult:
    """
    Assemble the final RiskResult from scored state.

    Args:
        request_id (str): Forwarded from the original request.
        risk_score (int): Final capped risk score.
        matched_signals (list[str]): All fired signal names.
        detected_categories (dict): Category weight ledger.
        judge_result: JudgeResult or None.

    Returns:
        RiskResult: Structured risk assessment.
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
            f" LLM judge: {judge_result.reasoning} (conf={judge_result.confidence})."
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

    Stages:
      1. Early-exit for empty input.
      2. _match_rules   — regex pass over all 26 rules.
      3. _apply_judge   — optional LLM second opinion in the ambiguous band.
      4. _build_result  — assemble categories, rationale, and RiskResult.

    Score is additive and capped at 100. The highest-weight category becomes
    the primary label. When the LLM judge runs it may add LLM_FLAGGED alongside
    regex-derived categories; use matched_signals to distinguish escalation
    (llm_judge_escalation) from a fail-closed infrastructure error
    (llm_judge_failure).

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

    risk_score, matched_signals, detected_categories = _match_rules(text)
    risk_score, matched_signals, detected_categories, judge_result = _apply_judge(
        text, risk_score, matched_signals, detected_categories
    )
    return _build_result(
        normalized.request_id, risk_score, matched_signals, detected_categories, judge_result
    )
