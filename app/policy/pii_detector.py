"""
PII Detection and Redaction module for Policy Enforcement Layer.

Project Plan Ref: Tasks 4.6, 4.7 (Phase 4 — Advanced Policy Rules)

Detects Personally Identifiable Information (PII) in content and provides
redaction capabilities for the SANITIZE policy action.

Reference: Microsoft Presidio (open-source PII detection) for pattern
inspiration. Search "Microsoft Presidio PII detection" for documentation.

TODO List:
    - [ ] Task 4.6  — Implement PII detection rules (email, phone, SSN, credit card)
    - [ ] Task 4.7  — Implement content redaction logic (replace PII with [REDACTED])
    - [ ] Task 7.9  — Verify PII redaction completeness (no partial leaks)
    - [ ] Add UK-specific patterns (NHS number, National Insurance number)
    - [ ] Add configurable redaction strategy (redact vs. tokenize vs. mask)
    - [ ] Integrate into policy engine SANITIZE action path
    - [ ] Write unit tests in tests/test_pii_detector.py
    - [ ] Benchmark false positive rate on benign business text
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class PIIType(str, Enum):
    """Categories of PII that can be detected."""

    EMAIL = "email"
    PHONE_US = "phone_us"
    PHONE_UK = "phone_uk"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"


@dataclass
class PIIMatch:
    """
    A detected PII instance in content.

    Args:
        pii_type: The category of PII detected.
        start: Start index in the original text.
        end: End index in the original text.
        matched_text: The actual text that matched (for length calculation only).
    """

    pii_type: PIIType
    start: int
    end: int
    matched_text: str


# ---------------------------------------------------------------------------
# Detection Patterns
# ---------------------------------------------------------------------------
# Each pattern is a compiled regex paired with its PII type.
# Patterns are intentionally conservative to minimize false positives on
# benign business text.
#
# TODO: [ ] Task 4.6 — Validate and tune these patterns against test corpus

_PII_PATTERNS: list[tuple[PIIType, re.Pattern[str]]] = [
    # Email addresses
    (
        PIIType.EMAIL,
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
    ),
    # US phone numbers (various formats)
    (
        PIIType.PHONE_US,
        re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    # UK phone numbers
    (
        PIIType.PHONE_UK,
        re.compile(
            r"\b(?:\+44\s?|0)(?:\d\s?){9,10}\b"
        ),
    ),
    # US Social Security Numbers (XXX-XX-XXXX)
    (
        PIIType.SSN,
        re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b"
        ),
    ),
    # Credit card numbers (basic Luhn-eligible patterns)
    (
        PIIType.CREDIT_CARD,
        re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        ),
    ),
    # IPv4 addresses
    (
        PIIType.IP_ADDRESS,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
]

# Redaction placeholder
_REDACTION_MARKER = "[REDACTED]"


def detect(text: str) -> list[PIIMatch]:
    """
    Scan text for PII patterns and return all matches.

    Args:
        text: The content to scan.

    Returns:
        list[PIIMatch]: All PII instances found, sorted by position.
    """
    matches: list[PIIMatch] = []
    for pii_type, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            matches.append(
                PIIMatch(
                    pii_type=pii_type,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(),
                )
            )
    matches.sort(key=lambda m: m.start)
    return matches


def redact(text: str, matches: list[PIIMatch] | None = None) -> tuple[str, list[PIIMatch]]:
    """
    Replace all detected PII in text with redaction markers.

    If matches is not provided, detection is run first.

    Args:
        text: The content to redact.
        matches: Pre-computed PII matches (optional).

    Returns:
        tuple: (redacted_text, list of PIIMatch that were redacted)
    """
    if matches is None:
        matches = detect(text)

    if not matches:
        return text, []

    # Process matches in reverse order to preserve indices
    redacted = text
    for match in sorted(matches, key=lambda m: m.start, reverse=True):
        redacted = redacted[: match.start] + _REDACTION_MARKER + redacted[match.end :]

    return redacted, matches


def contains_pii(text: str) -> bool:
    """Quick check: does the text contain any detectable PII?"""
    return len(detect(text)) > 0
