"""
Tests for the PII Detector module.

Project Plan Ref: Tasks 4.6, 4.7, 7.9

TODO List:
    - [ ] Task 4.6  — Validate PII detection patterns against test corpus
    - [ ] Task 7.9  — Verify PII redaction completeness (no partial leaks)
    - [ ] Add UK-specific PII pattern tests
    - [ ] Add false positive tests on benign business text
    - [ ] Add edge case tests (partial matches, overlapping patterns)

Covers:
    - Email address detection and redaction
    - US phone number detection and redaction
    - SSN detection and redaction
    - Credit card number detection and redaction
    - IP address detection and redaction
    - Multiple PII types in single text
    - Clean text with no PII
    - Redaction preserves non-PII text
"""

import pytest

from app.policy.pii_detector import PIIType, detect, redact, contains_pii


# ---------------------------------------------------------------------------
# Email detection
# ---------------------------------------------------------------------------


def test_detect_email() -> None:
    """Should detect email addresses in text."""
    matches = detect("Contact john.doe@example.com for details.")
    assert len(matches) >= 1
    assert any(m.pii_type == PIIType.EMAIL for m in matches)


def test_redact_email() -> None:
    """Should replace email with [REDACTED]."""
    text = "Send to user@company.org please."
    redacted, matches = redact(text)
    assert "[REDACTED]" in redacted
    assert "user@company.org" not in redacted


# ---------------------------------------------------------------------------
# Phone number detection
# ---------------------------------------------------------------------------


def test_detect_us_phone() -> None:
    """Should detect US phone numbers."""
    matches = detect("Call me at (555) 123-4567 or 555-987-6543.")
    phone_matches = [m for m in matches if m.pii_type == PIIType.PHONE_US]
    assert len(phone_matches) >= 1


# ---------------------------------------------------------------------------
# SSN detection
# ---------------------------------------------------------------------------


def test_detect_ssn() -> None:
    """Should detect Social Security Numbers in XXX-XX-XXXX format."""
    matches = detect("My SSN is 123-45-6789.")
    assert any(m.pii_type == PIIType.SSN for m in matches)


def test_redact_ssn() -> None:
    """Should redact SSN from text."""
    text = "SSN: 987-65-4321 on file."
    redacted, _ = redact(text)
    assert "987-65-4321" not in redacted
    assert "[REDACTED]" in redacted


# ---------------------------------------------------------------------------
# Credit card detection
# ---------------------------------------------------------------------------


def test_detect_credit_card() -> None:
    """Should detect credit card numbers."""
    matches = detect("Card number: 4111-1111-1111-1111")
    assert any(m.pii_type == PIIType.CREDIT_CARD for m in matches)


# ---------------------------------------------------------------------------
# IP address detection
# ---------------------------------------------------------------------------


def test_detect_ip_address() -> None:
    """Should detect IPv4 addresses."""
    matches = detect("Server at 192.168.1.100 responded.")
    assert any(m.pii_type == PIIType.IP_ADDRESS for m in matches)


# ---------------------------------------------------------------------------
# Multiple PII types
# ---------------------------------------------------------------------------


def test_detect_multiple_pii_types() -> None:
    """Should detect multiple PII types in the same text."""
    text = (
        "Contact alice@example.com or call 555-123-4567. "
        "SSN: 111-22-3333. Server: 10.0.0.1"
    )
    matches = detect(text)
    types_found = {m.pii_type for m in matches}
    assert PIIType.EMAIL in types_found
    assert PIIType.SSN in types_found


def test_redact_multiple_pii() -> None:
    """Redacting multiple PII instances should replace all of them."""
    text = "Email: test@test.com, SSN: 111-22-3333"
    redacted, matches = redact(text)
    assert "test@test.com" not in redacted
    assert "111-22-3333" not in redacted
    assert redacted.count("[REDACTED]") >= 2


# ---------------------------------------------------------------------------
# Clean text (no PII)
# ---------------------------------------------------------------------------


def test_clean_text_no_pii() -> None:
    """Text without PII should return no matches."""
    matches = detect("The quarterly report shows 12% growth in revenue.")
    assert len(matches) == 0


def test_contains_pii_false_for_clean() -> None:
    """contains_pii should return False for clean text."""
    assert contains_pii("Board meeting agenda for Friday.") is False


def test_contains_pii_true_for_email() -> None:
    """contains_pii should return True when email is present."""
    assert contains_pii("Reply to admin@corp.com") is True


# ---------------------------------------------------------------------------
# Redaction preserves non-PII text
# ---------------------------------------------------------------------------


def test_redaction_preserves_surrounding_text() -> None:
    """Non-PII text around redacted items should be preserved."""
    text = "Hello user@test.com, your report is ready."
    redacted, _ = redact(text)
    assert redacted.startswith("Hello ")
    assert redacted.endswith(", your report is ready.")
