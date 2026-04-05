"""
Ingest / Normalize module.

Responsibility: Accept raw text, strip known obfuscation artifacts, and
return a clean canonical form that downstream stages can reason about safely.

Why this matters: Attackers embed prompt injections in zero-width chars,
Unicode lookalikes, HTML entities, and excess whitespace to evade keyword
detection. Normalizing first makes all subsequent rules more reliable.
"""

from __future__ import annotations

import html
import re
import unicodedata

from app.models import NormalizedInput, PipelineRequest


# ---------------------------------------------------------------------------
# Zero-width / invisible Unicode code points that are injection-hiding tricks
# ---------------------------------------------------------------------------
_ZERO_WIDTH_PATTERN = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u00ad\u2060\ufeff\u180e]"
)

# Repeated whitespace collapser
_MULTI_WHITESPACE = re.compile(r"[ \t]+")
_MULTI_NEWLINE = re.compile(r"\n{3,}")


def _strip_zero_width(text: str) -> tuple[str, bool]:
    """Remove zero-width / invisible characters used to hide injections."""
    cleaned = _ZERO_WIDTH_PATTERN.sub("", text)
    return cleaned, cleaned != text


def _decode_html_entities(text: str) -> tuple[str, bool]:
    """
    Unescape HTML entities (e.g. &lt;script&gt; → <script>).

    Attackers encode injection payloads as HTML entities to fool regex rules.
    """
    decoded = html.unescape(text)
    return decoded, decoded != text


def _normalize_unicode(text: str) -> tuple[str, bool]:
    """
    Apply NFKC Unicode normalization.

    NFKC collapses compatibility equivalents (e.g. ｆｕｌｌ-ｗｉｄｔｈ → full-width)
    which are used to make injection keywords look different to naive pattern
    matchers while appearing similar to humans.
    """
    normalized = unicodedata.normalize("NFKC", text)
    return normalized, normalized != text


def _collapse_whitespace(text: str) -> tuple[str, bool]:
    """Collapse repeated spaces/tabs and excessive blank lines."""
    step1 = _MULTI_WHITESPACE.sub(" ", text)
    step2 = _MULTI_NEWLINE.sub("\n\n", step1)
    return step2.strip(), step2.strip() != text.strip()


def normalize(request: PipelineRequest) -> NormalizedInput:
    """
    Run the full normalization pipeline on a request's content.

    Steps applied (in order):
      1. HTML entity decoding
      2. Zero-width character removal
      3. NFKC Unicode normalization
      4. Whitespace collapsing

    Args:
        request (PipelineRequest): The incoming pipeline request.

    Returns:
        NormalizedInput: Cleaned text plus a list of applied steps.
    """
    notes: list[str] = []
    text = request.content

    text, changed = _decode_html_entities(text)
    if changed:
        notes.append("html_entities_decoded")

    text, changed = _strip_zero_width(text)
    if changed:
        notes.append("zero_width_chars_removed")

    text, changed = _normalize_unicode(text)
    if changed:
        notes.append("unicode_nfkc_normalized")

    text, changed = _collapse_whitespace(text)
    if changed:
        notes.append("whitespace_collapsed")

    return NormalizedInput(
        request_id=request.request_id,
        original_content=request.content,
        normalized_content=text,
        normalization_notes=notes,
    )
