"""Regression for the backtracking stall discovered by CLI evaluation tests."""

import os
import re
import subprocess
import sys

import pytest

from app.risk.engine import RULES


@pytest.mark.parametrize("text", [
    "a" * 20 + r"\u1234" + "0x41", "a" * 19 + r"\u1234" + "0x41",
    "0x41" + r"\u1234" + "a" * 20, "a" * 20 + "0x41" + r"\u1234",
    "a" * 20 + "== middle " + r"\UABCD" + " more 0XAB",
    "a" * 20 + r"\u1234" + "b" * 20 + r"\u5678" + "0x41", "normal text",
])
def test_ordered_detection_matches_previous_rule(text):
    previous = re.compile(r"([A-Za-z0-9+/]{20,}={0,2}).*(\\u[0-9a-fA-F]{4}).*(0x[0-9a-fA-F]{2,})",
                          re.I | re.S)
    current = next(rule.pattern for rule in RULES if rule.name == "stealth_obfuscation_combo")
    assert bool(current.search(text)) == bool(previous.search(text))


def test_large_valid_input_finishes_in_bounded_process():
    # A process timeout catches regressions without leaving pytest stuck in re.search.
    command = "from app.risk.engine import _match_rules; result = _match_rules('x' * 50000); assert result[0] == 20"
    completed = subprocess.run([sys.executable, "-c", command], capture_output=True,
                               text=True, timeout=5, env=os.environ | {"LLM_JUDGE_ENABLED": "false"})
    assert completed.returncode == 0, completed.stderr
