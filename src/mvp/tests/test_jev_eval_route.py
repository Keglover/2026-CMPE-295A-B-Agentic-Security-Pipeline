"""Unit tests for the Jev playground router (no API calls)."""

from evaluation.jev_playground.route import route

THRESHOLDS = {
    "action_threshold": 0.7,
    "review_threshold": 0.35,
    "severity_block": 2.0,
}


def test_low_nouls_pass() -> None:
    """Expected use: a clean request stays pass."""
    result = route({"jailbreak": 0.05, "exfil": 0.02}, 0.1, THRESHOLDS)
    assert result["decision"] == "pass"
    assert result["trigger"] is None


def test_mid_band_is_review() -> None:
    """Edge: a medium noul asks a human instead of blocking."""
    result = route({"jailbreak": 0.42}, 0.4, THRESHOLDS)
    assert result["decision"] == "review"
    assert result["trigger"] == "jailbreak"


def test_high_noul_blocks() -> None:
    """Failure path: a high noul is a hard block."""
    result = route({"exfil": 0.91}, 1.2, THRESHOLDS)
    assert result["decision"] == "block"
    assert result["trigger"] == "exfil"


def test_severity_promotes_review_to_block() -> None:
    """Edge: mid noul + high severity becomes block."""
    result = route({"jailbreak": 0.40}, 2.4, THRESHOLDS)
    assert result["decision"] == "block"


def test_empty_nouls_pass() -> None:
    """Failure path: missing answers do not invent a block."""
    result = route({}, None, THRESHOLDS)
    assert result["decision"] == "pass"
