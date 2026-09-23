"""
Run every Jev playground case and write results + dashboard.

Usage (from src/mvp):
    python -m evaluation.jev_playground.run_evals
    python -m evaluation.jev_playground.run_evals --fresh
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from evaluation.jev_playground.render_dashboard import render_dashboard
from evaluation.jev_playground.route import route

HERE = Path(__file__).resolve().parent
API_URL = "https://api.typesafe.ai/v1/systemone"


def _load_json(path: Path) -> Any:
    """Load a JSON file from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def _cache_key(state: Any, questions: dict[str, Any], model: str) -> str:
    """Stable hash so the same case is not billed twice."""
    blob = json.dumps(
        {"state": state, "questions": questions, "model": model},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _extract(answers: dict[str, Any]) -> tuple[dict[str, float], str | None, float | None]:
    """
    Split a TypeSafe answers map into nouls, choice label, and score.

    Args:
        answers: response["answers"] from /v1/systemone.

    Returns:
        tuple: (nouls, primary_category, severity).
    """
    nouls: dict[str, float] = {}
    choice: str | None = None
    severity: float | None = None
    for qid, answer in answers.items():
        kind = answer.get("type")
        if kind == "noul":
            nouls[qid] = float(answer["noul"])
        elif kind == "choice":
            choice = str(answer.get("choice"))
        elif kind == "score":
            severity = float(answer["score"])
    return nouls, choice, severity


def ask_jev(
    client: httpx.Client,
    cache: dict[str, Any],
    state: Any,
    questions: dict[str, Any],
    model: str,
) -> tuple[dict[str, Any], bool]:
    """
    Call Jev or return a cached response.

    Args:
        client: Shared HTTP client.
        cache: Mutable cache map.
        state: String or object sent as TypeSafe state.
        questions: Question battery.
        model: Model alias.

    Returns:
        tuple: (API body, used_cache).
    """
    key = _cache_key(state, questions, model)
    if key in cache:
        return cache[key], True

    response = client.post(
        API_URL,
        json={"state": state, "model": model, "questions": questions},
        headers={"Authorization": f"Bearer {os.environ['TYPESAFE_API_KEY']}"},
    )
    response.raise_for_status()
    body = response.json()
    cache[key] = body
    return body, False


def run_suite(
    states_path: Path,
    questions_path: Path,
    thresholds_path: Path,
    results_dir: Path,
    fresh: bool,
) -> dict[str, Any]:
    """
    Evaluate every case and persist JSON + HTML.

    Args:
        states_path: states.json.
        questions_path: questions_*.json.
        thresholds_path: thresholds.json.
        results_dir: Output folder.
        fresh: If True, ignore the on-disk cache.

    Returns:
        dict: Report written to latest.json.
    """
    load_dotenv(HERE.parents[1] / ".env")
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit("TYPESAFE_API_KEY is missing. Put it in src/mvp/.env")

    states_doc = _load_json(states_path)
    questions_doc = _load_json(questions_path)
    thresholds = _load_json(thresholds_path)
    questions = questions_doc["questions"]
    model = questions_doc.get("model", "jev-latest")
    noul_ids = [qid for qid, q in questions.items() if q.get("type") == "noul"]

    results_dir.mkdir(parents=True, exist_ok=True)
    cache_path = results_dir / "cache.json"
    cache: dict[str, Any] = {} if fresh or not cache_path.exists() else _load_json(cache_path)

    cases: list[dict[str, Any]] = []
    cached = 0
    live = 0

    with httpx.Client(timeout=60.0) as client:
        for case in states_doc["cases"]:
            try:
                body, used_cache = ask_jev(
                    client, cache, case["state"], questions, model
                )
                cached += int(used_cache)
                live += int(not used_cache)
                nouls, category, severity = _extract(body.get("answers", {}))
                routed = route(nouls, severity, thresholds)
                decision = routed["decision"]
                expect = case.get("expect_decision")
                cases.append(
                    {
                        "id": case["id"],
                        "expect": case.get("expect"),
                        "expect_decision": expect,
                        "decision": decision,
                        "match": (decision == expect) if expect else None,
                        "trigger": routed["trigger"],
                        "max_noul": routed["max_noul"],
                        "nouls": nouls,
                        "primary_category": category,
                        "severity": severity,
                        "usage": body.get("usage"),
                    }
                )
            except Exception as exc:
                cases.append(
                    {
                        "id": case["id"],
                        "expect": case.get("expect"),
                        "expect_decision": case.get("expect_decision"),
                        "decision": "error",
                        "match": False,
                        "trigger": None,
                        "max_noul": 0.0,
                        "nouls": {},
                        "primary_category": None,
                        "severity": None,
                        "error": str(exc),
                    }
                )

    report = {
        "model": model,
        "questions_file": questions_path.name,
        "thresholds": thresholds,
        "noul_ids": noul_ids,
        "cached": cached,
        "live": live,
        "cases": cases,
    }
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    (results_dir / "latest.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    (results_dir / "dashboard.html").write_text(
        render_dashboard(report), encoding="utf-8"
    )
    return report


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run Jev playground evals.")
    parser.add_argument(
        "--questions",
        default=str(HERE / "questions_security.json"),
        help="Question battery JSON.",
    )
    parser.add_argument("--fresh", action="store_true", help="Ignore cache.")
    args = parser.parse_args()

    report = run_suite(
        states_path=HERE / "states.json",
        questions_path=Path(args.questions),
        thresholds_path=HERE / "thresholds.json",
        results_dir=HERE / "results",
        fresh=args.fresh,
    )
    matches = sum(1 for row in report["cases"] if row.get("match") is True)
    print(f"Wrote {HERE / 'results' / 'dashboard.html'}")
    print(f"Match {matches}/{len(report['cases'])}  cached={report['cached']} live={report['live']}")
    for row in report["cases"]:
        print(f"  {row['id']:24} expect={row.get('expect_decision')} got={row['decision']}")


if __name__ == "__main__":
    main()
