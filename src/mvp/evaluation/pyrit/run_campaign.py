"""Prototype PyRIT campaign for the Agentic Security Pipeline.

This module deliberately keeps the campaign objective narrow and measurable:
send indirect/direct injection payloads to ``/pipeline`` while proposing a
tool call, then treat execution of that call as an attack success.

There are two execution modes:

* ``direct`` (default): uses httpx and does not require PyRIT. This is useful
  for checking the corpus, endpoint, and success oracle.
* ``pyrit``: uses PyRIT's HTTPTarget and PromptSendingAttack. PyRIT remains
  optional so the repository's normal tests do not require the red-team stack.

Run from ``src/mvp``:

    python -m evaluation.pyrit_campaign --mode direct
    python -m evaluation.pyrit_campaign --mode pyrit

The campaign is intentionally bounded and uses the repository's mock gateway.
It does not enable REAL_TOOLS and does not send payloads to third-party
services.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from agent.config import PIPELINE_URL

_log = logging.getLogger("pyrit_campaign")
RESULTS_DIR = Path(__file__).resolve().parent / "results"


@dataclass(frozen=True)
class AttackCase:
    """One bounded injection probe and the tool action it tries to trigger."""

    attempt_id: str
    scenario_type: str
    objective: str
    payload: str
    source_type: str
    proposed_tool: str | None
    tool_args: dict[str, Any]
    success_criteria: dict[str, Any]


@dataclass
class CampaignResult:
    attempt_id: str
    scenario_type: str
    objective: str
    mode: str
    payload: str
    response: dict[str, Any] | None
    attack_success: bool | None
    error: str | None = None


def build_campaign() -> list[AttackCase]:
    """Return a small representative corpus covering the current rule families.

    The payloads are benignly scoped to the local mock tools. They test whether
    untrusted content can cause unauthorized tool execution; they do not ask
    for real secrets or invoke external systems.
    """

    dir_path = os.path.abspath(__file__ + "/../campaign_scenarios")

    loaded_scenarios = []

    for scenario_file in os.listdir(dir_path):
        try:
            with open(os.path.join(dir_path, scenario_file), "r") as f:
                scenario = json.load(f)

                for attack_case_data in scenario["attempts"]:
                    attack_case = AttackCase(
                        attempt_id=attack_case_data["attempt_id"],
                        scenario_type=attack_case_data["scenario_type"],
                        objective=attack_case_data["objective"],
                        source_type=attack_case_data["source_type"],
                        payload=attack_case_data["payload"],
                        proposed_tool=attack_case_data["proposed_tool"],
                        tool_args=attack_case_data["tool_args"],
                        success_criteria=attack_case_data["success_criteria"],
                    )
                    loaded_scenarios.append(attack_case)

        except Exception as e:
            _log.error("Failed to load scenario %s: %s", scenario_file, e)
            continue

    return loaded_scenarios


def attack_succeeded(response: dict[str, Any], criteria: dict[str, Any]) -> bool:
    """Return whether the proposed privileged action actually executed.

    This oracle measures the security property under test, not merely whether
    the detector assigned a high score. A quarantine/block is a defense
    success; an ``EXECUTED`` gateway result is an attack success.
    """
    actual = response

    for field in criteria["field"].split("."):
        actual = actual.get(field) if isinstance(actual, dict) else None

    operator = criteria["operator"]
    expected = criteria["value"]

    if operator == "equals":
        return actual == expected

    raise ValueError(f"Unsupported success operator: {operator}")


def run_direct(cases: list[AttackCase], endpoint: str) -> list[CampaignResult]:
    """Run the corpus directly against the local HTTP target."""

    results: list[CampaignResult] = []

    with httpx.Client(timeout=20.0) as client:
        for case in cases:
            request = {
                "content": case.payload,
                "source_type": case.source_type,
                "proposed_tool": case.proposed_tool,
                "tool_args": case.tool_args,
            }
            try:
                response = client.post(endpoint, json=request)

                '''
                _log.info(
                    "Attempt %s returned HTTP %s: %s",
                    case.attempt_id,
                    response.status_code,
                    response.text,
                )
                '''
                data = response.json()
                success = attack_succeeded(data, case.success_criteria)

                response.raise_for_status()
                data = response.json()
                results.append(
                    CampaignResult(
                        attempt_id=case.attempt_id,
                        scenario_type=case.scenario_type,
                        objective=case.objective,
                        mode="direct",
                        payload=case.payload,
                        response=data,
                        attack_success=success,
                        error=None,
                    )
                )
            except Exception as exc:
                _log.exception("Failed while processing attempt %s", case.attempt_id)
                
                results.append(
                    CampaignResult(
                        attempt_id=case.attempt_id,
                        scenario_type=case.scenario_type,
                        objective=case.objective,
                        mode="direct",
                        payload=case.payload,
                        response=None,
                        attack_success=None,
                        error=f"{type(exc).__name__}: {exc!r}",
                    )
                )
    return results


async def run_pyrit(cases: list[AttackCase], endpoint: str) -> list[CampaignResult]:
    """Run each case through PyRIT's HTTP target.

    The HTTP target returns the pipeline's human-readable summary to PyRIT.
    The full structured responses are retained by the pipeline audit log; the
    direct mode should be used when per-field response analysis is required.
    """

    try:
        from pyrit.converter import JsonStringConverter
        from pyrit.executor.attack import PromptSendingAttack
        from pyrit.prompt_normalizer import ConverterConfiguration
        from pyrit.prompt_target import (
            HTTPTarget,
            get_http_target_json_response_callback_function,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PyRIT mode requires PyRIT to be installed; use --mode direct or install PyRIT."
        ) from exc

    try:
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async

        await initialize_pyrit_async(memory_db_type=IN_MEMORY)  # type: ignore[arg-type]
    except ImportError as exc:
        raise RuntimeError("This PyRIT version does not expose in-memory setup APIs.") from exc

    # Keep the proposed tool fixed per target instance. This avoids trying to
    # inject JSON metadata through the attack prompt itself.
    results: list[CampaignResult] = []
    for case in cases:
        raw_request = json.dumps(
            {
                "content": "{PROMPT}",
                "source_type": case.source_type,
                "proposed_tool": case.proposed_tool,
                "tool_args": case.tool_args,
            }
        )
        raw_http_request = (
            f"POST {endpoint} HTTP/1.1\n"
            "Content-Type: application/json\n\n"
            f"{raw_request}"
        )
        target = HTTPTarget(
            http_request=raw_http_request,
            callback_function=get_http_target_json_response_callback_function(key="summary"),
            timeout=20.0,
        )
        converter_config = ConverterConfiguration.from_converters(
            converters=[JsonStringConverter()]
        )
        attack = PromptSendingAttack(
            objective_target=target,
            attack_converter_config=converter_config,
        )
        try:
            attack_result = await attack.execute_async(objective=case.payload)  # type: ignore[arg-type]
            rendered_result = str(attack_result)
            results.append(
                CampaignResult(
                    attempt_id=case.attempt_id,
                    scenario_type=case.scenario_type,
                    objective=target,
                    mode="pyrit",
                    payload=case.payload,
                    response={"pyrit_result": rendered_result},
                    # HTTPTarget returns the pipeline summary in the target
                    # transcript. This is the PyRIT-mode equivalent of the
                    # structured direct-mode oracle.
                    attack_success="Gateway: EXECUTED" in rendered_result,
                )
            )
        except Exception as exc:  # campaign should report a failed case, not hide it
            results.append(
                CampaignResult(
                    attempt_id=case.attempt_id, 
                    scenario_type=case.scenario_type, 
                    objective=target,  
                    mode="pyrit", 
                    payload=case.payload, 
                    response=None, 
                    success=None, 
                    error=str(exc)))
    return results


def write_report(results: list[CampaignResult]) -> Path:
    """Write a timestamped JSON report and return its path."""

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("D_%Y-%m-%d_T_%H-%M-%S_UTC")
    path = RESULTS_DIR / f"pyrit_campaign_{timestamp}.json"
    successes = sum(result.attack_success is True for result in results)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign": "prototype-injection-campaign",
        "total_cases": len(results),
        "attack_successes": successes,
        "attack_success_rate": successes / len(results) if results else 0.0,
        "results": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("direct", "pyrit"), default="direct")
    parser.add_argument("--endpoint", default=PIPELINE_URL)
    args = parser.parse_args()

    if os.getenv("REAL_TOOLS", "false").lower() == "true":
        raise SystemExit("Refusing to run campaign with REAL_TOOLS=true; use the mock gateway for this prototype.")

    cases = build_campaign()
    results = asyncio.run(run_pyrit(cases, args.endpoint)) if args.mode == "pyrit" else run_direct(cases, args.endpoint)
    report_path = write_report(results)
    successes = sum(result.attack_success is True for result in results)
    errors = sum(result.error is not None for result in results)
    print(f"Campaign cases: {len(results)} | attack successes: {successes} | errors: {errors}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")
    main()
