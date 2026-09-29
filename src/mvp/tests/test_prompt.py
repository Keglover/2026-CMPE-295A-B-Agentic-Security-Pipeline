##Run one arbitrary prompt through the ingest, risk, and policy stages.

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from app.ingest.normalizer import normalize
from app.models import PipelineRequest, SourceType
from app.policy.engine import decide
from app.risk.engine import score


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate an arbitrary prompt through risk and policy."
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help="Prompt text. If omitted, enter it interactively.",
    )
    parser.add_argument(
        "--tool",
        dest="proposed_tool",
        help="Optional proposed tool name to display in the request envelope.",
    )
    parser.add_argument(
        "--tool-args",
        default="{}",
        help="Optional tool arguments as a JSON object.",
    )
    parser.add_argument(
        "--source",
        choices=[source.value for source in SourceType],
        default=SourceType.DIRECT_PROMPT.value,
        help="Input source type. Defaults to direct_prompt.",
    )
    return parser.parse_args()


def read_prompt(prompt_parts: list[str]) -> str:
    if prompt_parts:
        return " ".join(prompt_parts)
    prompt = input("Prompt: ").strip()
    if not prompt:
        raise ValueError("A prompt is required.")
    return prompt


def parse_tool_args(raw_tool_args: str) -> dict[str, object]:
    try:
        tool_args = json.loads(raw_tool_args)
    except json.JSONDecodeError as exc:
        raise ValueError("--tool-args must be valid JSON") from exc
    if not isinstance(tool_args, dict):
        raise ValueError("--tool-args must contain a JSON object")
    return tool_args


def print_result(request: PipelineRequest) -> None:
    normalized = normalize(request)
    risk = score(normalized)
    policy = decide(risk)

    print("\n=== Request ===")
    print(f"source_type: {request.source_type.value}")
    print(f"proposed_tool: {request.proposed_tool or 'none'}")
    print(f"tool_args: {json.dumps(request.tool_args or {}, ensure_ascii=True)}")
    print(f"prompt: {request.content}")

    print("\n=== Normalization ===")
    print(f"normalized: {normalized.normalized_content}")
    print(f"notes: {normalized.normalization_notes or ['none']}")

    print("\n=== Risk ===")
    print(f"score: {risk.risk_score}/100")
    print(f"categories: {[category.value for category in risk.risk_categories]}")
    print(f"signals: {risk.matched_signals or ['none']}")
    print(f"rationale: {risk.rationale}")

    print("\n=== Policy ===")
    print(f"action: {policy.policy_action.value}")
    print(f"requires_approval: {policy.requires_approval}")
    print(f"reason: {policy.policy_reason}")


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    arguments = parse_arguments()
    try:
        prompt = read_prompt(arguments.prompt)
        tool_args = parse_tool_args(arguments.tool_args)
        request = PipelineRequest(
            content=prompt,
            source_type=SourceType(arguments.source),
            proposed_tool=arguments.proposed_tool,
            tool_args=tool_args or None,
        )
        print_result(request)
    except (ValueError, KeyboardInterrupt) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
