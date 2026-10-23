#!/usr/bin/env python3
"""
CLI entry point for the agent loop.

Modes:
  Interactive:  python run_agent.py
  Single-shot:  python run_agent.py --payload "summarize this text about AI"
  Verbose:      python run_agent.py -v

Requires:
  1. FastAPI pipeline running: uvicorn app.main:app
  2. OPENAI_API_KEY set in environment
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from agent.loop import run_agent_turn


def _print_trace(result: dict) -> None:
    """
    Print a summary of the pipeline traces for the turn.

    Args:
        result: The dict returned by run_agent_turn().
    """
    print(f"\n--- Turn Summary ---")
    print(f"Tool calls made:    {result['tool_calls_made']}")
    print(f"Tool calls blocked: {result['tool_calls_blocked']}")

    for i, trace in enumerate(result["pipeline_traces"], 1):
        risk = trace.get("risk", {})
        policy = trace.get("policy", {})
        gw = trace.get("gateway") or {}
        print(
            f"  [{i}] score={risk.get('risk_score', '?')}"
            f"  action={policy.get('policy_action', '?')}"
            f"  gateway={gw.get('gateway_decision', 'N/A')}"
            f"  signals={risk.get('matched_signals', [])}"
        )
    print()


def _run_interactive(verbose: bool) -> None:
    """
    Run the agent in interactive mode — read-eval-print loop.

    Args:
        verbose: If True, print pipeline trace after each turn.
    """
    print("Agentic Security Pipeline — Interactive Agent")
    print("Type 'quit' or 'exit' to stop.\n")

    conversation = None

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input or user_input.lower() in ("quit", "exit"):
            print("Goodbye.")
            break

        result = run_agent_turn(user_input, conversation=conversation)
        conversation = result["conversation"]

        print(f"\nAssistant: {result['reply']}")

        if verbose or result["tool_calls_blocked"] > 0:
            _print_trace(result)


def _run_single(payload: str, verbose: bool) -> None:
    """
    Run the agent with a single payload and exit.

    Args:
        payload: The user prompt to send.
        verbose: If True, print pipeline trace.
    """
    result = run_agent_turn(payload)

    print(f"Assistant: {result['reply']}")
    _print_trace(result)

    if result["tool_calls_blocked"] > 0:
        sys.exit(1)


def main() -> None:
    """Parse args and run the appropriate mode."""
    parser = argparse.ArgumentParser(
        description="Run the LLM agent with security pipeline integration."
    )
    parser.add_argument(
        "--payload",
        type=str,
        default=None,
        help="Single prompt to send (non-interactive mode).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print pipeline traces after each turn.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    if args.payload:
        _run_single(args.payload, args.verbose)
    else:
        _run_interactive(args.verbose)


if __name__ == "__main__":
    main()
