from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

def _key(value: Any) -> str:
    return "::".join(value) if isinstance(value, tuple) else str(value)


def adapt_results(
    results: dict[str, Any],
    *,
    suite: str,
    model: str,
    defense: str,
    attack: str,
) -> dict[str, Any]:
    """Convert AgentDojo's tuple-keyed result object into JSON-safe data."""

    utility = results.get("utility_results", {})
    security = results.get("security_results", {})
    utility_values = [bool(value) for value in utility.values()]
    security_values = [bool(value) for value in security.values()]

    return {
        "schema_version": "agentdojo-prototype-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "suite": suite,
        "model": model,
        "defense": defense,
        "attack": attack,
        "metrics": {
            "utility_rate": sum(utility_values) / len(utility_values) if utility_values else None,
            "security_rate": sum(security_values) / len(security_values) if security_values else None,
            "utility_cases": len(utility_values),
            "security_cases": len(security_values),
            "injection_task_utility_rate": (
                sum(bool(value) for value in results.get("injection_tasks_utility_results", {}).values())
                / len(results["injection_tasks_utility_results"])
                if results.get("injection_tasks_utility_results")
                else None
            ),
        },
        "utility_results": {_key(key): bool(value) for key, value in utility.items()},
        "security_results": {_key(key): bool(value) for key, value in security.items()},
        "injection_tasks_utility_results": {
            str(key): bool(value)
            for key, value in results.get("injection_tasks_utility_results", {}).items()
        },
    }
