import logging
import json
import argparse

from .config import BenchmarkConfig
from httpx import main
from pathlib import Path
from mvp.agent.config import PIPELINE_URL

try:
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.attacks import baseline_attacks as _baseline_attacks  # noqa: F401
except ImportError as exc:
    raise RuntimeError(
        "AgentDojo is not installed. Run: pip install -r evaluation/agentdojo/requirements-eval.txt \
        If you have already installed it, ensure that it is available in your PYTHONPATH."
    ) from exc

from .adapters.agent_pipeline import build_pipeline
from .adapters.results_adapter import adapt_results

_log = logging.getLogger("AgentDojo Benchmarker") 
REPORTS_DIR = Path(__file__).resolve().parent / "reports"

def _parse_args() -> argparse.Namespace:
    defaults = BenchmarkConfig.from_environment()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default=defaults.suite, help="AgentDojo suite, e.g. workspace or banking")
    parser.add_argument("--tasks", nargs="*", default=[], help="User-task IDs; omit to run all suite tasks")
    parser.add_argument("--injection-tasks", nargs="*", default=[], help="Injection-task IDs; omit for all")
    parser.add_argument("--model", default=defaults.model)
    parser.add_argument("--model-id", default=defaults.model_id)
    parser.add_argument("--ollama-base-url", default=defaults.ollama_base_url)
    parser.add_argument("--endpoint", default=defaults.pipeline_url, help="MVP /pipeline URL")
    parser.add_argument("--attack", default=defaults.attack, help="Registered AgentDojo attack name")
    parser.add_argument("--benchmark-version", default="v1.2.2", help="AgentDojo suite version when supported")
    parser.add_argument("--no-defense", action="store_true", help="Run the same agent without MVP screening")
    parser.add_argument("--logdir", type=Path, default=defaults.logdir)
    parser.add_argument("--report-dir", type=Path, default=defaults.report_dir)
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", type=bool, default=False, action="store_true", help="Enable verbose logging")
    return parser.parse_args()

def main() -> None:
    logging.basicConfig(level=logging.INFO)
    _log.info("Starting benchmark...")

    args = _parse_args()

    try:
        suite = get_suite(args.benchmark_version, args.suite)
    except:
        _log.error("Failed to load suite '%s' with version '%s' - Using just the suite", args.suite, args.benchmark_version)
        suite = get_suite(args.suite)

    _log.info("Loaded suite '%s'", args.suite)
    pipeline = build_pipeline(
        model=args.model,
        model_id=args.model_id,
        ollama_base_url=args.ollama_base_url,
        defense_endpoint=args.endpoint,
        use_defense=not args.no_defense,
    )

    _log.info("Built pipeline '%s'", pipeline.name)
    attack = load_attack(args.attack, suite, pipeline)

    args.logdir.mkdir(parents=True, exist_ok=True)
    results = benchmark_suite_with_injections(
        agent_pipeline=pipeline,
        suite=suite,
        attack=attack,
        logdir=args.logdir,
        force_rerun=args.force_rerun,
        injection_tasks=args.injection_tasks,
        verbose=args.verbose,
    )

    _log.info("Benchmark run on pipeline '%s'", pipeline.name)
    report = adapt_results(
        results,
        suite=args.suite,
        model=args.model_id or args.model,
        defense="none" if args.no_defense else "mvp_pipeline",
        attack=args.attack,
    )

    _log.info("Adapted results for report")
    args.report_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_dir /  f"agentdojo_{args.suite}_{report['timestamp'].replace(':', '').replace('+00:00', 'Z')}.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _log.info("Wrote report to '%s'", report_path)

    return report_path

if __name__ == "__main__":
    main()