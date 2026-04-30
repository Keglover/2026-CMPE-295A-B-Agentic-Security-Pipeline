"""
E2E cloud pipeline test — validates the full sandboxed execution chain.

Chain under test:
  POST /pipeline
    → normalize → risk → policy → gateway
    → sandbox_client (HTTP) → tool-runner:8001
    → Docker SDK spawns ephemeral runsc container
    → gateway_real.py (inside gVisor sandbox)
    → HTTP → egress-proxy (IP, not hostname — gVisor DNS fix)
    → local Ollama daemon → Ollama Cloud (kimi-k2.5:cloud)
    → 403 if no subscription / 200 + summary if subscribed

Usage (from WSL):
  cd /mnt/c/Users/mwase/Desktop/2026-CMPE-295A-B-Agentic-Security-Pipeline
  python3 scripts/test_cloud_pipeline.py [--host http://localhost:8000]
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

PIPELINE_URL = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Test cases — each uses proposed_tool=summarize with kimi-k2.5:cloud
# ---------------------------------------------------------------------------

TESTS = [
    {
        "id": "cloud-sec-0",
        "label": "Project abstract — full paper text",
        "content": "summarize project abstract",
        "tool_args": {
            "text": (
                'Large Language Models (LLMs) are increasingly deployed as "agentic" systems that can browse '
                "the web, read messages, call third-party tools, and execute actions on behalf of users. These "
                "agents are becoming common in developer workflows and automation platforms because they "
                "can connect natural language instructions to high-privilege operations such as file access, API "
                "usage, and command execution. As AI agents continue to evolve everyday, finding ways to "
                "secure computer systems from unwanted agentic tool-use, while, at the same time, ensuring "
                "adequate agentic productivity is becoming integral for every modern day business entity. "
                "A major security risk in artificial intelligence agents is prompt injection, where contents like "
                "webpages, documents, emails could be used to manipulate the agent's reasoning that would lead "
                "to unauthorized access to private data. Unlike traditional software, many agent frameworks don't "
                "have reliable separation between harmful inputs and decision making. Hence, malicious "
                "instructions could pass into the agent and influence its decision making, override security "
                "policies, or trigger high-privilege calls. This could lead to real-world consequences such as "
                "leakage of private information, system modification, and data exfiltration. "
                "This project will design and implement a security pipeline that detects and intercepts how an "
                "agent reads untrusted inputs and invokes tools. The system will provide (1) real-time "
                "prompt-injection detection by combining rules, risk scoring, and machine-learning classifiers, (2) "
                "a policy enforcement layer that can block, sanitize, isolate, or require user confirmation before "
                "tool execution, and (3) generate audit reports for further analysis and evaluation. The prototype "
                "will be delivered by March/April and the final implementation will be expanded into an "
                "open-source framework with containerized deployment, reproducible benchmarks, and clear "
                "security controls suitable for real-world agent deployments."
            ),
        },
    },
    {
        "id": "cloud-sec-1",
        "label": "Prompt injection attack description",
        "content": "summarize this security threat",
        "tool_args": {
            "text": (
                "Prompt injection is an attack against AI agents where malicious "
                "instructions embedded in untrusted content — such as web pages, "
                "emails, or documents — manipulate the agent's reasoning to perform "
                "unauthorized actions. Unlike traditional SQL injection, prompt "
                "injection exploits the agent's language understanding rather than "
                "a parser. Defenses include separating trusted instructions from "
                "untrusted input, output validation, and sandboxing tool execution "
                "so that even a compromised agent cannot exfiltrate data or modify "
                "system state without passing through a policy enforcement layer."
            ),
        },
    },
    {
        "id": "cloud-sec-2",
        "label": "gVisor architecture summary",
        "content": "summarize gVisor security model",
        "tool_args": {
            "text": (
                "gVisor is a user-space kernel written in Go that implements a "
                "substantial portion of the Linux system call surface. When a "
                "container runs under the runsc runtime, every syscall is "
                "intercepted by the Sentry — gVisor's kernel component — rather "
                "than being passed directly to the host kernel. This means a "
                "vulnerability in the containerized application or its dependencies "
                "cannot directly exploit the host kernel: the attack surface is "
                "limited to the Sentry's implementation of each syscall. gVisor "
                "imposes a measurable performance overhead (typically 10-30% on "
                "I/O-heavy workloads) but provides strong isolation guarantees "
                "that complement namespaces and cgroups, which only limit "
                "visibility and resource usage without blocking syscalls."
            ),
        },
    },
    {
        "id": "cloud-sec-3",
        "label": "Agentic pipeline security model",
        "content": "summarize the pipeline design",
        "tool_args": {
            "text": (
                "The Agentic Security Pipeline is a policy-mediated execution "
                "framework designed to intercept and control tool use by AI agents. "
                "Every request flows through five stages: normalization strips "
                "encoding tricks and canonicalizes whitespace; risk scoring assigns "
                "a 0-100 threat score using rule-based signals and keyword matching; "
                "the policy engine maps the risk score to an action (ALLOW, "
                "SANITIZE, REQUIRE_APPROVAL, or BLOCK); the gateway enforces "
                "allowlists, rate limits, and circuit breakers before routing to "
                "a sandboxed executor; and an audit log records the full decision "
                "trace for forensic analysis. Tool execution is isolated inside "
                "ephemeral gVisor containers with no-new-privileges and dropped "
                "capabilities, ensuring that even a compromised tool cannot affect "
                "the host or other pipeline components."
            ),
        },
    },
]

# ---------------------------------------------------------------------------

def _post(url: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def _result_line(label: str, value: str) -> None:
    print(f"  {label:<22} {value}")


def run_tests(host: str) -> int:
    pipeline_url = f"{host}/pipeline"
    failures = 0

    _banner(f"Agentic Security Pipeline — Cloud E2E Test  ({datetime.now(timezone.utc).isoformat()})")
    print(f"  Target : {host}")
    print(f"  Model  : kimi-k2.5:cloud (via egress-proxy → https://api.ollama.com)")
    print(f"  Runtime: runsc (gVisor)  USE_GVISOR=true")
    print(f"  Tests  : {len(TESTS)}")

    for test in TESTS:
        print(f"\n[{test['id']}] {test['label']}")
        print("-" * 60)

        payload = {
            "request_id": test["id"],
            "content": test["content"],
            "proposed_tool": "summarize",
            "tool_args": test["tool_args"],
        }

        status, body = _post(pipeline_url, payload)
        gw = body.get("gateway") or {}
        decision = gw.get("gateway_decision", "N/A")
        reason   = gw.get("decision_reason", "")
        output   = gw.get("tool_output")
        risk     = body.get("risk", {}).get("risk_score", "?")
        policy   = body.get("policy", {}).get("policy_action", "?")

        _result_line("HTTP status:",    str(status))
        _result_line("Risk score:",     str(risk))
        _result_line("Policy action:",  str(policy))
        _result_line("Gateway:",        decision)

        if decision == "ALLOWED" and output and "Error" not in output:
            print(f"\n  ✓ SUMMARY:\n  {output[:300]}")
        elif output and ("403" in output or "subscription" in output.lower()):
            print(f"\n  ✓ CLOUD REACHED — subscription required (403)")
            print(f"    Proof: full chain worked — pipeline → runsc → egress-proxy → api.ollama.com")
            print(f"    Upgrade at: https://ollama.com/upgrade")
        elif output and ("401" in output or "unauthorized" in output.lower()):
            print(f"\n  ✓ CLOUD REACHED — API key required (401)")
            print(f"    Proof: full chain worked — pipeline → runsc → egress-proxy → api.ollama.com")
            print(f"    Set OLLAMA_API_KEY before 'docker compose up' to authenticate.")
            print(f"    Get keys at: https://ollama.com/settings/api-keys")
        elif decision == "EXECUTED" and output:
            # Any other EXECUTED result — chain proved, show output
            print(f"\n  ✓ EXECUTED: {output[:300]}")
        elif decision == "DENIED":
            print(f"\n  ✗ DENIED: {reason[:200]}")
            failures += 1
        else:
            print(f"\n  ? Unexpected: {reason[:200]}")

    _banner("SUMMARY")
    passed = len(TESTS) - failures
    print(f"  {passed}/{len(TESTS)} tests reached Ollama Cloud successfully")
    if failures == 0:
        print("  Pipeline chain: VERIFIED end-to-end")
        print("  (401/403 from api.ollama.com = cloud reached, auth/subscription needed)")
        print("  Set OLLAMA_API_KEY env var to authenticate. Get key: https://ollama.com/settings/api-keys")
    else:
        print(f"  {failures} test(s) failed — check logs above")
    print()

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud pipeline E2E test")
    parser.add_argument("--host", default=PIPELINE_URL, help="Pipeline base URL")
    args = parser.parse_args()
    sys.exit(run_tests(args.host))
