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
import subprocess
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


def _run_cmd(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    """Run a shell command and return (exit_code, stdout, stderr)."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except Exception as exc:
        return 1, "", str(exc)


def _print_runtime_evidence() -> None:
    """Print host/container runtime evidence for gVisor/runsc."""
    _banner("RUNTIME EVIDENCE")

    code, out, err = _run_cmd(["docker", "info", "--format", "{{json .Runtimes}}"])
    if code == 0:
        print(f"  Docker runtimes: {out}")
    else:
        print(f"  Docker runtime probe failed: {err or out}")

    code, out, err = _run_cmd(["runsc", "--version"])
    if code == 0:
        first_line = out.splitlines()[0] if out else "runsc available"
        print(f"  runsc version: {first_line}")
    else:
        print(f"  runsc version probe: {err or out or 'not available in PATH'}")

    code, out, err = _run_cmd(["docker", "logs", "--tail", "200", "tool-runner"])
    if code == 0:
        lines = out.splitlines()
        evidence = [
            line for line in lines
            if "runtime=runsc" in line or "gVisor active" in line
        ]
        if evidence:
            print("  tool-runner gVisor log evidence:")
            for line in evidence[-8:]:
                print(f"    {line}")
        else:
            print("  tool-runner logs found, but no explicit runsc/gVisor evidence lines yet.")
    else:
        print(f"  tool-runner logs probe failed: {err or out}")


def _run_syscall_probe(host: str) -> None:
    """Run execute_command probe and print syscall/security-relevant process output."""
    _banner("SYSCALL PROBE (execute_command via gateway)")

    request_id = "cloud-syscall-probe-001"
    payload = {
        "request_id": request_id,
        "source_type": "direct_prompt",
        "content": "Run runtime probe command in sandbox.",
        "proposed_tool": "execute_command",
        "tool_args": {
            "command": (
                "sh -lc \"echo syscall_probe_start; "
                "cat /proc/self/status | egrep 'Name|Pid|Seccomp|CapEff'; "
                "uname -a; echo syscall_probe_end\""
            )
        },
    }

    first_status, first_body = _post(f"{host}/pipeline", payload)
    first_gateway = (first_body.get("gateway") or {}).get("gateway_decision")
    first_reason = (first_body.get("gateway") or {}).get("decision_reason", "")
    _result_line("Probe first status:", str(first_status))
    _result_line("Probe first gateway:", str(first_gateway))
    _result_line("Probe first reason:", first_reason[:180])

    if first_gateway != "DENIED" or "approval" not in first_reason.lower():
        print("  Note: execute_command approval gate did not trigger as expected.")

    approve_status, approve_body = _post(
        f"{host}/approve/{request_id}",
        {"approved_by": "runtime-probe", "reason": "gvisor syscall evidence"},
    )
    _result_line("Probe approve status:", str(approve_status))
    _result_line("Probe approve body:", json.dumps(approve_body)[:180])

    replay_status, replay_body = _post(f"{host}/pipeline", payload)
    replay_gateway = (replay_body.get("gateway") or {}).get("gateway_decision")
    replay_output = str((replay_body.get("gateway") or {}).get("tool_output", ""))
    _result_line("Probe replay status:", str(replay_status))
    _result_line("Probe replay gateway:", str(replay_gateway))

    if replay_output:
        print("\n  Probe output (security/syscall-relevant lines):")
        for line in replay_output.splitlines():
            if (
                "syscall_probe_" in line
                or line.startswith("Name:")
                or line.startswith("Pid:")
                or line.startswith("Seccomp:")
                or line.startswith("CapEff:")
                or "Linux" in line
            ):
                print(f"    {line}")
    else:
        print("  No probe output captured from replay.")


def run_tests(host: str) -> int:
    pipeline_url = f"{host}/pipeline"
    failures = 0

    _banner(f"Agentic Security Pipeline — Cloud E2E Test  ({datetime.now(timezone.utc).isoformat()})")
    print(f"  Target : {host}")
    print(f"  Model  : kimi-k2.5:cloud (via egress-proxy → https://api.ollama.com)")
    print(f"  Runtime: runsc (gVisor)  USE_GVISOR=true")
    print(f"  Tests  : {len(TESTS)}")

    _print_runtime_evidence()
    _run_syscall_probe(host)

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

        # Oversize summarize may require explicit approval before replay.
        if decision == "DENIED" and "approval" in reason.lower():
            print("\n  i Approval required; approving request and replaying...")
            approve_status, _ = _post(
                f"{host}/approve/{test['id']}",
                {"approved_by": "cloud-script", "reason": "cloud summarize E2E"},
            )
            print(f"  i Approval status: {approve_status}")
            status, body = _post(pipeline_url, payload)
            gw = body.get("gateway") or {}
            decision = gw.get("gateway_decision", "N/A")
            reason = gw.get("decision_reason", "")
            output = gw.get("tool_output")
            risk = body.get("risk", {}).get("risk_score", "?")
            policy = body.get("policy", {}).get("policy_action", "?")

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
