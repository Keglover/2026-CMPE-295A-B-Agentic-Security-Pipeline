"""Direct tool-runner test — bypasses the pipeline and hits tool-runner:8001 directly."""
import httpx, json, sys

TEXT = (
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
)

host = sys.argv[1] if len(sys.argv) > 1 else "http://tool-runner:8001"
url  = f"{host}/execute/summarize"

print(f"POST {url}")
resp = httpx.post(url, json={"tool_args": {"text": TEXT}}, timeout=120)
print("STATUS:", resp.status_code)
try:
    body = resp.json()
    print("BODY:", json.dumps(body, indent=2))
except Exception:
    print("BODY:", resp.text[:800])






