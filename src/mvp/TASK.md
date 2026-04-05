# TASK.md — Agentic Security Pipeline MVP

> **Task tracking has moved to GitHub Issues.**
> This file is a read-only summary. Only Member A updates it.
> View all issues: https://github.com/razzacktiger/Agentic-Security-Pipeline/issues

---

## Sprint 1 — Completed (Week of March 3, 2026)

- [x] Create project directory structure and requirements.txt
- [x] Define Pydantic data models / interface contracts
- [x] Implement Ingest/Normalize module
- [x] Implement Risk Engine — rules-first, 4 attack categories
- [x] Implement Policy Engine — deterministic action mapping
- [x] Implement Tool Gateway — allowlist + schema validation
- [x] Implement Audit/Telemetry logger — NDJSON file output
- [x] Wire all modules into FastAPI app
- [x] Write 20+ Pytest tests — all 5 modules + 3 e2e demo paths
- [x] Dockerfile + docker-compose.yml
- [x] Run tests locally — 35/35 passing (2026-03-24)
- [x] Verify 3-path demo (benign/suspicious/malicious) (2026-03-24)

---

## Sprint 2 — Active (Week of March 31, 2026)

| # | Issue | Owner | Branch | Status |
|---|-------|-------|--------|--------|
| [#1](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/1) | Add 5+ risk detection rules | Member B | `feat/risk-rules` | TODO |
| [#2](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/2) | Build scenario evaluation runner | Member D | `feat/eval-scenarios` | TODO |
| [#3](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/3) | POST /approve endpoint | Member C | `feat/gateway-approval` | TODO |
| [#4](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/4) | GET /history endpoint | Member C | `feat/gateway-approval` | TODO |
| [#5](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/5) | LLM agent loop integration | Member A | `feat/agent-llm-integration` | IN PROGRESS |
| [#6](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/6) | End-to-end agent testing | Member A + D | — | TODO |
| [#7](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/7) | Real tool executors | Member C | `feat/gateway-approval` | TODO |
| [#8](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/8) | Gate 4 + Gate 5 sign-off | Member A | — | TODO |

---

## Discovered During Work

- Audit log path is configurable via `AUDIT_LOG_PATH` env var — important for Docker volume mounts.
- Policy thresholds are constants in `policy/engine.py` — easy to tune without touching logic.
- Gateway `TOOL_SCHEMAS` dict doubles as documentation for what args each tool needs.
- Agent scaffolding done on `feat/agent-llm-integration` branch (2026-04-01).
- `OPENAI_BASE_URL` env var allows swapping LLM providers (Qwen, Ollama, Together AI).

---

## Gate Progress (Ch8 §8.6)

| Gate | Criteria | Status |
|------|----------|--------|
| Gate 1 — Interface Freeze | All module contracts defined + skeleton runs | PASSED |
| Gate 2 — Core Module Completion | All 5 components implemented | PASSED |
| Gate 3 — End-to-End MVP | 3-path demo (benign/suspicious/malicious) pass | PASSED (2026-03-24) |
| Gate 4 — Evaluation Readiness | Reproducible run scripts | PENDING |
| Gate 5 — Workbook Readiness | Chapter 8/9 updated with evidence | PENDING |
