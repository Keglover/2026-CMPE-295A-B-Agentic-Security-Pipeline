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

- 2026-04-30: Risk engine hardening — LLM judge policy constants, unified `risk_score` variable, `ModuleNotFoundError`-only optional judge import, Windows asyncio policy moved to `main.py`, `RiskCategory.LLM_FLAGGED` for judge escalation/failure (replaces misleading OBFUSCATION fallback), plus mocked tests in `tests/test_risk.py`.
- Audit log path is configurable via `AUDIT_LOG_PATH` env var — important for Docker volume mounts.
- Policy thresholds are constants in `policy/engine.py` — easy to tune without touching logic.
- Gateway `TOOL_SCHEMAS` dict doubles as documentation for what args each tool needs.
- Agent scaffolding done on `feat/agent-llm-integration` branch (2026-04-01).
- `OPENAI_BASE_URL` env var allows swapping LLM providers (Qwen, Ollama, Together AI).

---

## GitHub [#23](https://github.com/Keglover/CMPE-295-Project-Repo/issues/23) — LLM-as-judge risk scoring: follow-up child tasks

Create **three separate GitHub issues** (or sub-issues if your org has them enabled), each **linked to / tracked under #23**. Paste the block below as a **comment on #23** once the child issues exist, replacing `NN`, `MM`, `PP` with their numbers.

**Suggested comment for #23:**

```markdown
Follow-ups from risk-engine refactor (branch `dao-risk-policy`):

- [ ] #NN — Async / event-loop safe LLM judge invocation
- [ ] #MM — Refactor `score()` into focused helpers
- [ ] #PP — Documentation pass for LLM-as-judge pipeline
```

### Child task 1 — Async / event-loop safe LLM judge invocation

**Title:** `[#23] Risk engine: async-safe LLM judge (no asyncio.run in running loop)`

**Body (draft):**

- Parent: #23  
- Replace `asyncio.run(judge(text))` inside sync `score()` with a pattern that works when FastAPI (or tests) already have a running event loop (`RuntimeError: asyncio.run() cannot be called from a running event loop`).  
- Remove or replace the fragile `"Event loop is closed"` string match in `except`; classify errors explicitly or re-raise where appropriate.  
- Options: `async def score_async(...)` + `await judge(text)` from async routes; `nest_asyncio` (usually avoid); or a small thread-pool wrapper for the judge call—pick one and document it.  
- Acceptance: `score()` (or replacement API) callable from sync `run_pipeline` and from async contexts without silent mis-scoring; tests cover both paths.

### Child task 2 — Refactor `score()` into focused helpers

**Title:** `[#23] Risk engine: split score() into match / judge / summarize helpers`

**Body (draft):**

- Parent: #23  
- Extract pure-ish units: rule matching → optional judge application → category + rationale assembly, keeping public `score()` as a thin orchestrator.  
- Goal: easier unit tests, clearer separation of policy constants vs logic, smaller diffs for future judge changes.  
- Acceptance: behaviour unchanged (existing + new tests pass); no new public API required unless agreed for async work in child task 1.

### Child task 3 — Documentation pass for LLM-as-judge pipeline

**Title:** `[#23] Docs: LLM judge band, fail-closed semantics, and RiskCategory.LLM_FLAGGED`

**Body (draft):**

- Parent: #23  
- Update MVP `README` (or design doc) with: judge band `JUDGE_BAND_LOW`–`JUDGE_BAND_HIGH`, when judge runs vs skipped, escalation vs `llm_judge_failure` scores and policy mapping (70 → QUARANTINE, 80 → BLOCK), and `RiskCategory.LLM_FLAGGED` vs `matched_signals`.  
- Mention optional deps (`openai`, `httpx`) and `LLM_JUDGE_ENABLED`.  
- Acceptance: a new reader can predict pipeline behaviour without reading `engine.py` line-by-line.

---

## Gate Progress (Ch8 §8.6)

| Gate | Criteria | Status |
|------|----------|--------|
| Gate 1 — Interface Freeze | All module contracts defined + skeleton runs | PASSED |
| Gate 2 — Core Module Completion | All 5 components implemented | PASSED |
| Gate 3 — End-to-End MVP | 3-path demo (benign/suspicious/malicious) pass | PASSED (2026-03-24) |
| Gate 4 — Evaluation Readiness | Reproducible run scripts | PENDING |
| Gate 5 — Workbook Readiness | Chapter 8/9 updated with evidence | PENDING |
