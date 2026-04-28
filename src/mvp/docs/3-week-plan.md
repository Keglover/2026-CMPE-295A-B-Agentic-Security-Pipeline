# 3-Week Prototype Plan — Due May 8, 2026

**Created:** April 16, 2026
**Team:** Haroon (A), Doa (B), Nkono (C), Kyle (D)
**Prototype deadline:** May 8 (Gate 4 + Gate 5 sign-off)

## Stage map (due dates are GitHub milestones)

| Stage | Due | Focus | GitHub milestone |
|-------|-----|-------|------------------|
| 1 — Foundation | **Apr 22** | Gateway real executors, approval + history endpoints, evaluation scaffold, initial e2e | `Stage 1 — Foundation` |
| 2 — Intelligence & Sandbox | **Apr 29** | LLM-as-judge, B0/B1/B2/B3 baselines, Docker sandbox | `Stage 2 — Intelligence & Sandbox` |
| 3 — Hardening & Integration | **May 5** | Regression pass, bug fixes from Stage 2, polish | `Stage 3 — Hardening & Integration` |
| 4 — Demo & Report | **May 8** | Recorded demo, Gate 4 + Gate 5 sign-off | `Stage 4 — Demo & Report` |

Stages are sequential: **no Stage N+1 work until Stage N exit criteria are met.** See the "GitHub Scheduling" section below for issue-to-stage assignments.

---

## Current State of the World (as of April 16)

### What's done

| Item | Status | Evidence |
|------|--------|----------|
| Agent loop + tools + config | Done | `feat/agent-loop-integration` branch, PR #21 |
| Pre-screen + redact blocked prompts | Done | PR #21 — fail-closed, 59/59 tests passing |
| 5+ detection rules (Doa) | Merged to main | PR #12 — 207 lines added to `risk/engine.py` + tests |
| Core pipeline (5 stages) | Done since Sprint 1 | Gates 1-3 passed |
| Architecture docs | Done | `docs/architecture.md` |

### What exists on branches but hasn't been merged

| Branch | Owner | What's there | Merge difficulty |
|--------|-------|-------------|-----------------|
| `tooling-Nkono` | Nkono | Real tool executors (#9), approve/reject endpoints (#5), history endpoint (#6), approval workflow, circuit breaker, rate limiter, PII detector, config YAML, 549 new test lines | **HIGH** — restructured entire project from `src/mvp/` to root. Will conflict with everything. |
| `feat/eval-scenarios` | Kyle | `run_scenarios.py` (~382 lines), 10 JSON scenario files (5 benign, 5 malicious) | **LOW** — additive, lives in `scenarios/` |
| `feat/agent-loop-integration` | Haroon | Pre-screen + redact (PR #21) | **LOW** — clean diff against main |

### What's still stubbed

- `src/mvp/app/gateway/gateway_real.py` on main — all 4 executors raise `NotImplementedError`
- No Docker testing of real tool calls has happened yet
- No approval endpoint on main (only on Nkono's branch)
- No history endpoint on main (only on Nkono's branch)

### Open issues (16)

| # | Title | Owner | Priority for prototype |
|---|-------|-------|-----------------------|
| 3 | 5+ detection rules | Doa | **Done** — close it |
| 4 | `run_scenarios.py` eval script | Kyle | **Critical** — nearly done |
| 5 | POST /approve endpoint | Nkono | **Critical** — built, needs merge |
| 6 | GET /history endpoint | Nkono | **Nice-to-have** — built, needs merge |
| 7 | LLM agent loop | Haroon | **Done** — close after PR #21 merges |
| 8 | E2E agent testing | Haroon+Kyle | **Critical** — not started |
| 9 | Real tool executors | Nkono | **Critical** — built, needs merge |
| 10 | Gate 4+5 sign-off | Haroon | **Critical** — blocked by #4, #8 |
| 13 | History poisoning | — | **Done** — resolved by PR #21 |
| 14-20 | Security hardening (7) | unassigned | **Not for prototype** — Sprint 3 |

---

## The Big Decision: Nkono's Branch

Nkono's `tooling-Nkono` branch moved the entire project from `src/mvp/` to root level and added ~3,500 lines across 20+ new files. Merging it as-is will break every other branch and rewrite the project structure.

**Recommendation: Cherry-pick, don't merge wholesale.**

1. Keep the existing `src/mvp/` structure (everything else depends on it)
2. Port Nkono's implementations file-by-file into the existing structure:
   - `gateway_real.py` → replace stubs in `src/mvp/app/gateway/gateway_real.py`
   - Approval workflow → new file at `src/mvp/app/approval/workflow.py`
   - `/approve` and `/history` routes → add to `src/mvp/app/main.py`
3. Skip extras that aren't needed for prototype: circuit breaker, rate limiter, PII detector, YAML config loader (these are Sprint 3 at best)

**Who does this:** Nkono, with Haroon reviewing. Nkono knows his code best.

---

## Week 1: Apr 16-22 — Sprint 2 Closure + Merge

**Goal:** All branch work merged to main. Pipeline runs end-to-end.

> **Scheduling note:** Team members work 2-3 sessions per week, not daily.
> Deliverables are per-week with soft ordering. Dependencies are noted so
> people can self-coordinate, but exact days are flexible within the week.

### Haroon — Week 1 deliverables

| Deliverable | Effort | Dependency | Notes |
|-------------|--------|------------|-------|
| Merge PR #21 to main | 15 min | — | Do first — unblocks Kyle and Doa |
| Close issues #3, #7, #13 | 5 min | PR #21 merged | Housekeeping |
| Create GitHub milestone + assign issues | 20 min | — | See GitHub Scheduling section |
| Review + merge Nkono's PRs (executors, approval, history) | 1-2 hrs | Nkono's PRs ready | Can happen across multiple sessions |
| Review + merge Kyle's eval PR | 1 hr | Kyle's PR ready | |
| Integration test: 3 demos on merged main | 2 hrs | All PRs merged | End-of-week validation |

### Nkono — Week 1 deliverables

| Deliverable | Effort | Dependency | Notes |
|-------------|--------|------------|-------|
| PR #1: Port real tool executors into `src/mvp/app/gateway/gateway_real.py` | 2-3 hrs | — | Replace the 4 stubs. His `tooling-Nkono` branch has working code — adapt to `src/mvp/` structure. |
| PR #2: Port approval workflow + `/approve`, `/reject`, `/history` routes | 3-4 hrs | — | New `src/mvp/app/approval/workflow.py` + routes in `main.py`. Can be same or separate PR. |
| Test `REAL_TOOLS=true` locally | 1-2 hrs | PRs merged | Mock Ollama or use local model for `summarize` |

### Kyle — Week 1 deliverables

| Deliverable | Effort | Dependency | Notes |
|-------------|--------|------------|-------|
| Finish JSON scenario files + output formatting | 2-3 hrs | — | His commit says "need to finish json scenarios files" |
| Open PR from `feat/eval-scenarios` | 1 hr | Scenarios finished | Must work against main: `python -m scenarios.run_scenarios` |
| Run scenarios against merged main, capture output | 1 hr | PR merged | First real results |

### Doa — Week 1 deliverables

| Deliverable | Effort | Dependency | Notes |
|-------------|--------|------------|-------|
| Pull updated main, verify detection rules pass | 30 min | PR #21 merged | `pytest tests/test_risk.py` |
| Review open issues, add comments to any that need clarification | 30 min | — | |

### Week 1 exit criteria

- [ ] Main branch has: agent loop, pre-screen, real executors, approval endpoint, history endpoint, eval script, 10+ scenarios
- [ ] `pytest` passes on main (all existing + new tests)
- [ ] Three demos work: benign tool call, blocked attack, human-in-the-loop approval
- [ ] Issues #3, #7, #13 closed. Issues #5, #6, #9 closed (ported from Nkono). Issue #4 closed (Kyle).

---

## Week 2: Apr 23-29 — Docker Testing + Baselines + LLM-as-Judge

**Goal:** Real tool calls tested in Docker. Baseline comparison table with real numbers. LLM-as-judge prototype working.

> Same flexible scheduling — each person picks 2-3 sessions in the week.
> Dependencies are noted but days are not prescribed.

### Docker/sandbox testing plan (Item 3)

**What we're testing:** The 4 real tool executors execute actual operations. We need to verify they work correctly AND that the security boundaries hold.

#### Docker setup (Haroon + Nkono)

1. **Update `docker-compose.yml`** to add:
   - `REAL_TOOLS=true` environment variable
   - Network isolation: `internal: true` on the pipeline network (no outbound internet)
   - A separate `egress` network for `fetch_url` only, with DNS restrictions
   - Volume mount: only `./audit_logs` and `./sandbox/notes` writable
   - Ollama sidecar container (or mock) for `summarize`

2. **Container structure:**
   ```
   docker-compose.yml
   ├── pipeline    (FastAPI, REAL_TOOLS=true, internal network)
   ├── ollama      (LLM for summarize, internal network only)
   └── agent       (run_agent.py, connects to pipeline)
   ```

3. **Verify isolation:**
   - From inside pipeline container: `curl https://google.com` should fail (internal network)
   - `fetch_url` with allowed domain should work through egress proxy/network
   - `write_note` should only write to `/app/sandbox/notes/`, not escape to host
   - `search_notes` should only read from `/app/sandbox/notes/`

#### Edge cases to test

| # | Test case | Expected behavior |
|---|-----------|-------------------|
| 1 | `fetch_url` with `http://169.254.169.254` (AWS metadata) | DENIED — SSRF protection |
| 2 | `fetch_url` with `http://localhost:11434` (Ollama) | DENIED — internal service, not on allowlist |
| 3 | `write_note` with `../../etc/passwd` as title | DENIED — path traversal blocked |
| 4 | `write_note` with 10MB body | DENIED or truncated — DoS protection |
| 5 | `summarize` when Ollama container is down | Graceful error, not crash |
| 6 | `search_notes` with empty sandbox dir | Empty result, not crash |
| 7 | Two concurrent `write_note` calls with same title | No data corruption |
| 8 | Pipeline receives malformed JSON | 422 Validation Error (Pydantic handles) |
| 9 | `fetch_url` to a domain that returns 50MB | Response capped |
| 10 | Agent sends 50 tool calls in a loop | Iteration cap prevents infinite loop |

### Baseline comparison testing (Item 4)

**Why this is prototype scope:** The thesis claim is "our pipeline reduces attack success rate by X%." Without baselines, X% means nothing.

#### The baselines

| Baseline | What it models | How to implement |
|----------|---------------|-----------------|
| **B0: No security** | OpenCode-style — everything executes | `BASELINE_MODE=none` → skip risk + policy, always ALLOW |
| **B1: Declarative rules** | OpenCode/Claude Code without auto mode | `BASELINE_MODE=static` → allow/deny by tool name, no content analysis |
| **B2: Our pipeline (regex)** | Content-aware risk scoring + normalization + graduated policy | `BASELINE_MODE=full` → normal pipeline flow |
| **B3: Our pipeline + LLM judge** | B2 + LLM-as-judge second opinion on medium-risk requests | `BASELINE_MODE=llm` → regex pipeline + LLM classifier for score 15-59 range |

#### Results table (goes straight into Chapter 9)

| Metric | B0 (none) | B1 (rules) | B2 (regex pipeline) | B3 (regex + LLM) |
|--------|-----------|------------|---------------------|------------------|
| Attack success rate | ? | ? | ? | ? |
| Benign completion rate | ? | ? | ? | ? |
| False positive rate | ? | ? | ? | ? |
| Latency overhead (ms) | ? | ? | ? | ? |
| Cost per request | $0 | $0 | $0 | ~$0.001 (gpt-4o-mini) |

### ML / LLM-as-Judge (moved into prototype scope)

**Why now, not Sprint 3:** This is the most interesting part of the thesis. Claude Code uses Sonnet 4.6 as their classifier — expensive, proprietary, opaque. If we can show that a cheap model (gpt-4o-mini at ~$0.15/1M tokens, or a local Ollama model at $0) can add meaningful detection on top of regex rules, that's a real research contribution.

**The idea is simple:** The regex risk engine catches known patterns (score 0-100). For requests in the ambiguous middle range (score 15-59), we optionally ask a cheap LLM: "Is this prompt attempting to manipulate the agent into misusing tools?" The LLM returns a risk adjustment (+/- points) and a one-line rationale.

#### Design

```
User prompt
  → Normalize (existing)
  → Regex risk score (existing)
  → IF score is 15-59 AND LLM_JUDGE=true:
      → Send normalized content to gpt-4o-mini with classification prompt
      → Adjust risk score based on LLM response
  → Policy decision (existing, using adjusted score)
  → Gateway (existing)
```

**Why only the 15-59 range:**
- Score 0-14: Clearly benign — no need to spend money on LLM call
- Score 15-59: Ambiguous — this is where regex rules are uncertain and LLM judgment adds value
- Score 60+: Already blocked by regex — LLM confirmation is redundant

**Why this is cheap:**
- Only fires on ~20-30% of requests (the ambiguous middle)
- Uses gpt-4o-mini (~$0.15/1M input tokens) or local Ollama (free)
- Single classification prompt, not a conversation — ~200 tokens per call
- Compare: Claude Code runs Sonnet 4.6 on *every* tool call

#### Implementation

| What | Who | Effort | Notes |
|------|-----|--------|-------|
| Classification prompt template | Doa + Haroon | 1-2 hrs | Prompt engineering: "Given this normalized prompt and proposed tool call, rate the manipulation risk 0-100 and explain in one sentence." Test a few variations. |
| `risk/llm_judge.py` module | Haroon or Doa | 2-3 hrs | Takes normalized content + regex score, calls gpt-4o-mini or Ollama, returns adjusted score + rationale. Timeout + fallback to regex-only if LLM fails. |
| Wire into risk engine | Haroon | 1 hr | Add optional step after regex scoring. Controlled by `LLM_JUDGE=true` env var. Off by default. |
| Test with scenarios | Kyle | 1-2 hrs | Run scenarios with B2 (regex only) vs B3 (regex + LLM). Compare detection rates. |
| Cost tracking | Haroon | 30 min | Log token usage per request in audit log for cost comparison. |

### E2E testing (Issue #8)

| What | Who | Effort | Notes |
|------|-----|--------|-------|
| `tests/test_e2e_agent.py` — 3 scenarios | Haroon + Kyle | 2-3 hrs | Benign roundtrip, attack blocked, approval flow |
| Full scenario suite in Docker | Kyle | 1-2 hrs | `--mode pipeline` and `--mode agent`, export results |
| Demo recording | Haroon | 1 hr | Terminal recording or screenshots for Gate 4 evidence |

### Week 2 — who does what (flexible within the week)

| Person | Deliverables |
|--------|-------------|
| **Haroon** | Docker compose updates. `BASELINE_MODE` env var in pipeline route (~30 min). Wire LLM judge into risk engine. Demo recording. |
| **Nkono** | Port SSRF + path traversal guards from his branch. Test real tools in Docker containers. |
| **Kyle** | Add `--baseline` flag to `run_scenarios.py`. Run all 4 baselines (B0-B3). Export comparison table. Add edge-case Docker scenarios. E2E test writing. |
| **Doa** | Define B1 static permission map. Co-design LLM judge prompt template with Haroon. Add SSRF + path traversal detection rules. |

### Week 2 exit criteria

- [ ] `docker-compose up` starts pipeline with `REAL_TOOLS=true` and all 4 tools work
- [ ] 10 edge-case scenarios pass (or documented as known limitations)
- [ ] Baseline comparison table (B0 vs B1 vs B2 vs B3) with real numbers
- [ ] LLM-as-judge module works (even if only on a subset of scenarios)
- [ ] Issue #8 closed
- [ ] Demo recording exists

---

## Week 3: Apr 30 - May 8 — Gate Sign-off + Polish

**Goal:** Gate 4 and Gate 5 pass. Prototype is demoable and documented.

> This is a full 9-day window. Use it to catch anything that slipped from
> Weeks 1-2 and polish the evaluation results. Everyone picks 2-3 sessions.

### Deliverables by person

| Person | Deliverables |
|--------|-------------|
| **Haroon** | Gate 4 checklist: verify all run scripts are reproducible. Write `DEMO.md`. Gate 5: update workbook Ch 8-9 with architecture diagram, evidence screenshots, and scenario results table. Close issue #10. Tag `v0.2.0-prototype`. |
| **Kyle** | Final scenario run across all baselines → export results as CSV + markdown → save in `docs/evaluation-results.md`. Include cost-per-request column for B3. |
| **Nkono** | Verify all real executor tests pass. Write "Real Tool Executors" section for workbook (1 page). |
| **Doa** | Write "Detection Rules + LLM Judge" section for workbook (1 page): list regex rules, what they catch, how LLM judge improves detection on ambiguous cases, cost comparison vs Claude Code's Sonnet 4.6 classifier. |
| **All** | Final smoke test: clone fresh, `docker-compose up`, run demos. Buffer for any slipped work. |

### Week 3 exit criteria

- [ ] Gate 4 passed: one-command reproducible demo (`docker-compose up` → `python run_agent.py`)
- [ ] Gate 5 passed: workbook Ch 8-9 updated with real evidence
- [ ] Evaluation results include B0/B1/B2/B3 comparison with cost data
- [ ] Issue #10 closed
- [ ] `v0.2.0-prototype` tag exists on main

---

## Items 4-7: Tracked for Sprint 3 (Post May 8)

Items 4 (baselines) and the ML/LLM-as-judge portion have been moved into prototype scope — see Week 2. The remaining items are tracked here.

### 5. Industry critique

**What it means:** Compare our pipeline approach against:
- Anthropic's model-level constitutional AI
- OpenAI's tool-use permissions (function calling restrictions)
- LangChain's permission frameworks
- Microsoft Semantic Kernel's trust boundaries
- Any academic papers on agentic security (OWASP Top 10 for LLM Applications)

**Why later:** This is thesis writing work (Chapters 1-2), not implementation. Requires literature review.

**Artifact:** Will become a section in workbook Chapter 2 (Related Work).

### 6. Tool expansion research

**What it means:** Study how production tools handle security:
- **Cursor**: How does it sandbox file system access?
- **Claude Code**: 3-layer model (declarative rules + OS sandbox + ML classifier) — see updated `sprint2-gameplan.md` Section 8
- **OpenCode**: Explicitly no sandbox — permission system is UX only
- **Devin/SWE-Agent**: How do they limit tool scope?

**Why later:** Interesting for thesis depth but doesn't change the prototype. Can inform Sprint 3 tool expansion (add `run_code`, `git_commit`, `db_query` tools).

**Artifact:** Will become a subsection in Chapter 2 and inform Sprint 3 tool registry expansion.

### 7. Workbook/report

**What it means:**
- Chapters 1-2 due this semester (introduction, related work, background)
- Workbook at [Google Doc](https://docs.google.com/document/d/19AR3aLDZIvz_V0Qx3EiR1F5j5ldrJc-o/edit) needs revision to match actual implementation
- Chapters 8-9 (implementation, evaluation) updated as part of Gate 5

**What we do for prototype:** Only Ch 8-9 evidence (handled in Week 3 above). Full Ch 1-2 writing is post-May-8.

**Artifact:** Updated workbook with implementation evidence by May 8. Full chapters by semester end.

---

## GitHub Scheduling (Item 1) — **Staged milestones**

The single `Prototype — May 8` milestone has been split into four staged milestones with real due dates so dependencies are explicit and each teammate has a near-term deadline instead of one May 8 cliff.

### Stage 1 — Foundation (due **Apr 22**)

Core prototype must be runnable end-to-end before Stage 2 starts.

| Issue | Title | Owner |
|-------|-------|-------|
| #4 | Build run_scenarios.py evaluation script | Kyle |
| #5 | Add POST /approve/{request_id} endpoint | Nkono |
| #6 | Add GET /history endpoint | Nkono |
| #8 | End-to-end agent testing — benign, attack, approval demos | Kyle + Haroon |
| #9 | Implement real tool executors in gateway_real.py | Nkono |
| #25 | Restructure src/mvp/scenarios → src/mvp/evaluation/ | Kyle |

**Exit:** `uvicorn app.main:app` runs; agent completes benign + attack + approval flows; 10+ scenarios execute against the pipeline.

### Stage 2 — Intelligence & Sandbox (due **Apr 29**)

Research-differentiator work, runs on top of a green Stage 1.

| Issue | Title | Owner |
|-------|-------|-------|
| #22 | Baseline evaluation runner — B0/B1/B2/B3 | Kyle + Haroon + Doa |
| #23 | LLM-as-judge risk scoring module | Doa + Haroon |
| #24 | Docker sandbox for real tool executors | Nkono + Haroon |

**Exit:** `results_matrix.json` contains numbers for all 4 baselines; LLM-judge fires only on ambiguous band; `docker compose up` contains sandbox-escape scenarios.

### Stage 3 — Hardening & Integration (due **May 5**)

Catch-all bug-fix + regression stage. **Bugs found during Stage 2 integration land in #29, not new tickets.**

| Issue | Title | Owner |
|-------|-------|-------|
| #29 | Integration hardening: regression pass + bug fixes + polish | All |

**Exit:** Zero P0 bugs; full regression green; fresh-clone run < 10 min; Stage 4 kickoff sign-off in #29.

### Stage 4 — Demo & Report (due **May 8**)

| Issue | Title | Owner |
|-------|-------|-------|
| #26 | Prototype demo — script, dry-run, recorded walkthrough | Haroon + Kyle |
| #10 | Gate 4 + Gate 5 sign-off — evaluation & workbook readiness | Haroon |

### Closed immediately (pre-existing work already done)

| Issue | Reason |
|-------|--------|
| #3 | Doa's rules merged in PR #12 |
| #7 | Agent loop done, PR #21 |
| #13 | Resolved by PR #21 |

### Sprint 3 — Hardening milestone (tracked as future)

| Issue | Title |
|-------|-------|
| #14-#20 | Security hardening backlog (DoS, ReDoS, logger, registry drift, etc.) |
| #27 | Baseline expansion — LangChain guardrails + LlamaGuard |
| #28 | Tool expansion research — Cursor / Claude Code / OpenCode |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Nkono's code doesn't port cleanly into `src/mvp/` | Medium | High — delays Week 1 | Haroon pair-programs with Nkono to unblock |
| Kyle's scenarios depend on agent module imports that don't exist on main yet | High | Medium — his script won't run | Merge PR #21 first, then Kyle rebases |
| Ollama not available in Docker (GPU, memory) | Medium | Medium — `summarize` tool fails | Use mock summarize in CI/testing, real Ollama only in local demos |
| Student schedules — people can't work every day | High | Medium — work takes longer | Weekly deliverables, not daily. 2-3 sessions per week is fine. |
| LLM-as-judge adds latency or cost concerns | Low | Low — it's optional | Only fires on ambiguous range (15-59). gpt-4o-mini is ~$0.001/request. Can be turned off entirely. |
| Merge conflicts from parallel branches | Medium | Medium | Merge to main frequently, don't let branches diverge |

---

## Check-in Format (async, 2-3x per week in team chat)

When you finish a work session, post:
```
Done: [what you completed]
Next: [what you'll work on next session]
Blocked: [nothing / specific thing]
```

Haroon checks these and unblocks anything that's stuck. No need to post on days you don't work on the project.

---

## Summary: What Each Person Does

### Haroon (architect + integrator)
- Week 1: Merge PRs, close done issues, set up milestone, integration test
- Week 2: Docker compose, baseline mode in pipeline, LLM judge wiring, demo recording
- Week 3: Gate 4+5 sign-off, workbook evidence, release tag

### Nkono (gateway + endpoints)
- Week 1: Port real executors + approval + history from his branch into `src/mvp/` PRs
- Week 2: SSRF + path traversal guards, test real tools in Docker
- Week 3: Write "Real Tool Executors" workbook section

### Kyle (evaluation + testing)
- Week 1: Finish and merge scenario script + JSON files
- Week 2: Run all 4 baselines (B0-B3), export comparison table, edge-case scenarios, E2E tests
- Week 3: Final eval run with cost data, export results for workbook

### Doa (detection rules + LLM judge)
- Week 1: Verify rules on updated main
- Week 2: Co-design LLM judge prompt template, define B1 static permissions, add SSRF/path-traversal rules
- Week 3: Write "Detection Rules + LLM Judge" workbook section
