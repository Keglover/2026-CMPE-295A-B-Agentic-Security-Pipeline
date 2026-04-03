# Project Plan: Tool Proxy & Policy Enforcement Layer

> **Living Document** — Update task checkboxes and status indicators as the project progresses.
> Last Updated: 2026-03-18 | Owner: Security Architecture Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Deliverable Definitions](#2-deliverable-definitions)
3. [Status Legend](#3-status-legend)
4. [Dependency Map](#4-dependency-map)
5. [Phase 1 — Requirements Gathering & Discovery](#5-phase-1--requirements-gathering--discovery)
6. [Phase 2 — System Design & Architecture](#6-phase-2--system-design--architecture)
7. [Phase 3 — Core Development: Tool Proxy](#7-phase-3--core-development-tool-proxy)
8. [Phase 4 — Core Development: Policy Enforcement Layer](#8-phase-4--core-development-policy-enforcement-layer)
9. [Phase 5 — Integration & Wiring](#9-phase-5--integration--wiring)
10. [Phase 6 — Testing & Validation](#10-phase-6--testing--validation)
11. [Phase 7 — Security Audit & Hardening](#11-phase-7--security-audit--hardening)
12. [Phase 8 — Documentation, Packaging & Handoff](#12-phase-8--documentation-packaging--handoff)
13. [Cross-Cutting Concerns](#13-cross-cutting-concerns)
14. [Risk Register](#14-risk-register)
15. [Fallback & Contingency Paths](#15-fallback--contingency-paths)
16. [Required Reading & Onboarding Resources](#16-required-reading--onboarding-resources)
17. [Appendix: Contract Schemas](#17-appendix-contract-schemas)

---

## 1. Executive Summary

This document is the development roadmap for delivering two of the five primary deliverables of the Agentic Security Pipeline initiative:

| Deliverable | Component | Role |
|---|---|---|
| **A** | **Tool Proxy (Gateway)** | Secure intermediary that intercepts, authenticates, schema-validates, and mediates every request an AI/LLM agent makes to external tools, APIs, or data stores. |
| **B** | **Policy Enforcement Layer (Guardrails)** | Deterministic rules engine that evaluates inputs and outputs against security, compliance, data-privacy (PII), and ethical policies — blocking, redacting, or escalating violative requests. |

Both components enforce a **layered defense model**: the Policy Engine determines *legitimacy* (is this request safe?), while the Tool Proxy enforces *permission* (is this request structurally valid and allowed?). Neither component alone is sufficient — they are co-dependent by design.

### Current State (as of 2026-03-18)

- **Core modules implemented**: Ingest, Risk Engine, Policy Engine, Tool Gateway, Audit Logger — all functional.
- **20+ unit tests passing** across all modules.
- **Three demo paths** (benign → ALLOW, suspicious → REQUIRE_APPROVAL, malicious → BLOCK) ready for Gate 3 validation.
- **Sprint 2 scope** (real tools, approval workflow, history endpoint) not yet started.

---

## 2. Deliverable Definitions

### 2.1 Deliverable A — Tool Proxy (Gateway)

**Purpose**: The sole authorized execution path for all tool invocations. No tool call may bypass the gateway.

**Core Capabilities**:
- Tool allowlisting (registry of permitted tools)
- Argument schema validation via Pydantic
- Policy action gating (only `ALLOW` / `SANITIZE` permit execution)
- Executor routing (mock vs. real tool backends)
- Safe fallback denial with explicit rationale
- Request traceability via `request_id` propagation

**Architectural Invariant**: Even human-approved requests must still pass gateway schema and allowlist validation. Approval alone does not bypass structural checks.

### 2.2 Deliverable B — Policy Enforcement Layer

**Purpose**: A deterministic decision engine mapping risk scores to policy actions.

**Core Capabilities**:
- Score-to-action mapping with configurable thresholds
- High-attention category overrides (e.g., `TOOL_COERCION`, `DATA_EXFILTRATION` force minimum `REQUIRE_APPROVAL`)
- Five policy actions: `ALLOW`, `SANITIZE`, `QUARANTINE`, `REQUIRE_APPROVAL`, `BLOCK`
- Pure-function design (no side effects, no state, deterministic output for given input)
- Extensibility for future ML-based scoring layers

**Current Threshold Map**:

| Risk Score | Policy Action | Semantics |
|---|---|---|
| 0–14 | `ALLOW` | Safe — proceed to gateway |
| 15–34 | `SANITIZE` | Low risk — flag content, permit execution |
| 35–59 | `REQUIRE_APPROVAL` | Medium risk — human sign-off required |
| 60–79 | `QUARANTINE` | High risk — isolate, reference-only |
| 80–100 | `BLOCK` | Malicious — deny immediately |

---

## 3. Status Legend

Use these indicators in the **Status** column of all task tables:

| Indicator | Meaning |
|---|---|
| 🔴 | Not Started |
| 🟡 | In Progress |
| 🟢 | Completed |
| ⏸️ | Blocked / Awaiting Dependency |
| 🔁 | Needs Rework |

---

## 4. Dependency Map

### 4.1 Module Dependency Graph

```
models.py (shared Pydantic contracts)
    │
    ├──▸ normalizer.py (Ingest)
    │       └──▸ NormalizedInput
    │
    ├──▸ risk/engine.py (Risk Engine)
    │       ├── consumes NormalizedInput
    │       └──▸ RiskResult
    │
    ├──▸ policy/engine.py (Policy Engine)    ◀── DELIVERABLE B
    │       ├── consumes RiskResult
    │       └──▸ PolicyResult
    │
    ├──▸ gateway/gateway.py (Tool Proxy)     ◀── DELIVERABLE A
    │       ├── consumes PipelineRequest + PolicyResult
    │       ├── routes to gateway_mock.py | gateway_real.py
    │       └──▸ GatewayResult
    │
    └──▸ audit/logger.py
            └── consumes all intermediate results
```

### 4.2 Inter-Deliverable Dependencies

| Dependency | Direction | Description | Impact if Broken |
|---|---|---|---|
| **Policy → Gateway** | B feeds A | Gateway reads `PolicyResult.policy_action` to decide whether to execute | Gateway cannot make allow/deny decisions without policy output |
| **Gateway → Policy (indirect)** | A informs B | Gateway execution results feed back into audit trail; future policies may reference historical gateway decisions | Loss of feedback loop for adaptive policy tuning |
| **Shared Contracts** | Bidirectional | Both components import from `models.py` | Any schema change requires synchronized updates to both |
| **Risk Engine → Policy** | Upstream feeds B | Policy consumes `RiskResult`; if Risk Engine is unavailable, Policy has no input | Policy must define a fail-closed default (BLOCK or QUARANTINE) |
| **Policy ↔ Approval Workflow** | B triggers, external resolves | `REQUIRE_APPROVAL` action creates a pending state that the gateway must wait on | Approval timeout handling required; gateway must not hang indefinitely |

### 4.3 Critical Edge Case: Policy Engine Latency / Offline

**Scenario**: The Policy Enforcement Layer experiences high latency or is completely unreachable during a request.

**Required Behavior**:
- The Tool Proxy **MUST fail closed** — default to `BLOCK` if Policy Engine response is unavailable within the configured timeout.
- The system **MUST NOT** cache stale policy decisions and apply them to new requests (each request requires a fresh evaluation).
- The Audit Logger **MUST** record the failure mode (policy timeout) and the resulting default action.
- A circuit-breaker pattern should be implemented: after N consecutive Policy Engine failures, the gateway enters degraded mode (all requests blocked, alert raised) rather than repeatedly timing out.

---

## 5. Phase 1 — Requirements Gathering & Discovery

**Duration**: Week 1 (Mar 2–8, 2026)
**Gate**: Gate 1 — All contracts signed off, skeleton runs

### 5.1 Tool Proxy Requirements

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 1.1 | - [x] Define the tool registry schema (tool name, required args, optional args, types) | Arch | 🟢 | `TOOL_SCHEMAS` dict in `gateway.py` |
| 1.2 | - [x] Enumerate initial tool allowlist (summarize, write_note, search_notes, fetch_url) | Arch | 🟢 | 4 tools registered |
| 1.3 | - [x] Define gateway decision enum (`EXECUTED`, `DENIED`) | Arch | 🟢 | In `models.py` |
| 1.4 | - [x] Specify executor routing strategy (mock vs. real backends) | Arch | 🟢 | `REAL_TOOLS` env flag |
| 1.5 | - [x] Document trust boundary for privileged execution (Boundary B) | Arch | 🟢 | Section 5 spec |
| 1.6 | - [ ] Define rate-limiting requirements per tool per agent | Eng | 🔴 | Sprint 2 scope |
| 1.7 | - [ ] Define authentication requirements for real external tool APIs | Eng | 🔴 | Sprint 2 scope |
| 1.8 | - [ ] Specify timeout and retry semantics per tool category | Eng | 🔴 | Needed before real tools |

### 5.2 Policy Enforcement Requirements

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 1.9 | - [x] Define policy action enum (ALLOW, SANITIZE, QUARANTINE, REQUIRE_APPROVAL, BLOCK) | Arch | 🟢 | In `models.py` |
| 1.10 | - [x] Define score-to-action threshold mapping | Arch | 🟢 | See threshold table above |
| 1.11 | - [x] Define high-attention category override rules | Arch | 🟢 | TOOL_COERCION / DATA_EXFILTRATION → min REQUIRE_APPROVAL |
| 1.12 | - [x] Specify deterministic evaluation contract (pure function, no side effects) | Arch | 🟢 | |
| 1.13 | - [ ] Define PII detection patterns for SANITIZE action | Eng | 🔴 | Regex + entity patterns |
| 1.14 | - [ ] Specify QUARANTINE semantics (read-only reference, no tool execution, human review queue) | Eng | 🟡 | Partially documented |
| 1.15 | - [ ] Define policy versioning and hot-reload strategy | Eng | 🔴 | For production deployments |
| 1.16 | - [ ] Document compliance mapping (OWASP LLM Top 10 → policy rules) | Arch | 🔴 | Reference `05_OWASP_LLM_Top10.md` |

---

## 6. Phase 2 — System Design & Architecture

**Duration**: Weeks 1–2 (Mar 2–15, 2026)
**Gate**: Architecture review sign-off

### 6.1 Tool Proxy Architecture

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 2.1 | - [x] Design gateway as single-entry-point for all tool execution | Arch | 🟢 | Architectural invariant established |
| 2.2 | - [x] Design allowlist validation pipeline (tool exists → args valid → policy permits) | Arch | 🟢 | Three-stage check in `gateway.py` |
| 2.3 | - [x] Design executor abstraction (mock/real swap via interface) | Arch | 🟢 | `gateway_mock.py` / `gateway_real.py` |
| 2.4 | - [ ] Design credential vault integration for real tool backends | Eng | 🔴 | Environment variables as interim |
| 2.5 | - [ ] Design circuit-breaker for downstream tool failures | Eng | 🔴 | Required for production resilience |
| 2.6 | - [ ] Design request queuing for `REQUIRE_APPROVAL` state | Eng | 🔴 | Needed for approval workflow |
| 2.7 | - [ ] Design observability hooks (latency metrics, error rates per tool) | Eng | 🔴 | Prometheus / structured logs |
| 2.8 | - [ ] Schema evolution strategy for adding new tools without downtime | Arch | 🔴 | Registry versioning |

### 6.2 Policy Enforcement Architecture

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 2.9 | - [x] Design pure-function policy evaluation (score + categories → action) | Arch | 🟢 | `evaluate()` in `engine.py` |
| 2.10 | - [x] Design category override mechanism | Arch | 🟢 | High-attention categories bump minimum |
| 2.11 | - [ ] Design policy rule DSL or configuration format (YAML/JSON) | Eng | 🔴 | Currently hardcoded thresholds |
| 2.12 | - [ ] Design policy decision caching strategy (if any) | Eng | 🔴 | Current: no caching (fresh eval per request) |
| 2.13 | - [ ] Design multi-policy composition (AND/OR logic for stacked rules) | Eng | 🔴 | For complex compliance scenarios |
| 2.14 | - [ ] Design policy audit trail (which rule fired, why) | Eng | 🟡 | `policy_reason` field exists, needs enrichment |
| 2.15 | - [ ] Design fail-closed default behavior when upstream (Risk Engine) is unavailable | Arch | 🔴 | Critical for resilience |

### 6.3 Integration Architecture

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 2.16 | - [x] Design end-to-end pipeline orchestration (Ingest → Risk → Policy → Gateway → Audit) | Arch | 🟢 | `main.py` `/pipeline` endpoint |
| 2.17 | - [x] Design shared contract model (`models.py` Pydantic schemas) | Arch | 🟢 | All models defined |
| 2.18 | - [ ] Design async pipeline variant (for high-throughput deployments) | Eng | 🔴 | Current: synchronous |
| 2.19 | - [ ] Design health-check and readiness probes for each component | Eng | 🟡 | `/health` exists, component-level probes missing |

---

## 7. Phase 3 — Core Development: Tool Proxy

**Duration**: Weeks 2–4 (Mar 9–29, 2026)
**Gate**: Gate 2 — All 5 modules functional; Gate 3 — 3 demo paths pass

### 7.1 Allowlist & Registry

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 3.1 | - [x] Implement `TOOL_SCHEMAS` registry with tool names and required argument lists | Eng | 🟢 | 4 tools: summarize, write_note, search_notes, fetch_url |
| 3.2 | - [x] Implement allowlist check (`tool_name in TOOL_SCHEMAS`) | Eng | 🟢 | |
| 3.3 | - [ ] Externalize tool registry to configuration file (YAML/JSON) | Eng | 🔴 | Remove hardcoded dict |
| 3.4 | - [ ] Add tool metadata: description, risk tier, required privilege level | Eng | 🔴 | Enriched registry |
| 3.5 | - [ ] Implement dynamic tool registration endpoint (`POST /tools/register`) | Eng | 🔴 | Admin-only, authenticated |

### 7.2 Schema Validation

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 3.6 | - [x] Implement argument presence validation (required args check) | Eng | 🟢 | |
| 3.7 | - [ ] Implement argument type validation (string, int, URL, etc.) | Eng | 🔴 | Currently checks presence only |
| 3.8 | - [ ] Implement argument value constraints (max length, allowed patterns) | Eng | 🔴 | Defense against oversized payloads |
| 3.9 | - [ ] Implement nested argument validation for complex tool inputs | Eng | 🔴 | |

### 7.3 Policy Gating

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 3.10 | - [x] Implement policy action check (only ALLOW/SANITIZE proceed to execution) | Eng | 🟢 | |
| 3.11 | - [x] Implement DENIED response construction with rationale | Eng | 🟢 | |
| 3.12 | - [ ] Implement REQUIRE_APPROVAL hold-and-wait logic | Eng | 🔴 | Needs approval endpoint |
| 3.13 | - [ ] Implement configurable approval timeout with auto-deny | Eng | 🔴 | Prevents indefinite pending state |

### 7.4 Executor Backends

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 3.14 | - [x] Implement mock executor (safe stubs, no side effects) | Eng | 🟢 | `gateway_mock.py` |
| 3.15 | - [ ] Implement real `fetch_url` executor with allowlisted domains | Eng | 🔴 | SSRF protection required |
| 3.16 | - [ ] Implement real `write_note` executor with filesystem sandboxing | Eng | 🔴 | Path traversal protection |
| 3.17 | - [ ] Implement real `summarize` executor via LLM API call | Eng | 🔴 | Token budget + API key management |
| 3.18 | - [ ] Implement real `search_notes` executor with query sanitization | Eng | 🔴 | Injection prevention |
| 3.19 | - [ ] Implement executor timeout and error handling per tool | Eng | 🔴 | Prevent hanging on unresponsive tools |

### 7.5 Resilience & Rate Limiting

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 3.20 | - [ ] Implement per-tool rate limiting (token bucket or sliding window) | Eng | 🔴 | |
| 3.21 | - [ ] Implement circuit breaker for downstream tool failures | Eng | 🔴 | |
| 3.22 | - [ ] Implement graceful degradation mode (all tools unavailable → inform agent) | Eng | 🔴 | |
| 3.23 | - [ ] Implement request deduplication (prevent replay of identical tool calls) | Eng | 🔴 | |

---

## 8. Phase 4 — Core Development: Policy Enforcement Layer

**Duration**: Weeks 2–4 (Mar 9–29, 2026)
**Gate**: Gate 2 — All 5 modules functional

### 8.1 Core Engine

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 4.1 | - [x] Implement deterministic score-to-action mapping | Eng | 🟢 | 5 thresholds |
| 4.2 | - [x] Implement high-attention category override logic | Eng | 🟢 | TOOL_COERCION, DATA_EXFILTRATION |
| 4.3 | - [x] Implement `PolicyResult` output with `policy_action`, `policy_reason`, `requires_approval` | Eng | 🟢 | |
| 4.4 | - [ ] Externalize threshold configuration to YAML/JSON | Eng | 🔴 | Remove hardcoded values |
| 4.5 | - [ ] Implement threshold hot-reload without service restart | Eng | 🔴 | File-watch or config endpoint |

### 8.2 Advanced Policy Rules

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 4.6 | - [ ] Implement PII detection rules (email, phone, SSN, credit card patterns) | Eng | 🔴 | For SANITIZE action |
| 4.7 | - [ ] Implement content redaction logic (replace PII with `[REDACTED]`) | Eng | 🔴 | Paired with PII detection |
| 4.8 | - [ ] Implement tool-specific policy overrides (e.g., `fetch_url` always requires elevated scrutiny) | Eng | 🔴 | Per-tool policy annotations |
| 4.9 | - [ ] Implement policy rule chaining (multiple rules can fire, most restrictive wins) | Eng | 🔴 | Composition logic |
| 4.10 | - [ ] Implement context-aware policy (e.g., time-of-day restrictions, agent identity) | Eng | 🔴 | Stretch goal |

### 8.3 Approval Workflow

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 4.11 | - [ ] Implement `POST /approve/{request_id}` endpoint | Eng | 🔴 | Simulated human approval |
| 4.12 | - [ ] Implement approval state store (pending requests queue) | Eng | 🔴 | In-memory for MVP, Redis for prod |
| 4.13 | - [ ] Implement approval timeout (auto-deny after configurable TTL) | Eng | 🔴 | Prevent orphaned approvals |
| 4.14 | - [ ] Implement approval audit trail (who approved, when, original risk context) | Eng | 🔴 | Feeds into audit logger |
| 4.15 | - [ ] Implement approval escalation (if no response in T seconds, escalate to secondary approver) | Eng | 🔴 | Stretch goal |

### 8.4 Compliance & Reporting

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 4.16 | - [ ] Map OWASP LLM Top 10 items to specific policy rules | Arch | 🔴 | Cross-reference existing research |
| 4.17 | - [ ] Implement policy decision statistics endpoint (`GET /policy/stats`) | Eng | 🔴 | Action distribution over time |
| 4.18 | - [ ] Implement policy rule version tracking (which version of rules evaluated a request) | Eng | 🔴 | Auditability |
| 4.19 | - [ ] Implement `GET /history` endpoint for audit log queries | Eng | 🔴 | Identified in existing task backlog |

---

## 9. Phase 5 — Integration & Wiring

**Duration**: Weeks 4–5 (Mar 23 – Apr 5, 2026)
**Gate**: Gate 3 — All 3 demo paths pass end-to-end

### 9.1 Pipeline Integration

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 5.1 | - [x] Wire Ingest → Risk → Policy → Gateway → Audit in `main.py` | Eng | 🟢 | `/pipeline` endpoint |
| 5.2 | - [x] Propagate `request_id` through all pipeline stages | Eng | 🟢 | Full traceability |
| 5.3 | - [ ] Validate Gate 3: benign prompt → ALLOW → EXECUTED | Eng | 🟡 | Ready to test |
| 5.4 | - [ ] Validate Gate 3: suspicious prompt → REQUIRE_APPROVAL → DENIED (no approval) | Eng | 🟡 | Ready to test |
| 5.5 | - [ ] Validate Gate 3: malicious prompt → BLOCK → DENIED | Eng | 🟡 | Ready to test |
| 5.6 | - [ ] Implement `run_scenarios.py` for reproducible evaluation | Eng | 🔴 | Automated scenario runner |
| 5.7 | - [ ] Wire approval endpoint into gateway hold-and-wait loop | Eng | 🔴 | Depends on 4.11, 3.12 |

### 9.2 Contract Validation

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 5.8 | - [x] Verify all inter-module contracts match `models.py` definitions | Eng | 🟢 | |
| 5.9 | - [ ] Add contract assertion middleware (validate Pydantic models at each boundary) | Eng | 🔴 | Defense against silent schema drift |
| 5.10 | - [ ] Implement structured error propagation (error at any stage → graceful pipeline abort with audit entry) | Eng | 🔴 | |

---

## 10. Phase 6 — Testing & Validation

**Duration**: Weeks 5–6 (Mar 30 – Apr 12, 2026)
**Gate**: Gate 4 — Reproducible baseline vs. protected runs

### 10.1 Unit Tests

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 6.1 | - [x] Gateway unit tests (allowlist, schema, policy gating, denial reasons) | Eng | 🟢 | 8 tests |
| 6.2 | - [x] Policy engine unit tests (thresholds, category overrides, edge scores) | Eng | 🟢 | 7 tests |
| 6.3 | - [ ] Expand gateway tests for real executor paths | Eng | 🔴 | When real tools are implemented |
| 6.4 | - [ ] Add policy tests for PII detection and redaction | Eng | 🔴 | When 4.6/4.7 are implemented |
| 6.5 | - [ ] Add approval workflow tests (approve, timeout, auto-deny) | Eng | 🔴 | When 4.11–4.14 are implemented |
| 6.6 | - [ ] Achieve 100% critical path coverage for gateway and policy modules | Eng | 🔴 | Target: Week 5 |

### 10.2 Integration & End-to-End Tests

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 6.7 | - [x] E2E tests for full pipeline (7 scenarios) | Eng | 🟢 | `test_e2e.py` |
| 6.8 | - [ ] Expand scenario pack to 12+ scenarios | Eng | 🔴 | Include edge cases |
| 6.9 | - [ ] Implement adversarial test suite (prompt injection variants) | Eng | 🔴 | Red-team harness (Deliverable D) |
| 6.10 | - [ ] Implement latency benchmarks (target: < 200ms p95 for full pipeline) | Eng | 🔴 | |
| 6.11 | - [ ] Implement false positive rate measurement (target: FPR < 5% on benign inputs) | Eng | 🔴 | |

### 10.3 Metrics & Evaluation

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 6.12 | - [ ] Define and collect: Attack Success Rate (ASR), False Positive Rate (FPR), Latency p50/p95/p99 | Eng | 🔴 | |
| 6.13 | - [ ] Run baseline evaluation (no security pipeline) vs. protected evaluation | Eng | 🔴 | Gate 4 requirement |
| 6.14 | - [ ] Document metric results in evaluation report | Eng | 🔴 | Week 7 deliverable |

---

## 11. Phase 7 — Security Audit & Hardening

**Duration**: Weeks 6–7 (Apr 6–19, 2026)

### 11.1 Tool Proxy Hardening

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 7.1 | - [ ] Audit `fetch_url` for SSRF vulnerabilities (allowlisted domains only, no private IP ranges) | Sec | 🔴 | |
| 7.2 | - [ ] Audit `write_note` for path traversal (chroot / sandbox enforcement) | Sec | 🔴 | |
| 7.3 | - [ ] Validate no direct tool execution paths exist outside gateway | Sec | 🔴 | Invariant verification |
| 7.4 | - [ ] Verify argument injection protection (no shell metacharacter passthrough) | Sec | 🔴 | |
| 7.5 | - [ ] Validate rate limiting prevents resource exhaustion | Sec | 🔴 | |
| 7.6 | - [ ] Review Docker network isolation (gateway cannot reach unintended services) | Sec | 🔴 | |

### 11.2 Policy Engine Hardening

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 7.7 | - [ ] Verify fail-closed behavior when Risk Engine is unreachable | Sec | 🔴 | |
| 7.8 | - [ ] Verify no policy bypass via direct API call to gateway (gateway must always check policy) | Sec | 🔴 | |
| 7.9 | - [ ] Verify PII redaction completeness (no partial leaks in logs or responses) | Sec | 🔴 | |
| 7.10 | - [ ] Audit approval workflow for race conditions (double-approve, approve-after-timeout) | Sec | 🔴 | |
| 7.11 | - [ ] Verify audit log integrity (append-only, no log tampering) | Sec | 🔴 | |

### 11.3 OWASP LLM Top 10 Alignment

| OWASP LLM Risk | Relevant Component | Mitigation Status |
|---|---|---|
| LLM01: Prompt Injection | Risk Engine + Policy | 🟡 Detection rules exist, tuning in progress |
| LLM02: Insecure Output Handling | Gateway + Policy | 🔴 Output validation not yet implemented |
| LLM03: Training Data Poisoning | Out of scope | N/A |
| LLM04: Model Denial of Service | Gateway (rate limiting) | 🔴 Rate limiting not yet implemented |
| LLM05: Supply Chain Vulnerabilities | Deployment (deps) | 🟡 Pinned requirements.txt |
| LLM06: Sensitive Information Disclosure | Policy (PII detection) | 🔴 PII rules not yet implemented |
| LLM07: Insecure Plugin Design | Gateway (schema validation) | 🟡 Basic validation exists |
| LLM08: Excessive Agency | Gateway (allowlist) + Policy | 🟢 Tool allowlist enforced |
| LLM09: Overreliance | Out of scope (UX layer) | N/A |
| LLM10: Model Theft | Out of scope (infra layer) | N/A |

---

## 12. Phase 8 — Documentation, Packaging & Handoff

**Duration**: Weeks 8–9 (Apr 20 – May 8, 2026)
**Gate**: Gate 5 — Ready for handoff

| # | Task | Owner | Status | Notes |
|---|---|---|---|---|
| 8.1 | - [ ] Complete API reference documentation (all endpoints, request/response schemas) | Eng | 🔴 | |
| 8.2 | - [ ] Write operator guide (deployment, configuration, monitoring) | Eng | 🔴 | |
| 8.3 | - [ ] Write developer guide (adding new tools, modifying policy rules) | Eng | 🔴 | |
| 8.4 | - [ ] Verify Docker deployment on clean machine | Eng | 🔴 | |
| 8.5 | - [ ] Update README with final architecture diagram | Eng | 🔴 | |
| 8.6 | - [ ] Finalize workbook chapters 4, 5, 8, 9 | Eng | 🔴 | |
| 8.7 | - [ ] Produce evaluation report with metrics and recommendations | Eng | 🔴 | |
| 8.8 | - [ ] Conduct final regression test suite | Eng | 🔴 | |

---

## 13. Cross-Cutting Concerns

### 13.1 Audit & Observability

All operations across both components must produce structured audit records:

| Field | Source | Purpose |
|---|---|---|
| `request_id` | Generated at ingestion | End-to-end trace correlation |
| `timestamp` | Each pipeline stage | Latency measurement |
| `content_hash` | SHA-256, first 16 chars | Privacy-preserving content reference |
| `policy_action` | Policy Engine | Decision audit |
| `gateway_decision` | Gateway | Execution audit |
| `tool_name` | Gateway | Tool usage tracking |
| `risk_score` | Risk Engine | Threat severity |

**Privacy Constraint**: Raw user content is **never** written to logs. Only the content hash is persisted.

### 13.2 Error Handling Philosophy

| Failure Mode | Component | Behavior |
|---|---|---|
| Risk Engine unreachable | Policy Engine | Fail closed → BLOCK |
| Policy Engine unreachable | Gateway | Fail closed → DENIED |
| Tool backend timeout | Gateway | Return DENIED with timeout reason |
| Invalid tool arguments | Gateway | Return DENIED with schema violation details |
| Unknown tool requested | Gateway | Return DENIED with "tool not in allowlist" |
| Approval timeout exceeded | Gateway | Auto-deny, log as timeout |

### 13.3 Configuration Management

| Parameter | Component | Current | Target |
|---|---|---|---|
| Policy thresholds | Policy Engine | Hardcoded in `engine.py` | External YAML config |
| Tool registry | Gateway | Hardcoded `TOOL_SCHEMAS` dict | External JSON/YAML config |
| Approval timeout | Gateway | Not implemented | Configurable (default: 300s) |
| Rate limits | Gateway | Not implemented | Per-tool configurable |
| Log output path | Audit Logger | `audit_logs/audit.ndjson` | Configurable |
| Real/mock tools toggle | Gateway | `REAL_TOOLS` env var | Per-tool toggle |

---

## 14. Risk Register

| # | Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|---|
| R1 | Policy Engine latency causes gateway timeouts | Medium | High | Circuit breaker + fail-closed default | Eng |
| R2 | False positives block legitimate agent actions | Medium | High | FPR tuning in Week 7; configurable thresholds | Eng |
| R3 | Real tool backends introduce SSRF/injection vectors | High | Critical | Domain allowlisting, input sanitization, sandboxing | Sec |
| R4 | Approval workflow creates UX bottleneck | Medium | Medium | Auto-deny timeout; escalation rules | Eng |
| R5 | Schema drift between `models.py` and module implementations | Low | High | Pydantic strict mode; contract assertion middleware | Eng |
| R6 | Audit log volume becomes unmanageable | Low | Medium | Log rotation; structured queries via `/history` | Eng |
| R7 | Hardcoded thresholds prevent tuning without redeployment | Medium | Medium | Externalize to config (tasks 4.4, 4.5) | Eng |
| R8 | Adversarial inputs bypass Risk Engine detection | High | Critical | Red-team harness (Deliverable D); continuous rule updates | Sec |

---

## 15. Fallback & Contingency Paths

| Path | Trigger | Scope Reduction | Revised Deadline |
|---|---|---|---|
| **Plan A (Nominal)** | All gates pass on schedule | Full scope: 12+ scenarios, all metrics, real tools | May 8, 2026 |
| **Plan B** | One stream slips by > 1 week | Reduce scenario set to 8; defer advanced metrics | May 15, 2026 |
| **Plan C (Minimum Viable)** | Multiple streams slip | Core pipeline only (ingest + risk + policy + gateway + audit); 1 benign + 1 malicious scenario; mock tools only | May 22, 2026 |

---

## 16. Required Reading & Onboarding Resources

This section provides foundational knowledge for engineers building the Tool Proxy and Policy Enforcement Layer. No fabricated URLs are included — all references are to well-known standards, protocols, or open-source projects that can be located via standard search engines.

### 16.1 API Gateway & Proxy Patterns

| Topic | What to Study | Why It Matters |
|---|---|---|
| **API Gateway Pattern** | Search: "API Gateway pattern microservices" — study the role of a gateway as a single entry point that handles cross-cutting concerns (auth, rate limiting, routing). Reference implementations: Kong, Envoy Proxy, AWS API Gateway. | The Tool Proxy is fundamentally an API gateway specialized for LLM tool calls. Understanding standard gateway concerns (routing, auth, rate limiting, circuit breaking) provides the architectural vocabulary. |
| **Reverse Proxy Architecture** | Search: "reverse proxy vs forward proxy architecture" — understand request interception, header manipulation, and backend routing. Reference: NGINX documentation on reverse proxy configuration. | The gateway intercepts agent-to-tool requests identically to how a reverse proxy intercepts client-to-server requests. |
| **Circuit Breaker Pattern** | Search: "circuit breaker pattern Martin Fowler" — study the state machine (closed → open → half-open) for handling downstream failures. | Required for handling Tool Backend and Policy Engine failures gracefully (see Section 13.2). |
| **Rate Limiting Algorithms** | Search: "token bucket vs sliding window rate limiting" — understand fixed window, sliding window, token bucket, and leaky bucket approaches. | Per-tool rate limiting is a core gateway requirement (task 3.20). |

### 16.2 Authentication, Authorization & Access Control

| Topic | What to Study | Why It Matters |
|---|---|---|
| **OAuth 2.0 for Tool Calling** | Read: RFC 6749 (OAuth 2.0 Authorization Framework). Search: "OAuth2 client credentials flow" for service-to-service auth. | Real tool backends (fetch_url, external APIs) will require authenticated access. Client credentials flow is the standard for machine-to-machine authentication. |
| **RBAC (Role-Based Access Control)** | Search: "RBAC model NIST" — study the NIST RBAC standard (roles, permissions, sessions). | Tool-level access control (which agents can invoke which tools) maps directly to RBAC. Policy rules may differ by agent role/privilege level. |
| **Principle of Least Privilege** | Search: "principle of least privilege NIST 800-53" — understand how to scope permissions minimally. | Core design principle: agents should only have access to the tools they need, with the minimum required argument permissions. |

### 16.3 LLM Security & Prompt Injection

| Topic | What to Study | Why It Matters |
|---|---|---|
| **OWASP Top 10 for LLM Applications** | Search: "OWASP Top 10 for Large Language Models" — the 2025 edition covers prompt injection, insecure output handling, excessive agency, and more. | Direct mapping to policy rules. The project's existing research file `05_OWASP_LLM_Top10.md` provides a curated summary. |
| **Prompt Injection Taxonomy** | Search: "prompt injection attacks taxonomy 2024 2025" — study direct injection, indirect injection, jailbreaking, and goal hijacking. Key papers: Greshake et al. "Not what you've signed up for" (indirect prompt injection). | The Risk Engine's four detection categories (INSTRUCTION_OVERRIDE, DATA_EXFILTRATION, TOOL_COERCION, OBFUSCATION) map directly to known attack classes. |
| **LLM Guardrails Frameworks** | Study: **NVIDIA NeMo Guardrails** — open-source framework for adding programmable guardrails to LLM applications. Search: "NeMo Guardrails documentation getting started". | NeMo Guardrails is the closest industry-standard reference implementation for the Policy Enforcement Layer concept. Study its Colang policy language and rail definitions for design inspiration. |
| **LangChain Tool Calling** | Search: "LangChain tool calling agents" — study how LangChain structures tool definitions, argument schemas, and tool execution within agent loops. | Understanding how leading agent frameworks structure tool calls informs the design of the Tool Proxy's registry and schema validation. |

### 16.4 Data Privacy & PII Handling

| Topic | What to Study | Why It Matters |
|---|---|---|
| **PII Detection Patterns** | Search: "PII detection regex patterns email phone SSN" — study common regex patterns. Reference: Microsoft Presidio (open-source PII detection and anonymization). | Tasks 4.6/4.7 (PII detection and redaction) require robust pattern matching. Presidio provides a well-tested library for this. |
| **Data Minimization Principle** | Search: "GDPR data minimization principle" — understand the requirement to collect and process only the minimum necessary personal data. | The audit logger's design (content hash only, never raw content) implements data minimization. Policy rules for SANITIZE must enforce this at the content level. |
| **Tokenization & Redaction Strategies** | Search: "PII tokenization vs redaction vs masking" — understand the tradeoffs between replacing PII with tokens (reversible), redaction markers (irreversible), or partial masking. | The SANITIZE policy action must choose a redaction strategy. Irreversible redaction is safest but loses information; tokenization allows authorized recovery. |

### 16.5 Security Architecture & Trust Boundaries

| Topic | What to Study | Why It Matters |
|---|---|---|
| **STRIDE Threat Modeling** | Search: "STRIDE threat model Microsoft" — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. | Formal framework for identifying threats at each trust boundary. Apply STRIDE to both the Tool Proxy (Boundary B: privileged execution) and Policy Engine (Boundary A: untrusted content). |
| **Zero Trust Architecture** | Search: "NIST 800-207 Zero Trust Architecture" — study the principle of "never trust, always verify" and how it applies to internal service communication. | The pipeline's design philosophy — every request evaluated regardless of source — is a Zero Trust implementation. |
| **Defense in Depth** | Search: "defense in depth layered security" — understand why multiple independent security layers are more robust than a single checkpoint. | The architectural invariant (Policy determines legitimacy, Gateway enforces permission, both must pass) is a textbook defense-in-depth implementation. |

### 16.6 Infrastructure & Deployment

| Topic | What to Study | Why It Matters |
|---|---|---|
| **Docker Network Isolation** | Search: "Docker network isolation security best practices" — study bridge networks, network policies, and service-to-service communication control. | The deployment uses Docker Compose with network isolation. Understanding Docker networking is required for security audit (task 7.6). |
| **Structured Logging (NDJSON)** | Search: "NDJSON newline delimited JSON structured logging" — understand the format and its advantages for log aggregation and querying. | The audit logger outputs NDJSON. Engineers need to understand this format for building the `/history` query endpoint (task 4.19). |
| **FastAPI Security Features** | Search: "FastAPI security tutorial" — study dependency injection for auth, request validation, CORS, and middleware patterns in FastAPI. | The MVP uses FastAPI. Understanding its security middleware patterns is essential for adding authentication to admin endpoints (tool registration, approval). |

### 16.7 Recommended Open-Source Projects for Reference

| Project | What to Study | Relevance |
|---|---|---|
| **NVIDIA NeMo Guardrails** | Policy language (Colang), rail definitions, input/output rails, topical rails | Closest analog to the Policy Enforcement Layer |
| **Microsoft Presidio** | PII detection engine, recognizer patterns, anonymization operators | Reference for PII detection/redaction (tasks 4.6/4.7) |
| **LangChain** | Tool definitions, structured tool calling, agent executor patterns | Reference for tool registry and schema validation design |
| **Guardrails AI** | Validators, on-fail actions, structured output validation | Alternative guardrails framework; compare approach with NeMo |
| **Envoy Proxy** | HTTP filter chains, rate limiting, circuit breaking, observability | Reference for proxy resilience patterns |
| **Open Policy Agent (OPA)** | Rego policy language, policy-as-code, decision logging | Reference for externalizing policy rules (tasks 2.11, 4.4) |

---

## 17. Appendix: Contract Schemas

### 17.1 Shared Enums

```python
class SourceType(str, Enum):
    DIRECT_PROMPT = "direct_prompt"
    RETRIEVED_CONTENT = "retrieved_content"

class RiskCategory(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_COERCION = "tool_coercion"
    OBFUSCATION = "obfuscation"
    BENIGN = "benign"

class PolicyAction(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

class GatewayDecision(str, Enum):
    EXECUTED = "executed"
    DENIED = "denied"
```

### 17.2 Core Data Models

| Model | Input From | Output To | Key Fields |
|---|---|---|---|
| `PipelineRequest` | External caller | All stages | `content`, `source_type`, `proposed_tool`, `tool_args`, `request_id` |
| `NormalizedInput` | Ingest | Risk Engine | `normalized_content`, `normalization_notes` |
| `RiskResult` | Risk Engine | Policy Engine | `risk_score` (0–100), `risk_categories[]`, `matched_signals[]`, `rationale` |
| `PolicyResult` | Policy Engine | Gateway | `policy_action`, `policy_reason`, `requires_approval` |
| `GatewayResult` | Gateway | Audit / Caller | `gateway_decision`, `decision_reason`, `tool_output` |
| `PipelineResponse` | Orchestrator | External caller | All above + `timestamp`, `summary` |

### 17.3 Tool Schema Registry (Current)

```json
{
    "summarize": {"required_args": ["text"], "risk_tier": "low"},
    "write_note": {"required_args": ["title", "body"], "risk_tier": "medium"},
    "search_notes": {"required_args": ["query"], "risk_tier": "low"},
    "fetch_url": {"required_args": ["url"], "risk_tier": "high"}
}
```

---

## Sprint-Level Summary View

| Sprint | Week | Tool Proxy Focus | Policy Engine Focus | Gate |
|---|---|---|---|---|
| 1 | Mar 2–8 | Contracts, skeleton | Contracts, skeleton | Gate 1 ✅ |
| 2 | Mar 9–15 | Allowlist, schema validation, mock executor | Score→action mapping, category overrides | — |
| 3 | Mar 16–22 | Gateway integration with policy output | Threshold tuning with risk engine output | Gate 2 |
| 4 | Mar 23–29 | E2E demo path validation | Approval workflow design | Gate 3 |
| 5 | Mar 30–Apr 5 | Real executor stubs, rate limiting | PII detection, redaction | — |
| 6 | Apr 6–12 | Security audit (SSRF, injection) | FPR tuning, metric collection | Gate 4 |
| 7 | Apr 13–19 | Circuit breaker, resilience | Evaluation report, rule recommendations | — |
| 8 | Apr 20–26 | Docs, deployment verification | Docs, config externalization | — |
| 9 | Apr 27–May 8 | Final regression, handoff | Final regression, handoff | Gate 5 |

---

> **Document Maintenance**: This plan should be reviewed and updated at each sprint boundary. Mark tasks as they progress using the status indicators. Add new tasks as scope evolves. Archive completed phases to a separate "Completed Work" section if the document grows unwieldy.
