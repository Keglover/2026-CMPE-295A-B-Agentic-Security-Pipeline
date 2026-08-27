## Plan: Agentic Security Pipeline Prototype

Wire all disconnected components (PII detector, config loader, circuit breaker, rate limiter, approval workflow) into the live pipeline, add Micro-VM tool execution via gVisor/Firecracker, externalize configuration, and update the tracker with new tasks including completion criteria. Open-source tools preferred throughout.

---

### Current State (Apr 15, 2026)

| Layer | Status |
|---|---|
| Normalize → Risk → Policy → Gateway (mock) → Audit | Working end-to-end |
| PII detector, config loader, circuit breaker, rate limiter, approval workflow | **Implemented but disconnected** |
| Micro-VM execution, output sanitization, YAML-driven config | **Not started** |

---

### Steps

**Phase A — Wire Disconnected Components** (all parallelizable except A5)

1. **A1: Wire Config Loader** — Replace hardcoded thresholds in `policy/engine.py` and hardcoded `TOOL_SCHEMAS` in `gateway/gateway.py` with values from `load_policy_config()` / `load_tool_registry()`. Keep hardcoded fallbacks as safety net.
   - Files: engine.py, gateway.py, config_loader.py
   - **Done when:** Changing policy_thresholds.yaml threshold values changes runtime behavior; unit tests pass with YAML-driven config

2. **A2: Wire PII Detector into SANITIZE path** — When `policy_action == SANITIZE`, call `pii_detector.redact()` on content before gateway. Record PII match count in audit.
   - Files: main.py, pii_detector.py
   - **Done when:** Request with email/SSN at risk score 15-34 → content reaching gateway has `[REDACTED]` markers; audit log records sanitization

3. **A3: Wire Circuit Breaker** — Wrap executor dispatch in `mediate()` with `CircuitBreakerRegistry`. Check `allow_request()` before execution, call `record_success()`/`record_failure()` after. Expose in `/health`.
   - Files: gateway.py, circuit_breaker.py
   - **Done when:** 5 consecutive tool failures → circuit opens → subsequent calls DENIED with "circuit breaker open"; `/health` shows per-tool state

4. **A4: Wire Rate Limiter** — Check `rate_limiter.check(tool_name)` before dispatch. Return DENIED with "rate limit exceeded" if empty.
   - Files: gateway.py, rate_limiter.py
   - **Done when:** Rapid requests exceed burst → DENIED; tokens refill after wait period

5. **A5: Wire Approval Workflow End-to-End** — `REQUIRE_APPROVAL` → submit to ApprovalManager → return PENDING. `/approve/{id}` → re-run gateway. Timeout → auto-deny. *Depends on A3.*
   - Files: main.py, gateway.py, workflow.py
   - **Done when:** Full cycle works: PENDING → APPROVED → EXECUTED, or PENDING → TIMED_OUT → DENIED

**Phase B — Real Tool Backends** (*depends on Phase A*)

6. **B1: Enable Real Executors** — Validate existing `gateway_real.py` security controls (SSRF blocking, path traversal, domain allowlist). Wire with `REAL_TOOLS=true` in Docker.
   - **Done when:** Docker deployment runs all 4 tools; SSRF to `127.0.0.1` blocked; `../../etc/passwd` traversal blocked

7. **B2: Argument Type/Constraint Validation** — Extend schema validation using `arg_types` and `arg_constraints` from `tool_registry.yaml`. *Depends on A1.*
   - **Done when:** Oversized text (>50k) → DENIED; invalid URL → DENIED; specific error messages

8. **B3: Output Sanitization (Egress)** — Scan tool output through PII detector before returning. Prevents tools from leaking PII. *Depends on A2, B1.*
   - **Done when:** Summarize output containing SSN → redacted before reaching caller

**Phase C — Micro-VM Tool Execution**

9. **C1: Design Micro-VM Architecture** — Evaluate and select:

   | Option | Isolation | Complexity | Boot Time | License |
   |---|---|---|---|---|
   | **gVisor (runsc)** *(recommended)* | Syscall filtering | Low (Docker runtime swap) | None (container) | Apache 2.0 |
   | **Bubblewrap (bwrap)** | User namespaces | Low (per-process) | <10ms | LGPL 2.1 |
   | **Kata Containers** | Lightweight VM | Medium (OCI-compatible) | ~1s | Apache 2.0 |
   | **Firecracker** | Full microVM | High (API lifecycle) | ~125ms (snapshot) | Apache 2.0 |

   - **Done when:** ADR (Architecture Decision Record) written with chosen approach, resource limits, network policy

10. **C2: Implement Sandbox Runner** — New app/gateway/sandbox_runner.py wrapping tool execution. Resource limits: CPU 100ms, memory 64MB, network deny-by-default, read-only filesystem.
    - **Done when:** Tool runs inside sandbox; host filesystem inaccessible; non-fetch_url tools have no network

11. **C3: Docker Compose with gVisor** — Add `tool-executor` service using gVisor runtime. Pipeline → HTTP → Sandboxed executor.
    - **Done when:** `docker-compose up` starts both services; tools execute in gVisor container

12. **C4: Firecracker Integration** *(stretch goal)* — Ephemeral microVM per tool call. Snapshot restore for sub-second boot.
    - **Done when:** Tool calls in Firecracker VMs; boot+execute+destroy < 2s

**Phase D — Enhanced Policy & Observability** (*parallel with Phase B/C*)

13. **D1: Policy Versioning** — Include YAML `version` in `PolicyResult` and audit log. *Depends on A1.*
14. **D2: Fail-Closed Behavior** — Risk engine failure → BLOCK default. Circuit breaker on risk engine.
15. **D3: Structured Observability** — Per-stage latency timing in response + audit. Optional: Prometheus `/metrics` endpoint via `prometheus-client` (open source).
16. **D4: History/Stats Enhancement** — Ensure `/history` filters and `/policy/stats` aggregation work correctly.

**Phase E — Testing & Validation** (*depends on all above*)

17. **E1:** Integration tests for all wired components (target 90%+ coverage on gateway/policy)
18. **E2:** Expand adversarial scenarios to 20+ (ASR < 10%, FPR < 5%)
19. **E3:** Micro-VM isolation tests (filesystem escape, network escape, resource exhaustion)

---

### Relevant Files

- main.py — Pipeline orchestration, wire PII/approval
- engine.py — Replace hardcoded thresholds with config loader
- pii_detector.py — Wire into SANITIZE + egress
- config_loader.py — Wire into engine + gateway
- gateway.py — Wire circuit breaker, rate limiter, config, sandbox
- circuit_breaker.py — Wire into gateway executor dispatch
- rate_limiter.py — Wire into gateway pre-execution
- gateway_real.py — Validate security controls
- workflow.py — Wire end-to-end
- policy_thresholds.yaml — Policy config source
- tool_registry.yaml — Tool registry source
- docker-compose.yml — Add gVisor executor service
- seed.py — Add new tasks, risks, dependencies

---

### Tracker Updates (New Tasks for seed.py)

**Phase 5 — Integration & Wiring (new):**
| # | Task | Owner | Done When |
|---|---|---|---|
| 5.11 | Wire config_loader into policy/engine.py | Eng | Thresholds from YAML; fallback works |
| 5.12 | Wire config_loader into gateway.py | Eng | Tool registry from YAML; fallback works |
| 5.13 | Wire pii_detector into SANITIZE path | Eng | PII redacted before gateway; audit records it |
| 5.14 | Wire circuit_breaker into gateway executor | Eng | 5 failures → open; `/health` shows state |
| 5.15 | Wire rate_limiter into gateway | Eng | Burst exceeded → DENIED; refill works |
| 5.16 | Wire approval workflow end-to-end | Eng | PENDING→APPROVED→EXECUTED cycle works |
| 5.17 | Implement output sanitization (egress PII) | Eng | Tool output PII redacted before response |
| 5.18 | Implement fail-closed default | Eng | Risk engine failure → BLOCK; audit records it |

**Phase 3 — Tool Proxy (new):**
| # | Task | Owner | Done When |
|---|---|---|---|
| 3.24 | Design Micro-VM architecture (ADR) | Arch | Decision document with chosen approach |
| 3.25 | Implement sandbox_runner.py | Eng | Tool runs isolated; host FS inaccessible |
| 3.26 | Docker Compose with gVisor runtime | Eng | `docker-compose up` sandbox works |
| 3.27 | Per-tool resource limits (CPU/mem/net/fs) | Eng | Limits enforced; exhaustion caught |
| 3.28 | Firecracker microVM integration (stretch) | Eng | Ephemeral VM per call; <2s lifecycle |

**Phase 6 — Testing (new):**
| # | Task | Owner | Done When |
|---|---|---|---|
| 6.15 | Tests for config-driven thresholds | Eng | YAML changes → behavior changes |
| 6.16 | Tests for PII sanitization path | Eng | Email/SSN/CC redacted in SANITIZE |
| 6.17 | Tests for circuit breaker behavior | Eng | Open/half-open/closed transitions |
| 6.18 | Tests for rate limiting | Eng | Burst → deny → refill → allow |
| 6.19 | Tests for approval workflow E2E | Eng | Approve/reject/timeout all tested |
| 6.20 | Micro-VM isolation tests | Eng | No escape: FS, network, resources |
| 6.21 | Expand adversarial suite to 20+ scenarios | Eng | Coverage of all attack categories |
| 6.22 | Measure ASR, FPR, latency p50/p95/p99 | Eng | Documented metrics report |

**Phase 7 — Security Audit (new):**
| # | Task | Owner | Done When |
|---|---|---|---|
| 7.12 | Audit Micro-VM escape paths | Sec | gVisor syscall filter verified |
| 7.13 | Audit inter-container network policy | Sec | No unauthorized cross-container traffic |
| 7.14 | Verify executor has no pipeline secrets | Sec | Secrets absent from sandbox env |

**New Risks:**
| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R9 | gVisor unsupported on Windows/macOS dev | Medium | Medium | WSL2 for dev; CI on Linux |
| R10 | Micro-VM boot latency exceeds SLA | Low | Medium | gVisor (no boot); Firecracker snapshots |
| R11 | Config hot-reload race conditions | Low | High | Atomic swap with version tracking |

**New Dependencies:**
- Tool Gateway → Sandbox Runner (execution isolation)
- Config Loader → Policy Engine + Tool Gateway (YAML config)
- PII Detector → Main Pipeline (SANITIZE + egress)

---

### Verification

1. **Phase A:** `pytest tests/` green; 3 demo paths work; YAML config loaded; PII redacted; CB + RL active
2. **Phase B:** `REAL_TOOLS=true` works; SSRF/traversal blocked; type validation rejects invalid args
3. **Phase C:** `docker-compose up` starts sandboxed executor; isolation tests pass
4. **Phase D:** `/health` shows states; audit has `policy_version` + per-stage timing
5. **Phase E:** 20+ scenarios; ASR < 10%; FPR < 5%; p95 < 500ms

---

### Decisions

- **Micro-VM:** gVisor for prototype (zero executor code changes), Firecracker as stretch
- **PII:** Keep custom regex for now; Presidio as future enhancement
- **Config:** YAML (already written); no OPA sidecar for prototype simplicity
- **Approval store:** In-memory for prototype; Redis for production
- **Scope out:** Multi-tool orchestration safety (per Xu et al. survey) — document for future

---

### Miscellaneous — Options Not Previously Considered

1. **WebAssembly (Wasm) Sandboxing** — Use Wasmtime/WasmEdge to compile tool executors to Wasm. Near-native perf, strong sandbox, cross-platform (works on Windows). Trade-off: requires executor rewrites or WASI support.

2. **OPA (Open Policy Agent)** — Run as Docker sidecar, replace Python policy engine with Rego rules. Hot-reloadable bundles, language-agnostic. Referenced in research paper. Trade-off: adds operational complexity.

3. **NeMo Guardrails** — NVIDIA open-source (Apache 2.0) conversational rails. Complements regex risk engine with ML-based jailbreak detection via Colang flows. Trade-off: model dependency, ~200ms latency.

4. **Microsoft Presidio for PII** — MIT-licensed NLP+regex PII detection. Built-in anonymizer with replace/redact/mask/encrypt operators. Drop-in replacement for `pii_detector.py`. Trade-off: heavier dependency (spaCy model).

5. **Cosign / SLSA for Supply Chain** — Sign container images via Sigstore. Addresses OWASP LLM05. Zero runtime cost: verification at deploy time only.

6. **OpenTelemetry Export** — Pipe NDJSON audit events to OTel collector → Grafana/Jaeger. Distributed tracing of pipeline stages. Use `opentelemetry-sdk` (Apache 2.0).

7. **Redis-backed Approval Queue** — Persist approvals across restarts via Redis Streams. Enables pub/sub notification on status change.

8. **Policy Dry-Run Mode** — Add `/pipeline?dry_run=true` parameter. Full pipeline evaluation without tool execution or audit recording. Useful for testing policy changes.

9. **Agent Identity / RBAC** — Per research paper: role-based tool access via JWT claims or YAML role-to-tool mapping. Different agent roles get different tool permissions. Referenced in NIST RBAC standard.

10. **Dependency-Aware Multi-Tool Scheduling** — Per Xu et al. survey (Section 5.1): validate tool chain topology before execution to prevent cross-tool state contamination. Out of scope for prototype, but critical for production multi-tool orchestration.