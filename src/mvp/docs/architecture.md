# Agentic Security Pipeline — Architecture Flow

## Full System Flow

```mermaid
flowchart TD
    subgraph USER["👤 User"]
        U1[Type message in terminal]
    end

    subgraph AGENT["Agent Loop — run_agent.py + agent/"]
        A1["run_agent.py<br/><i>CLI: interactive or --payload</i>"]
        A2["run_agent_turn()<br/><i>agent/loop.py</i>"]
        A3["OpenAI Client<br/><i>agent/config.py settings</i>"]
        LLM["LLM<br/>(OpenAI / Together / Ollama)"]
        A4{LLM response?}
        A5["Build PipelineRequest<br/>content + tool_name + tool_args"]
        A6["Feed tool result<br/>back to LLM"]
        A7["Feed BLOCKED message<br/>back to LLM"]
        A8["Return reply to user"]
    end

    subgraph PIPELINE["Security Pipeline — FastAPI POST /pipeline"]
        direction TB
        M["main.py — orchestrator"]

        subgraph S1["Stage 1: Normalize"]
            N1["ingest/normalizer.py<br/>HTML decode → strip zero-width<br/>→ Unicode NFKC → collapse whitespace"]
        end

        subgraph S2["Stage 2: Risk Score"]
            R1["risk/engine.py<br/>25 regex rules across 4 families<br/>→ score 0-100"]
        end

        subgraph S3["Stage 3: Policy Decision"]
            P1["policy/engine.py<br/>Score thresholds:<br/>0-14 ALLOW | 15-34 SANITIZE<br/>35-59 REQUIRE_APPROVAL<br/>60-79 QUARANTINE | 80+ BLOCK"]
        end

        subgraph S4["Stage 4: Tool Gateway"]
            G1{"On allowlist?"}
            G2{"Args valid?"}
            G3{"Policy permits?"}
            G4["Execute tool<br/>(mock or real)"]
            G5["DENIED + reason"]
        end

        subgraph S5["Stage 5: Audit"]
            AU["audit/logger.py<br/>→ audit.ndjson<br/>(hash only, never raw input)"]
        end
    end

    U1 --> A1
    A1 --> A2
    A2 --> A3
    A3 -->|"messages + tool defs"| LLM
    LLM -->|"response"| A4

    A4 -->|"Text only"| A8
    A4 -->|"Tool call(s)"| A5

    A5 -->|"HTTP POST /pipeline"| M

    M --> N1
    N1 -->|"NormalizedInput"| R1
    R1 -->|"RiskResult"| P1
    P1 -->|"PolicyResult"| G1

    G1 -->|"Yes"| G2
    G1 -->|"No"| G5
    G2 -->|"Yes"| G3
    G2 -->|"No"| G5
    G3 -->|"ALLOW or SANITIZE"| G4
    G3 -->|"BLOCK/QUARANTINE/REQUIRE_APPROVAL"| G5

    G4 -->|"GatewayResult: EXECUTED"| AU
    G5 -->|"GatewayResult: DENIED"| AU

    AU -->|"PipelineResponse JSON"| A6
    AU -->|"PipelineResponse JSON"| A7

    G4 -.->|"tool_output"| A6
    G5 -.->|"blocked reason"| A7

    A6 -->|"loop back"| A3
    A7 -->|"loop back"| A3

    A8 --> U1

    style USER fill:#2d5a3d,stroke:#4ade80,color:#fff
    style AGENT fill:#1e3a5f,stroke:#60a5fa,color:#fff
    style PIPELINE fill:#3b1f2b,stroke:#f87171,color:#fff
    style S1 fill:#4a3800,stroke:#fbbf24,color:#fff
    style S2 fill:#5a2d00,stroke:#fb923c,color:#fff
    style S3 fill:#5a1a1a,stroke:#f87171,color:#fff
    style S4 fill:#1a3a5a,stroke:#60a5fa,color:#fff
    style S5 fill:#2a2a3a,stroke:#a1a1aa,color:#fff
    style G4 fill:#166534,stroke:#4ade80,color:#fff
    style G5 fill:#7f1d1d,stroke:#f87171,color:#fff
    style LLM fill:#4a1d7a,stroke:#c084fc,color:#fff
```

## Data Model Chain

```mermaid
flowchart LR
    PR["PipelineRequest<br/><i>content, source_type,<br/>proposed_tool, tool_args</i>"]
    NI["NormalizedInput<br/><i>normalized_content,<br/>normalization_notes</i>"]
    RR["RiskResult<br/><i>risk_score, risk_categories,<br/>matched_signals, rationale</i>"]
    PLR["PolicyResult<br/><i>policy_action, policy_reason,<br/>requires_approval</i>"]
    GR["GatewayResult<br/><i>gateway_decision,<br/>decision_reason, tool_output</i>"]
    RESP["PipelineResponse<br/><i>wraps all above +<br/>timestamp + summary</i>"]

    PR -->|"normalizer.normalize()"| NI
    NI -->|"risk_engine.score()"| RR
    RR -->|"policy_engine.decide()"| PLR
    PLR -->|"gateway.mediate()"| GR
    GR --> RESP
    PR -.->|"also passed to gateway"| GR

    style PR fill:#1e3a5f,stroke:#60a5fa,color:#fff
    style NI fill:#4a3800,stroke:#fbbf24,color:#fff
    style RR fill:#5a2d00,stroke:#fb923c,color:#fff
    style PLR fill:#5a1a1a,stroke:#f87171,color:#fff
    style GR fill:#1a3a5a,stroke:#60a5fa,color:#fff
    style RESP fill:#166534,stroke:#4ade80,color:#fff
```

## File Map

```mermaid
flowchart TD
    subgraph ENTRY["Entry Points"]
        EP1["run_agent.py — LLM agent CLI"]
        EP2["uvicorn app.main:app — Pipeline server"]
        EP3["curl / Swagger UI — Direct API testing"]
    end

    subgraph AGENT_MOD["agent/"]
        AM1["config.py — API keys, model, URLs"]
        AM2["tools.py — LLM tool definitions"]
        AM3["loop.py — LLM ↔ pipeline loop"]
    end

    subgraph APP_MOD["app/"]
        AP1["models.py — All Pydantic types"]
        AP2["main.py — FastAPI routes"]
        AP3["ingest/normalizer.py"]
        AP4["risk/engine.py"]
        AP5["policy/engine.py"]
        AP6["gateway/gateway.py"]
        AP7["gateway/gateway_mock.py"]
        AP8["gateway/gateway_real.py"]
        AP9["audit/logger.py"]
    end

    EP1 --> AM3
    AM3 --> AM1
    AM3 --> AM2
    AM3 -->|"HTTP"| AP2
    EP2 --> AP2
    EP3 -->|"HTTP"| AP2
    AP2 --> AP3 --> AP4 --> AP5 --> AP6 --> AP9
    AP6 --> AP7
    AP6 --> AP8
    AP1 -.->|"shared types"| AP3
    AP1 -.->|"shared types"| AP4
    AP1 -.->|"shared types"| AP5
    AP1 -.->|"shared types"| AP6
    AP1 -.->|"shared types"| AP9
```

> **To render:** Open this file in GitHub, VS Code with a Mermaid extension, or paste the code blocks into [mermaid.live](https://mermaid.live).
