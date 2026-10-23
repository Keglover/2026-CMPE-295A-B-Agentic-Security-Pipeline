# Contributing — Agentic Security Pipeline

## Task Tracking

**All tasks live on GitHub Issues**: https://github.com/Keglover/2026-CMPE-295A-B-Agentic-Security-Pipeline/issues

`TASK.md` is a read-only summary maintained by Member A. **Do not edit TASK.md on your branch** — this avoids merge conflicts.

### How issues work

1. Each issue has labels: `member-a`, `member-b`, etc. for assignment
2. When you start work, comment on the issue: "Starting this"
3. When you open a PR, reference the issue: `Closes #1` in the PR description
4. When the PR merges, the issue auto-closes

### Quick commands

```bash
# See all open issues assigned to you
gh issue list --label "member-b"

# See all Sprint 2 issues
gh issue list --label "sprint-2"

# Close an issue when done
gh issue close 1
```

---

## Branch Strategy

We use **feature branches** off `main`. Each person works in their own branch on their own files, then merges via pull request.

```
main  ─────●────────●────────●────────●──── (always deployable)
            \      / \      / \      /
             \    /   \    /   \    /
  feat/agent-llm-integration   (Member A)
  feat/gateway-approval        (Member C)
  feat/risk-rules              (Member B)
  feat/eval-scenarios          (Member D)
```

## Branch Assignments

| Branch | Owner | Files Touched | GitHub Issues |
|--------|-------|---------------|---------------|
| `feat/agent-llm-integration` | Member A | `agent/`, `run_agent.py`, `requirements.txt` | [#5](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/5), [#6](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/6) |
| `feat/gateway-approval` | Member C | `app/main.py`, `app/models.py`, `app/gateway/gateway_real.py`, `tests/` | [#3](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/3), [#4](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/4), [#7](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/7) |
| `feat/risk-rules` | Member B | `app/risk/engine.py`, `tests/test_risk.py` | [#1](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/1) |
| `feat/eval-scenarios` | Member D | `scenarios/`, `run_scenarios.py` | [#2](https://github.com/razzacktiger/Agentic-Security-Pipeline/issues/2) |

## Getting Started

### 1. Clone and set up

```bash
git clone https://github.com/razzacktiger/Agentic-Security-Pipeline.git
cd Agentic-Security-Pipeline/mvp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Create your branch

```bash
git checkout main
git pull origin main
git checkout -b feat/your-branch-name
```

### 3. Work on your files

Make changes, test locally, commit often with clear messages.

### 4. Run tests before pushing

```bash
# Always run the full test suite before pushing
source .venv/bin/activate
pytest tests/ -v

# All 35+ tests must pass
```

### 5. Push and open a PR

```bash
git add .
git commit -m "feat: description of what you did"
git push -u origin feat/your-branch-name
```

Then go to GitHub and open a Pull Request to `main`.
- Reference the issue in the PR body: `Closes #3`
- Tag Member A (Haroon) for review

### 6. After your PR is merged

Switch back to main and pull the latest:

```bash
git checkout main
git pull origin main
```

If you're continuing work on the same branch:

```bash
git checkout feat/your-branch-name
git pull origin main
```

## Commit Message Format

Keep it simple and consistent:

```
feat: add 5 new risk detection rules
fix: handle missing tool_args in gateway
test: add e2e test for approval endpoint
docs: update TASK.md with gate progress
```

Prefix with `feat:`, `fix:`, `test:`, or `docs:`.

## Running the Project Locally

You need **two terminals** to test the full flow:

```bash
# Terminal 1 — Start the pipeline server
cd mvp
source .venv/bin/activate
uvicorn app.main:app --reload

# Terminal 2 — Run the agent (requires OPENAI_API_KEY)
cd mvp
source .venv/bin/activate
export OPENAI_API_KEY="sk-your-key"
python3 run_agent.py -v
```

To run tests only (no API key needed):

```bash
cd mvp
source .venv/bin/activate
pytest tests/ -v
```

## File Ownership — Who Edits What

This matters to avoid merge conflicts. Stick to your assigned files:

```
Member A (architect):
  agent/*              ← LLM integration
  run_agent.py         ← CLI entry point
  requirements.txt     ← dependencies
  TASK.md              ← gate tracking
  SPRINT2_GAMEPLAN.md  ← coordination

Member B (risk rules):
  app/risk/engine.py   ← add new Rule() entries
  tests/test_risk.py   ← one test per new rule

Member C (gateway/API):
  app/main.py          ← new endpoints (/approve, /history)
  app/models.py        ← new Pydantic models (ApprovalResponse, AuditEntry)
  tests/test_e2e.py    ← endpoint tests

Member D (scenarios):
  scenarios/*           ← payloads and runner
  run_scenarios.py      ← evaluation script
```

If you need to edit a file outside your area, **check with the owner first** to avoid conflicts.

## Resolving Merge Conflicts

If you get a conflict when merging main into your branch:

```bash
git pull origin main
# If conflict appears:
# 1. Open the conflicted file
# 2. Look for <<<<<<< and >>>>>>> markers
# 3. Keep the right version, remove the markers
# 4. git add the fixed file
# 5. git commit
```

Ask in the group chat before resolving conflicts in files you don't own.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `OPENAI_API_KEY` | For agent only | — | LLM API key |
| `OPENAI_BASE_URL` | No | OpenAI default | Override for Qwen/Ollama/Together AI |
| `AGENT_MODEL` | No | `gpt-4o-mini` | Which model the agent uses |
| `PIPELINE_URL` | No | `http://localhost:8000/pipeline` | Pipeline server address |
| `REAL_TOOLS` | No | `false` | Use real tool executors (Docker only) |
| `AUDIT_LOG_PATH` | No | `audit_logs/audit.ndjson` | Where audit logs are written |

## Definition of Done (for PRs)

Before opening a PR, confirm:

- [ ] All existing tests still pass (`pytest tests/ -v`)
- [ ] New tests added for new functionality
- [ ] No hardcoded API keys or secrets in code
- [ ] Commit messages follow the format above
- [ ] PR description references the issue (`Closes #N`)
- [ ] Do NOT edit TASK.md — Member A handles it
