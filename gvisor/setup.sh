#!/usr/bin/env bash
# =============================================================================
# setup.sh
# End-to-end setup script: Docker CE → gVisor → register runtime →
# Docker Compose stack → pull model → verify.
#
# Run once from inside WSL (Ubuntu) after cloning the repo.
#
# Usage:
#   bash gvisor/setup.sh
#
# Prerequisites:
#   - WSL 2 with Ubuntu
#   - OLLAMA_API_KEY exported (for cloud models — optional for local inference)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_banner() { echo ""; echo "========================================================"; echo "  $*"; echo "========================================================"; }
_ok()     { echo "  [OK] $*"; }
_skip()   { echo "  [SKIP] $*"; }
_info()   { echo "  >>> $*"; }

_banner "Agentic Security Pipeline — Full Setup"

# --------------------------------------------------------------------------- #
# Step 0 — WSL check
# --------------------------------------------------------------------------- #
if ! grep -qi microsoft /proc/version 2>/dev/null; then
    echo "ERROR: Run this script inside a WSL 2 Ubuntu terminal." >&2
    exit 1
fi
_ok "Running inside WSL 2."

# --------------------------------------------------------------------------- #
# Step 1 — Install Docker CE (idempotent)
# --------------------------------------------------------------------------- #
_banner "Step 1 — Docker CE"
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    _skip "Docker already installed and running: $(docker --version)"
else
    _info "Installing Docker CE..."
    bash "$SCRIPT_DIR/setup-docker.sh"
    echo ""
    echo "  ⚠  IMPORTANT: Close and reopen this Ubuntu terminal so the"
    echo "     docker group membership takes effect, then re-run this script."
    exit 0
fi

# --------------------------------------------------------------------------- #
# Step 2 — Install gVisor (idempotent)
# --------------------------------------------------------------------------- #
_banner "Step 2 — gVisor (runsc)"
if command -v runsc &>/dev/null; then
    _skip "runsc already installed: $(runsc --version | head -1)"
else
    _info "Installing gVisor..."
    bash "$SCRIPT_DIR/setup-gvisor.sh"
fi

# --------------------------------------------------------------------------- #
# Step 3 — Register gVisor with Docker (idempotent)
# --------------------------------------------------------------------------- #
_banner "Step 3 — Register gVisor runtime"
if docker info 2>/dev/null | grep -q "runsc"; then
    _skip "runsc already registered with Docker."
else
    _info "Registering runsc..."
    bash "$SCRIPT_DIR/setup-runtime.sh"
fi
_ok "Docker runtimes: $(docker info 2>/dev/null | grep -A3 "Runtimes:" | tr '\n' ' ')"

# --------------------------------------------------------------------------- #
# Step 4 — Validate OLLAMA_API_KEY (warn only, not required for local models)
# --------------------------------------------------------------------------- #
_banner "Step 4 — Ollama API key"
if [[ -n "${OLLAMA_API_KEY:-}" ]]; then
    _ok "OLLAMA_API_KEY is set (${#OLLAMA_API_KEY} chars)."
else
    echo "  [WARN] OLLAMA_API_KEY is not set."
    echo "         Local models (mistral, qwen2.5:7b) will work."
    echo "         Cloud models (kimi-k2.5:cloud) need a key."
    echo "         Get one at: https://ollama.com/settings/api-keys"
    echo "         Then: export OLLAMA_API_KEY=<your-key>"
fi

# --------------------------------------------------------------------------- #
# Step 5 — Build and start the Docker Compose stack
# --------------------------------------------------------------------------- #
_banner "Step 5 — Start Docker Compose stack"
cd "$REPO_DIR"
_info "Building images and starting services..."
docker compose up --build -d

_info "Waiting for all services to become healthy (up to 90s)..."
TIMEOUT=90
ELAPSED=0
while true; do
    UNHEALTHY=$(docker compose ps --format json 2>/dev/null \
        | python3 -c "
import sys, json
lines = sys.stdin.read().strip()
# compose ps --format json outputs one JSON object per line (not an array)
containers = [json.loads(l) for l in lines.splitlines() if l.strip()]
bad = [c['Name'] for c in containers if c.get('Health','') not in ('healthy','')]
print('\n'.join(bad))
" 2>/dev/null || echo "")
    if [[ -z "$UNHEALTHY" ]]; then
        _ok "All services healthy."
        break
    fi
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo "  [WARN] Some services not yet healthy after ${TIMEOUT}s: $UNHEALTHY"
        echo "         Check logs: docker compose logs <service>"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

docker compose ps

# --------------------------------------------------------------------------- #
# Step 6 — Pull local model (first time only)
# --------------------------------------------------------------------------- #
_banner "Step 6 — Pull local model"
MODEL="${LLM_MODEL:-mistral:latest}"
if docker exec ollama ollama list 2>/dev/null | grep -q "mistral"; then
    _skip "$MODEL already present in ollama_data volume."
else
    _info "Pulling $MODEL into the ollama container..."
    docker exec ollama ollama pull "$MODEL"
    _ok "$MODEL pulled."
fi

# --------------------------------------------------------------------------- #
# Step 7 — Get Ollama SSH public key for cloud model auth
# --------------------------------------------------------------------------- #
_banner "Step 7 — Ollama SSH public key (cloud model auth)"
echo ""
bash "$SCRIPT_DIR/get-ollama-key.sh" ollama
echo ""

# --------------------------------------------------------------------------- #
# Step 8 — Verify pipeline health
# --------------------------------------------------------------------------- #
_banner "Step 8 — Pipeline health check"
_info "Querying http://localhost:8000/health ..."
sleep 2
HEALTH=$(curl -sf http://localhost:8000/health 2>/dev/null || echo "")
if [[ -n "$HEALTH" ]]; then
    echo "$HEALTH" | python3 -m json.tool
    _ok "Pipeline is up."
else
    echo "  [WARN] Pipeline did not respond. Check: docker compose logs pipeline"
fi

# --------------------------------------------------------------------------- #
# Step 9 — Smoke test (local model summarize)
# --------------------------------------------------------------------------- #
_banner "Step 9 — Smoke test"
_info "Sending summarize request to pipeline..."
RESULT=$(curl -sf -X POST http://localhost:8000/pipeline \
    -H "Content-Type: application/json" \
    -d '{
        "request_id": "setup-smoke-test",
        "content": "Summarize this text.",
        "proposed_tool": "summarize",
        "tool_args": {"text": "gVisor intercepts every syscall the containerised process makes and handles it in a user-space kernel. This means a vulnerability in the application cannot directly exploit the Linux kernel."}
    }' 2>/dev/null || echo "")

if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('gateway',{}).get('gateway_decision')=='EXECUTED'" 2>/dev/null; then
    _ok "Smoke test passed — tool_output:"
    echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print('    ' + str(d['gateway']['tool_output'])[:300])"
else
    echo "  [WARN] Smoke test did not get EXECUTED result. Raw response:"
    echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"
    echo ""
    echo "  The model may still be loading. Retry manually:"
    echo "  curl -s -X POST http://localhost:8000/pipeline \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"request_id\":\"test\",\"content\":\"Summarize.\",\"proposed_tool\":\"summarize\",\"tool_args\":{\"text\":\"gVisor is a container sandbox.\"}}' | python3 -m json.tool"
fi

# --------------------------------------------------------------------------- #
# Done
# --------------------------------------------------------------------------- #
_banner "Setup complete"
echo ""
echo "  Pipeline URL  : http://localhost:8000"
echo "  Swagger UI    : http://localhost:8000/docs"
echo "  Ollama URL    : http://localhost:11434"
echo ""
echo "  Useful commands:"
echo "    docker compose ps                  # service status"
echo "    docker logs tool-runner            # gVisor spawn logs"
echo "    docker logs agentic-security-pipeline  # pipeline logs"
echo "    bash gvisor/verify.sh              # verify gVisor Ollama container"
echo "    bash gvisor/teardown.sh            # stop everything (keep models)"
echo "    bash gvisor/teardown.sh --full     # stop + delete models"
echo ""
echo "  Cloud models (after registering SSH key at ollama.com/settings/keys):"
echo "    docker exec ollama ollama run kimi-k2.5:cloud"
echo "========================================================"
