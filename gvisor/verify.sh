#!/usr/bin/env bash
# =============================================================================
# verify.sh
# Confirms the Ollama container is running inside the gVisor sandbox and
# that its HTTP API is reachable on localhost.
# Usage: bash verify.sh
# =============================================================================
set -euo pipefail

CONTAINER_NAME="ollama-secure"
HOST_PORT="11434"
API_BASE="http://localhost:${HOST_PORT}"

# --------------------------------------------------------------------------- #
# 1. Container is running
# --------------------------------------------------------------------------- #
echo ">>> Checking container status..."
STATUS=$(docker inspect --format '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not_found")
if [[ "$STATUS" != "running" ]]; then
  echo "  [FAIL] Container '$CONTAINER_NAME' is not running (status: $STATUS)." >&2
  echo "         Run 'bash run-ollama.sh' to start it." >&2
  exit 1
fi
echo "  [OK] Container '$CONTAINER_NAME' is running."

# --------------------------------------------------------------------------- #
# 2. Container is using the runsc (gVisor) runtime
# --------------------------------------------------------------------------- #
echo ">>> Checking container runtime..."
RUNTIME=$(docker inspect --format '{{.HostConfig.Runtime}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
if [[ "$RUNTIME" != "runsc" ]]; then
  echo "  [FAIL] Container is NOT using gVisor. Detected runtime: '$RUNTIME'." >&2
  exit 1
fi
echo "  [OK] Container runtime is: $RUNTIME (gVisor enforced)."

# --------------------------------------------------------------------------- #
# 3. Ollama API responds
# --------------------------------------------------------------------------- #
echo ">>> Querying Ollama API version endpoint..."
RESPONSE=$(curl -sf "${API_BASE}/api/version" 2>/dev/null || echo "")
if [[ -z "$RESPONSE" ]]; then
  echo "  [FAIL] No response from ${API_BASE}/api/version." >&2
  echo "         Check logs: docker logs $CONTAINER_NAME" >&2
  exit 1
fi
echo "  [OK] API response: $RESPONSE"

# --------------------------------------------------------------------------- #
# 4. List locally available models
# --------------------------------------------------------------------------- #
echo ">>> Listing locally available models..."
MODELS=$(curl -sf "${API_BASE}/api/tags" 2>/dev/null || echo "")
if [[ -n "$MODELS" ]]; then
  echo "  $MODELS"
else
  echo "  (no models pulled yet — use 'docker exec ollama-secure ollama pull <model>')"
fi

echo ""
echo "========================================================"
echo "All checks passed. Ollama is running securely with gVisor."
echo "========================================================"
