#!/usr/bin/env bash
# =============================================================================
# run-ollama.sh
# Pulls the official Ollama image and launches it inside a gVisor-sandboxed
# container. The Ollama API key is read from ollama.env — never hardcoded.
#
# Prerequisites: setup-docker.sh, setup-gvisor.sh, setup-runtime.sh all done.
# Usage: bash run-ollama.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/ollama.env"
CONTAINER_NAME="ollama-secure"
HOST_PORT="11434"
VOLUME_NAME="ollama_data"

# --------------------------------------------------------------------------- #
# 1. Validate environment file exists and key has been set
# --------------------------------------------------------------------------- #
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found." >&2
  echo "       Copy ollama.env.template to ollama.env and set:" >&2
  echo "       OLLAMA_API_KEY=<your-key>" >&2
  exit 1
fi

# Warn if the placeholder value is still present
if grep -q "your_key_here" "$ENV_FILE"; then
  echo "ERROR: ollama.env still contains the placeholder value 'your_key_here'." >&2
  echo "       Edit ollama.env and set OLLAMA_API_KEY to your actual Ollama API key." >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 2. Check that the runsc runtime is available
# --------------------------------------------------------------------------- #
if ! docker info 2>/dev/null | grep -q "runsc"; then
  echo "ERROR: runsc runtime is not registered with Docker." >&2
  echo "       Run setup-runtime.sh first." >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 3. Remove any existing container with the same name (idempotent re-runs)
# --------------------------------------------------------------------------- #
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo ">>> Stopping and removing existing '$CONTAINER_NAME' container..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  docker rm   "$CONTAINER_NAME" 2>/dev/null || true
fi

# --------------------------------------------------------------------------- #
# 4. Pull the latest official Ollama image
# --------------------------------------------------------------------------- #
echo ">>> Pulling ollama/ollama image..."
docker pull ollama/ollama:latest

# --------------------------------------------------------------------------- #
# 5. Launch Ollama inside a gVisor sandbox
#    --runtime=runsc      : enforce gVisor syscall sandbox
#    --env-file           : inject API key without exposing it in CLI history
#    -v ollama_data       : persist downloaded models across restarts
#    --security-opt       : drop all Linux capabilities and apply no-new-privs
# --------------------------------------------------------------------------- #
echo ">>> Starting Ollama container with gVisor runtime..."
docker run -d \
  --runtime=runsc \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${HOST_PORT}:11434" \
  --env-file "$ENV_FILE" \
  -v "${VOLUME_NAME}:/root/.ollama" \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  ollama/ollama:latest

# --------------------------------------------------------------------------- #
# 6. Wait for the Ollama HTTP server to be ready (up to 30 s)
# --------------------------------------------------------------------------- #
echo ">>> Waiting for Ollama API to become ready..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:${HOST_PORT}/api/version > /dev/null 2>&1; then
    echo "    [OK] Ollama is up."
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "    [WARNING] Ollama did not respond within 30 s. Check logs:"
    echo "    docker logs $CONTAINER_NAME"
    exit 1
  fi
  sleep 1
done

echo ""
echo "========================================================"
echo "Ollama is running securely inside a gVisor sandbox."
echo ""
echo "  Container : $CONTAINER_NAME"
echo "  Runtime   : runsc (gVisor)"
echo "  API URL   : http://localhost:${HOST_PORT}"
echo ""
echo "Run 'bash verify.sh' to confirm the API is responding."
echo "========================================================"
