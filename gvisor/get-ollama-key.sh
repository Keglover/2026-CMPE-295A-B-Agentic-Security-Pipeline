#!/usr/bin/env bash
# =============================================================================
# get-ollama-key.sh
#
# Extracts the Ollama SSH public key from a running container and prints
# step-by-step instructions for registering it at ollama.com/settings/keys.
#
# This key authenticates the Ollama *daemon* to the Ollama Cloud registry,
# which is required for cloud-routed models (e.g. kimi-k2.5:cloud).
# It is separate from OLLAMA_API_KEY (the HTTP Bearer token for app requests).
#
# Key persistence:
#   The key lives in /root/.ollama/id_ed25519{,.pub} inside the container.
#   Both the compose 'ollama' service and the standalone 'ollama-secure'
#   container mount a named Docker volume (ollama_data) at /root/.ollama.
#   As long as the volume is not destroyed, the registered key survives
#   container stops, restarts, and image upgrades.
#
# Usage:
#   bash get-ollama-key.sh                   # auto-detects running container
#   bash get-ollama-key.sh ollama            # target compose service container
#   bash get-ollama-key.sh ollama-secure     # target standalone gVisor container
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------------------- #
# 1. Determine target container
# --------------------------------------------------------------------------- #
CONTAINER="${1:-}"

if [[ -z "$CONTAINER" ]]; then
  # Auto-detect: prefer compose service, fall back to standalone
  if docker ps --format '{{.Names}}' | grep -q "^ollama$"; then
    CONTAINER="ollama"
  elif docker ps --format '{{.Names}}' | grep -q "^ollama-secure$"; then
    CONTAINER="ollama-secure"
  else
    echo "ERROR: No running Ollama container found." >&2
    echo "       Start one with 'docker compose up -d' or 'bash run-ollama.sh'." >&2
    exit 1
  fi
fi

echo ">>> Target container: $CONTAINER"
echo ""

# Confirm it is running
STATUS=$(docker inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "not_found")
if [[ "$STATUS" != "running" ]]; then
  echo "ERROR: Container '$CONTAINER' is not running (status: $STATUS)." >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 2. Retrieve or generate the SSH public key
# --------------------------------------------------------------------------- #
KEY_PATH="/root/.ollama/id_ed25519.pub"
PUBKEY=$(docker exec "$CONTAINER" cat "$KEY_PATH" 2>/dev/null || echo "")

if [[ -z "$PUBKEY" ]]; then
  echo ">>> SSH key not found — triggering key generation..."
  echo "    (Ollama generates the key on first 'ollama signin' or model pull)"
  echo ""
  # Pulling a local model is the easiest way to force key generation
  docker exec "$CONTAINER" ollama list > /dev/null 2>&1 || true
  # Try once more
  PUBKEY=$(docker exec "$CONTAINER" cat "$KEY_PATH" 2>/dev/null || echo "")
fi

if [[ -z "$PUBKEY" ]]; then
  echo ">>> Key still not present. Running 'ollama signin' to force generation..."
  echo "    (You can Ctrl-C after the key appears — no credentials needed)"
  echo ""
  docker exec -it "$CONTAINER" ollama signin 2>/dev/null || true
  PUBKEY=$(docker exec "$CONTAINER" cat "$KEY_PATH" 2>/dev/null || echo "")
fi

if [[ -z "$PUBKEY" ]]; then
  echo "ERROR: Could not retrieve SSH public key from '$CONTAINER'." >&2
  echo "       Try: docker exec -it $CONTAINER cat $KEY_PATH" >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 3. Display the key and registration instructions
# --------------------------------------------------------------------------- #
echo "========================================================"
echo "  Ollama SSH Public Key"
echo "========================================================"
echo ""
echo "$PUBKEY"
echo ""
echo "========================================================"
echo "  How to register this key (one-time per volume)"
echo "========================================================"
echo ""
echo "  1. Copy the full key above (starts with 'ssh-ed25519 AAAA...')"
echo "  2. Open: https://ollama.com/settings/keys"
echo "  3. Click 'Add Key', paste the key, save."
echo ""
echo "  Once registered, the Ollama daemon inside '$CONTAINER' can"
echo "  authenticate to Ollama Cloud and run cloud-routed models"
echo "  such as kimi-k2.5:cloud."
echo ""
echo "========================================================"
echo "  Key persistence"
echo "========================================================"
echo ""
echo "  The key pair is stored in the 'ollama_data' Docker volume:"
echo "    /root/.ollama/id_ed25519      (private — never leave container)"
echo "    /root/.ollama/id_ed25519.pub  (public  — register at ollama.com)"
echo ""
echo "  The key survives 'docker stop', 'docker rm', and image upgrades"
echo "  as long as you do NOT run 'docker volume rm ollama_data'."
echo "  If you destroy the volume, a new key is generated and you must"
echo "  repeat Steps 1-3 above."
echo ""
echo "========================================================"
echo "  Test with a cloud model"
echo "========================================================"
echo ""
echo "  docker exec $CONTAINER ollama run kimi-k2.5:cloud"
echo ""
echo "  Or via the pipeline API (after setting OLLAMA_API_KEY):"
echo "  curl -s -X POST http://localhost:8000/pipeline \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"request_id\":\"cloud-test\",\"content\":\"Summarize gVisor security.\",\"proposed_tool\":\"summarize\",\"tool_args\":{\"text\":\"gVisor uses a user-space kernel to intercept syscalls.\"}}'"
echo "========================================================"
