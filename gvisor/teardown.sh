#!/usr/bin/env bash
# =============================================================================
# teardown.sh
# Stops and removes all containers, networks, images, and volumes created by
# this project. Run from inside WSL.
#
# Usage:
#   bash teardown.sh            # removes containers + networks (keeps model volume)
#   bash teardown.sh --full     # also removes ollama_data volume (deletes models)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
FULL="${1:-}"

echo ""
echo "========================================================"
echo "  Agentic Security Pipeline — Teardown"
echo "========================================================"
echo ""

# --------------------------------------------------------------------------- #
# 1. Stop and remove the standalone gVisor Ollama container (if running)
# --------------------------------------------------------------------------- #
if docker ps -a --format '{{.Names}}' | grep -q "^ollama-secure$"; then
    echo ">>> Stopping standalone gVisor Ollama container (ollama-secure)..."
    docker stop ollama-secure 2>/dev/null || true
    docker rm   ollama-secure 2>/dev/null || true
    echo "    [OK] ollama-secure removed."
else
    echo "    [SKIP] ollama-secure not found."
fi

# --------------------------------------------------------------------------- #
# 2. Bring down the Docker Compose stack
# --------------------------------------------------------------------------- #
echo ""
echo ">>> Tearing down Docker Compose stack..."
cd "$REPO_DIR"

if [[ "$FULL" == "--full" ]]; then
    echo "    --full flag set: removing volumes (ollama_data will be deleted)."
    docker compose down --volumes --remove-orphans
    echo "    [OK] Compose stack + volumes removed."
else
    docker compose down --remove-orphans
    echo "    [OK] Compose stack removed (ollama_data volume preserved)."
fi

# --------------------------------------------------------------------------- #
# 3. Remove project Docker images
# --------------------------------------------------------------------------- #
echo ""
echo ">>> Removing project Docker images..."
IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep "2026-cmpe-295a-b-agentic-security-pipeline" || true)
if [[ -n "$IMAGES" ]]; then
    echo "$IMAGES" | xargs docker rmi -f 2>/dev/null || true
    echo "    [OK] Project images removed."
else
    echo "    [SKIP] No project images found."
fi

# Also remove the tool image used by the tool-runner
if docker images --format "{{.Repository}}" | grep -q "^agentic-security-tool-image$"; then
    docker rmi -f agentic-security-tool-image 2>/dev/null || true
    echo "    [OK] agentic-security-tool-image removed."
fi

# --------------------------------------------------------------------------- #
# 4. Remove dangling build cache (optional, keeps disk tidy)
# --------------------------------------------------------------------------- #
echo ""
echo ">>> Pruning dangling build cache..."
docker builder prune -f --filter "until=1h" 2>/dev/null || true
echo "    [OK] Build cache pruned."

# --------------------------------------------------------------------------- #
# 5. Summary
# --------------------------------------------------------------------------- #
echo ""
echo "========================================================"
echo "  Teardown complete."
echo ""
if [[ "$FULL" == "--full" ]]; then
    echo "  ⚠  ollama_data volume deleted — models must be re-pulled on next start."
else
    echo "  ✓  ollama_data volume preserved — models will be available on next start."
    echo "     To also remove the volume (and models): bash teardown.sh --full"
fi
echo ""
echo "  To set up again:  bash gvisor/setup.sh"
echo "========================================================"
