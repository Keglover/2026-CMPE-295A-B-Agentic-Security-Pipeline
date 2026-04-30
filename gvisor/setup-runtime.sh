#!/usr/bin/env bash
# =============================================================================
# setup-runtime.sh
# Registers gVisor (runsc) as a Docker runtime and restarts the Docker daemon.
# Run AFTER setup-gvisor.sh from your Ubuntu WSL terminal.
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------------------- #
# 1. Sanity checks
# --------------------------------------------------------------------------- #
if ! grep -qi microsoft /proc/version 2>/dev/null; then
  echo "ERROR: This script must be run inside a WSL 2 Ubuntu terminal." >&2
  exit 1
fi

if ! command -v runsc &>/dev/null; then
  echo "ERROR: runsc not found in PATH. Run setup-gvisor.sh first." >&2
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker not found. Run setup-docker.sh first." >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 2. Register runsc as a Docker runtime
#    'runsc install' writes the runtime entry into /etc/docker/daemon.json
# --------------------------------------------------------------------------- #
echo ">>> Registering runsc runtime with Docker..."
sudo /usr/local/bin/runsc install

# --------------------------------------------------------------------------- #
# 3. Restart Docker to pick up the new runtime configuration
# --------------------------------------------------------------------------- #
echo ">>> Restarting Docker daemon..."
sudo service docker restart

# Wait briefly for the daemon to be ready before checking
sleep 2

# --------------------------------------------------------------------------- #
# 4. Confirm runtime is listed
# --------------------------------------------------------------------------- #
echo ">>> Checking registered Docker runtimes..."
if docker info 2>/dev/null | grep -q "runsc"; then
  echo "    [OK] runsc runtime is registered."
else
  echo "    [WARNING] runsc not found in 'docker info'. Check /etc/docker/daemon.json manually."
fi

echo ""
echo "========================================================"
echo "gVisor runtime registered with Docker."
echo ""
echo "Next steps:"
echo "  1. Edit ollama.env and replace 'your_key_here' with your Ollama API key."
echo "  2. bash run-ollama.sh"
echo "========================================================"
