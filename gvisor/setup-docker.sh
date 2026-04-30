#!/usr/bin/env bash
# =============================================================================
# setup-docker.sh
# Installs Docker CE natively inside WSL 2 (Ubuntu).
# Run this script ONCE from your Ubuntu WSL terminal.
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------------------- #
# 1. Check we are running inside WSL
# --------------------------------------------------------------------------- #
if ! grep -qi microsoft /proc/version 2>/dev/null; then
  echo "ERROR: This script must be run inside a WSL 2 Ubuntu terminal." >&2
  exit 1
fi

# --------------------------------------------------------------------------- #
# 2. Remove any old / conflicting Docker packages
# --------------------------------------------------------------------------- #
echo ">>> Removing legacy Docker packages (if any)..."
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  sudo apt-get remove -y "$pkg" 2>/dev/null || true
done

# --------------------------------------------------------------------------- #
# 3. Install apt prerequisites
# --------------------------------------------------------------------------- #
echo ">>> Installing prerequisites..."
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# --------------------------------------------------------------------------- #
# 4. Add Docker's official GPG key (trusted, pinned keyring)
# --------------------------------------------------------------------------- #
echo ">>> Adding Docker GPG key..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# --------------------------------------------------------------------------- #
# 5. Add Docker apt repository
# --------------------------------------------------------------------------- #
echo ">>> Adding Docker apt repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# --------------------------------------------------------------------------- #
# 6. Install Docker Engine
# --------------------------------------------------------------------------- #
echo ">>> Installing Docker CE..."
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

# --------------------------------------------------------------------------- #
# 7. Start Docker daemon and add current user to docker group
# --------------------------------------------------------------------------- #
echo ">>> Starting Docker daemon..."
sudo service docker start

echo ">>> Adding $USER to the docker group..."
sudo usermod -aG docker "$USER"

# --------------------------------------------------------------------------- #
# 8. Smoke test
# --------------------------------------------------------------------------- #
echo ">>> Verifying Docker installation..."
sudo docker run --rm hello-world

echo ""
echo "========================================================"
echo "Docker CE installed successfully."
echo "IMPORTANT: Close and reopen your Ubuntu terminal so that"
echo "the docker group membership takes effect, then continue"
echo "with: bash setup-gvisor.sh"
echo "========================================================"
