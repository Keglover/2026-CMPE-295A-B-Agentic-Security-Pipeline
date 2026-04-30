#!/usr/bin/env bash
# =============================================================================
# setup-gvisor.sh
# Downloads, verifies (sha512), and installs the gVisor container runtime
# (runsc) and the containerd shim inside WSL 2.
# Run AFTER setup-docker.sh from your Ubuntu WSL terminal.
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
# 2. Detect CPU architecture
# --------------------------------------------------------------------------- #
ARCH=$(uname -m)

# gVisor ships as x86_64 and aarch64 builds
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
  echo "ERROR: Unsupported architecture: $ARCH" >&2
  exit 1
fi

echo ">>> Detected architecture: $ARCH"

# --------------------------------------------------------------------------- #
# 3. Download gVisor binaries and checksums into a temp directory
# --------------------------------------------------------------------------- #
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT   # always clean up temp files on exit

BASE_URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"

echo ">>> Downloading gVisor binaries from: $BASE_URL"
(
  cd "$TMPDIR"
  wget -q --show-progress \
    "${BASE_URL}/runsc" \
    "${BASE_URL}/runsc.sha512" \
    "${BASE_URL}/containerd-shim-runsc-v1" \
    "${BASE_URL}/containerd-shim-runsc-v1.sha512"
)

# --------------------------------------------------------------------------- #
# 4. Verify checksums BEFORE installing anything
# --------------------------------------------------------------------------- #
echo ">>> Verifying sha512 checksums..."
(
  cd "$TMPDIR"
  sha512sum -c runsc.sha512
  sha512sum -c containerd-shim-runsc-v1.sha512
)
echo ">>> Checksums verified OK."

# --------------------------------------------------------------------------- #
# 5. Set permissions and install
# --------------------------------------------------------------------------- #
echo ">>> Installing runsc and containerd-shim-runsc-v1 to /usr/local/bin..."
chmod a+rx "$TMPDIR/runsc" "$TMPDIR/containerd-shim-runsc-v1"
sudo mv "$TMPDIR/runsc" /usr/local/bin/runsc
sudo mv "$TMPDIR/containerd-shim-runsc-v1" /usr/local/bin/containerd-shim-runsc-v1

# --------------------------------------------------------------------------- #
# 6. Confirm installation
# --------------------------------------------------------------------------- #
echo ">>> gVisor version:"
/usr/local/bin/runsc --version

echo ""
echo "========================================================"
echo "gVisor (runsc) installed successfully."
echo "Next step: bash setup-runtime.sh"
echo "========================================================"
