#!/usr/bin/env bash
set -euo pipefail

# Build Rustyjack for 64-bit ARM (Pi Zero 2 W on 64-bit Pi OS / other ARM64 Pis) inside the arm64 container.
# Requires Docker Desktop with binfmt/qemu enabled.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

./docker/arm64/run.sh env CARGO_TARGET_DIR=/work/target-64 cargo build --target aarch64-unknown-linux-gnu -p rustyjack-ui
