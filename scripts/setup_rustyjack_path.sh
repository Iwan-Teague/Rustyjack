#!/usr/bin/env bash
#
# Ensure rustyjack-core is installed on PATH and exported with the desired root.
# Usage: sudo ./scripts/setup_rustyjack_path.sh [/root/Raspyjack]
set -euo pipefail

ROOT="${1:-/root/Raspyjack}"
CORE_DIR="$ROOT/rustyjack-core"
TARGET_BIN="$CORE_DIR/target/release/rustyjack-core"

step() { printf "\e[1;34m[STEP]\e[0m %s\n" "$*"; }
info() { printf "\e[1;32m[INFO]\e[0m %s\n" "$*"; }
warn() { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
fail() { printf "\e[1;31m[FAIL]\e[0m %s\n" "$*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  fail "Please run this script as root (sudo)."
fi

if [[ ! -d $CORE_DIR ]]; then
  fail "Rustyjack core directory not found at $CORE_DIR"
fi

if ! command -v cargo >/dev/null 2>&1; then
  warn "cargo not found – assuming rustyjack-core is already built"
else
  step "Building rustyjack-core (release)…"
  (cd "$CORE_DIR" && cargo build --release)
fi

if [[ ! -x $TARGET_BIN ]]; then
  fail "rustyjack-core binary not found at $TARGET_BIN"
fi

step "Installing rustyjack-core to /usr/local/bin …"
install -Dm755 "$TARGET_BIN" /usr/local/bin/rustyjack-core

ENV_FILE="/etc/profile.d/rustyjack.sh"
step "Writing environment export to $ENV_FILE"
cat >"$ENV_FILE" <<EOF
# Added by setup_rustyjack_path.sh
export RUSTYJACK_ROOT="$ROOT"
export PATH="/usr/local/bin:\$PATH"
EOF

info "PATH helper installed. New shells will pick up rustyjack-core automatically."
