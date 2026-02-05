#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Not inside a git work tree: $REPO_ROOT" >&2
    exit 1
fi

current_hooks="$(git -C "$REPO_ROOT" config --local --get core.hooksPath 2>/dev/null || true)"
if [ "$current_hooks" = ".githooks" ]; then
    exit 0
fi

git -C "$REPO_ROOT" config core.hooksPath .githooks

echo "Configured git to use .githooks for this repository."
