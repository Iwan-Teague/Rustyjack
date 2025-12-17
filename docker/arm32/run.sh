#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=rustyjack/arm32-dev

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ "$#" -eq 0 ]; then
    set -- bash
fi

docker build --pull --platform linux/arm/v7 -t "$IMAGE_NAME" "$SCRIPT_DIR"

mkdir -p "$REPO_ROOT/tmp"

docker run --rm -it --platform linux/arm/v7 \
    -v "$REPO_ROOT":/work -w /work \
    -e TMPDIR=/work/tmp \
    "$IMAGE_NAME" \
    "$@"
