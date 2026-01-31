#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=rustyjack/arm64-dev
TARGET=aarch64-unknown-linux-gnu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

# Default to bash if no command provided
if [ "$#" -eq 0 ]; then
    set -- bash
fi

# Smart docker build: only rebuild if Dockerfile changed or image doesn't exist
build_docker_image() {
    if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        # Image exists - check if Dockerfile has changed since image was built
        IMAGE_CREATED_RAW=$(docker inspect "$IMAGE_NAME" --format='{{.Created}}')
        DOCKERFILE_MODIFIED_EPOCH=$(stat -f%m "$DOCKERFILE" 2>/dev/null || stat -c%Y "$DOCKERFILE")

        parse_epoch() {
            local raw="$1"
            local trimmed="${raw%%.*}"
            trimmed="${trimmed%Z}"
            date -u -d "$raw" +%s 2>/dev/null \
                || date -u -d "$trimmed" +%s 2>/dev/null \
                || date -u -j -f "%Y-%m-%dT%H:%M:%S" "$trimmed" +%s 2>/dev/null
        }

        IMAGE_CREATED_EPOCH=$(parse_epoch "$IMAGE_CREATED_RAW")

        if [ -z "$IMAGE_CREATED_EPOCH" ] || [ -z "$DOCKERFILE_MODIFIED_EPOCH" ]; then
            echo "Timestamp parse failed; rebuilding docker image..."
            docker build --platform linux/arm64 -t "$IMAGE_NAME" "$SCRIPT_DIR"
        elif [ "$DOCKERFILE_MODIFIED_EPOCH" -gt "$IMAGE_CREATED_EPOCH" ]; then
            echo "Dockerfile changed; rebuilding docker image..."
            docker build --platform linux/arm64 -t "$IMAGE_NAME" "$SCRIPT_DIR"
        else
            echo "Docker image up-to-date (no rebuild needed)"
        fi
    else
        echo "Docker image doesn't exist; building..."
        docker build --platform linux/arm64 -t "$IMAGE_NAME" "$SCRIPT_DIR"
    fi
}

build_docker_image

mkdir -p "$REPO_ROOT/tmp"

# Parse volume mounts from environment variable or arguments
DOCKER_VOLUMES=()

# Check if DOCKER_VOLUMES_EXTRA env var is set (for passing additional mounts)
if [ -n "${DOCKER_VOLUMES_EXTRA:-}" ]; then
    while IFS= read -r vol; do
        [ -n "$vol" ] && DOCKER_VOLUMES+=(-v "$vol")
    done <<< "$DOCKER_VOLUMES_EXTRA"
fi

# Run docker with base and optional additional volumes
docker run --rm -it --platform linux/arm64 \
    -v "$REPO_ROOT":/work -w /work \
    -e TMPDIR=/work/tmp \
    "${DOCKER_VOLUMES[@]}" \
    "$IMAGE_NAME" \
    "$@"
