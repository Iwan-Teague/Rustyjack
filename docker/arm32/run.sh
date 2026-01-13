#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=rustyjack/arm32-dev
TARGET=armv7-unknown-linux-gnueabihf

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

# Ensure Docker is running before trying to build or run containers.
ensure_docker_running() {
    if docker info >/dev/null 2>&1; then
        return 0
    fi

    echo "Docker is not running; attempting to start it..."
    case "$(uname -s)" in
        Darwin)
            if command -v open >/dev/null 2>&1; then
                open -a Docker >/dev/null 2>&1 || true
            fi
            ;;
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                systemctl start docker >/dev/null 2>&1 || true
                if ! docker info >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
                    sudo systemctl start docker >/dev/null 2>&1 || true
                fi
            elif command -v service >/dev/null 2>&1; then
                service docker start >/dev/null 2>&1 || true
                if ! docker info >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
                    sudo service docker start >/dev/null 2>&1 || true
                fi
            fi
            ;;
        *)
            ;;
    esac

    for _ in $(seq 1 60); do
        if docker info >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    echo "Docker did not start; please start it manually." >&2
    return 1
}

# Default to bash if no command provided
if [ "$#" -eq 0 ]; then
    set -- bash
fi

# Smart docker build: only rebuild if Dockerfile changed or image doesn't exist
build_docker_image() {
    if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        # Image exists - check if Dockerfile has changed since image was built
        IMAGE_CREATED=$(docker inspect "$IMAGE_NAME" --format='{{.Created}}')
        DOCKERFILE_MODIFIED=$(stat -f%Sm -t '%Y-%m-%d %H:%M:%S' "$DOCKERFILE" 2>/dev/null || stat -c%y "$DOCKERFILE" | cut -d' ' -f1-2)

        if [ "$DOCKERFILE_MODIFIED" -gt "$IMAGE_CREATED" ]; then
            echo "Dockerfile changed; rebuilding docker image..."
            docker build --platform linux/arm/v7 -t "$IMAGE_NAME" "$SCRIPT_DIR"
        else
            echo "Docker image up-to-date (no rebuild needed)"
        fi
    else
        echo "Docker image doesn't exist; building..."
        docker build --platform linux/arm/v7 -t "$IMAGE_NAME" "$SCRIPT_DIR"
    fi
}

ensure_docker_running
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
docker run --rm -it --platform linux/arm/v7 \
    -v "$REPO_ROOT":/work -w /work \
    -e TMPDIR=/work/tmp \
    "${DOCKER_VOLUMES[@]}" \
    "$IMAGE_NAME" \
    "$@"
