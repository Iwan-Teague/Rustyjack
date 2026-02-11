#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=rustyjack/arm64-dev
TARGET=aarch64-unknown-linux-gnu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKERFILE="$SCRIPT_DIR/Dockerfile"

docker_socket_path() {
    if [[ "${DOCKER_HOST:-}" == unix://* ]]; then
        printf '%s\n' "${DOCKER_HOST#unix://}"
        return 0
    fi
    if [ -S "$HOME/.docker/run/docker.sock" ]; then
        printf '%s\n' "$HOME/.docker/run/docker.sock"
        return 0
    fi
    if [ -S "/var/run/docker.sock" ]; then
        printf '%s\n' "/var/run/docker.sock"
        return 0
    fi
    return 1
}

docker_daemon_ready_via_socket() {
    local sock
    sock="$(docker_socket_path)" || return 1
    command -v curl >/dev/null 2>&1 || return 1
    [ -S "$sock" ] || return 1
    local resp
    resp="$(curl --silent --show-error --max-time 2 --unix-socket "$sock" http://docker/_ping 2>/dev/null || true)"
    [ "$resp" = "OK" ]
}

docker_daemon_ready_via_cli() {
    command -v docker >/dev/null 2>&1 || return 1

    local out_file
    out_file="$(mktemp)"
    docker version --format '{{.Server.Version}}' >"$out_file" 2>/dev/null &
    local pid="$!"
    local waited=0
    local timeout_secs=3

    while kill -0 "$pid" >/dev/null 2>&1; do
        if [ "$waited" -ge "$timeout_secs" ]; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
            rm -f "$out_file"
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done

    if ! wait "$pid" >/dev/null 2>&1; then
        rm -f "$out_file"
        return 1
    fi

    local version
    version="$(tr -d '\r\n[:space:]' < "$out_file" 2>/dev/null || true)"
    rm -f "$out_file"
    [ -n "$version" ]
}

docker_daemon_ready() {
    docker_daemon_ready_via_socket || docker_daemon_ready_via_cli
}

# Ensure Docker is running before trying to build or run containers.
ensure_docker_running() {
    if docker_daemon_ready; then
        return 0
    fi

    echo "Docker is not running; attempting to start it..."
    case "$(uname -s)" in
        Darwin)
            if command -v open >/dev/null 2>&1; then
                open -a Docker >/dev/null 2>&1 || true
                echo "Requested Docker Desktop startup."
            fi
            ;;
        Linux)
            if command -v systemctl >/dev/null 2>&1; then
                systemctl start docker >/dev/null 2>&1 || true
                if ! docker_daemon_ready && command -v sudo >/dev/null 2>&1; then
                    sudo systemctl start docker >/dev/null 2>&1 || true
                fi
            elif command -v service >/dev/null 2>&1; then
                service docker start >/dev/null 2>&1 || true
                if ! docker_daemon_ready && command -v sudo >/dev/null 2>&1; then
                    sudo service docker start >/dev/null 2>&1 || true
                fi
            fi
            ;;
        *)
            ;;
    esac

    for second in $(seq 1 60); do
        if docker_daemon_ready; then
            echo "Docker daemon is ready."
            return 0
        fi
        if [ "$second" -eq 1 ] || [ $((second % 5)) -eq 0 ]; then
            echo "Waiting for Docker daemon... (${second}s/60s)"
        fi
        sleep 1
    done

    echo "Docker did not start; please start it manually." >&2
    return 1
}

run_with_heartbeat() {
    local label="$1"
    shift

    local started_at
    started_at="$(date +%s)"
    local interval="${DOCKER_BUILD_HEARTBEAT_SECS:-15}"
    local cmd_pid=""
    local ticker_pid=""
    local status=0

    "$@" &
    cmd_pid="$!"

    (
        while kill -0 "$cmd_pid" >/dev/null 2>&1; do
            sleep "$interval"
            if ! kill -0 "$cmd_pid" >/dev/null 2>&1; then
                break
            fi
            local now elapsed mins secs
            now="$(date +%s)"
            elapsed=$((now - started_at))
            mins=$((elapsed / 60))
            secs=$((elapsed % 60))
            echo "[$label] still running (${mins}m${secs}s elapsed)..."
        done
    ) &
    ticker_pid="$!"

    if wait "$cmd_pid"; then
        status=0
    else
        status=$?
    fi

    kill "$ticker_pid" >/dev/null 2>&1 || true
    wait "$ticker_pid" >/dev/null 2>&1 || true
    return "$status"
}

docker_build_image() {
    local -a args
    args=(--platform linux/arm64 -t "$IMAGE_NAME" "$SCRIPT_DIR")

    # With buildx docker-container builders, --load is required so the image
    # is available to `docker run` after the build completes.
    if docker build --help 2>/dev/null | grep -q -- '--load'; then
        args=(--load "${args[@]}")
    fi

    if docker build --help 2>/dev/null | grep -q -- '--progress'; then
        args=(--progress "${DOCKER_BUILD_PROGRESS:-plain}" "${args[@]}")
    fi

    run_with_heartbeat "docker build" docker build "${args[@]}"
}

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
            docker_build_image
        elif [ "$DOCKERFILE_MODIFIED_EPOCH" -gt "$IMAGE_CREATED_EPOCH" ]; then
            echo "Dockerfile changed; rebuilding docker image..."
            docker_build_image
        else
            echo "Docker image up-to-date (no rebuild needed)"
        fi
    else
        echo "Docker image doesn't exist; building..."
        docker_build_image
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
docker run --rm -it --platform linux/arm64 \
    -v "$REPO_ROOT":/work -w /work \
    -e TMPDIR=/work/tmp \
    "${DOCKER_VOLUMES[@]}" \
    "$IMAGE_NAME" \
    "$@"
