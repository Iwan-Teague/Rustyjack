#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="aarch64-unknown-linux-gnu"
TARGET_DIR="/work/target-64"
HOST_TARGET_DIR="$REPO_ROOT/target-64"
DOCKER_RUN_SCRIPT="$REPO_ROOT/docker/arm64/run.sh"
DEFAULT_BUILD=0
CMD=()
BUILD_RAN=0
LAST_BUILD_STAMP="$HOST_TARGET_DIR/.last_build_stamp"

# Ensure target directory exists on host (for docker volume mount)
mkdir -p "$HOST_TARGET_DIR"

if [ "$#" -gt 0 ]; then
    CMD=("$@")
else
    DEFAULT_BUILD=1
    PACKAGES=(
        "rustyjack-ui|cargo build --target $TARGET -p rustyjack-ui|crates/rustyjack-ui"
        "rustyjackd|cargo build --target $TARGET -p rustyjack-daemon|crates/rustyjack-daemon"
        "rustyjack-portal|cargo build --target $TARGET -p rustyjack-portal|crates/rustyjack-portal"
        "rustyjack|cargo build --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli|crates/rustyjack-core"
    )

    changed=()
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if por="$(git status --porcelain 2>/dev/null)"; then
            while IFS= read -r line; do
                if [ "${#line}" -gt 3 ]; then
                    file="${line:3}"
                    if [[ "$file" == *" -> "* ]]; then
                        file="${file##* -> }"
                    fi
                    changed+=("$file")
                fi
            done <<< "$por"
        fi
    fi

    if [ "${#changed[@]}" -gt 0 ]; then
        changed_sorted=()
        while IFS= read -r file; do
            [ -n "$file" ] && changed_sorted+=("$file")
        done < <(printf '%s\n' "${changed[@]}" | sed '/^$/d' | sort -u)
        changed=("${changed_sorted[@]}")
    fi

    BUILD_PARTS=()
    BUILD_CMDS=()

    if [ ! -f "$LAST_BUILD_STAMP" ]; then
        echo "No build stamp found; rebuilding all packages."
        workspace_changed=1
    else
        workspace_changed=0

        for f in Cargo.toml Cargo.lock .cargo/config.toml .cargo/config; do
            if [ -f "$REPO_ROOT/$f" ] && [ "$REPO_ROOT/$f" -nt "$LAST_BUILD_STAMP" ]; then
                workspace_changed=1
                break
            fi
        done

        if [ "$workspace_changed" -eq 0 ] && [ -d "$REPO_ROOT/crates" ]; then
            for dir in "$REPO_ROOT"/crates/*; do
                [ -d "$dir" ] || continue
                case "$dir" in
                    "$REPO_ROOT/crates/rustyjack-ui"|\
                    "$REPO_ROOT/crates/rustyjack-daemon"|\
                    "$REPO_ROOT/crates/rustyjack-portal") ;;
                    *)
                        if find "$dir" -type f -newer "$LAST_BUILD_STAMP" -print -quit | grep -q .; then
                            workspace_changed=1
                            break
                        fi
                        ;;
                esac
            done
        fi
    fi

    if [ "${#changed[@]}" -eq 0 ] && [ "$workspace_changed" -eq 0 ]; then
        echo "No local changes detected; falling back to artifact existence check."
        for entry in "${PACKAGES[@]}"; do
            IFS="|" read -r bin cmd dir <<< "$entry"
            src="$HOST_TARGET_DIR/$TARGET/debug/$bin"
            if [ -f "$src" ]; then
                echo "Found existing target binary for $bin at $src - skipping rebuild"
            else
                BUILD_PARTS+=("$cmd")
                BUILD_CMDS+=("$cmd")
            fi
        done
        if [ "${#BUILD_PARTS[@]}" -eq 0 ]; then
            echo "All target binaries exist - skipping docker build."
        fi
    else
        if [ "$workspace_changed" -eq 1 ]; then
            echo "Workspace changes detected; rebuilding all packages"
            for entry in "${PACKAGES[@]}"; do
                IFS="|" read -r _bin cmd _dir <<< "$entry"
                BUILD_PARTS+=("$cmd")
                BUILD_CMDS+=("$cmd")
            done
        else
            for entry in "${PACKAGES[@]}"; do
                IFS="|" read -r _bin cmd dir <<< "$entry"
                if [ ! -f "$LAST_BUILD_STAMP" ]; then
                    BUILD_PARTS+=("$cmd")
                    BUILD_CMDS+=("$cmd")
                    continue
                fi
                if find "$REPO_ROOT/$dir" -type f -newer "$LAST_BUILD_STAMP" -print -quit | grep -q .; then
                    BUILD_PARTS+=("$cmd")
                    BUILD_CMDS+=("$cmd")
                    continue
                fi
                for f in "${changed[@]}"; do
                    if [[ "$f" == "$dir/"* || "$f" == */"$dir/"* ]]; then
                        BUILD_PARTS+=("$cmd")
                        BUILD_CMDS+=("$cmd")
                        break
                    fi
                done
            done
        fi

        if [ "${#BUILD_PARTS[@]}" -gt 0 ]; then
            build_parts_sorted=()
            while IFS= read -r cmd; do
                [ -n "$cmd" ] && build_parts_sorted+=("$cmd")
            done < <(printf '%s\n' "${BUILD_PARTS[@]}" | sort -u)
            BUILD_PARTS=("${build_parts_sorted[@]}")

            build_cmds_sorted=()
            while IFS= read -r cmd; do
                [ -n "$cmd" ] && build_cmds_sorted+=("$cmd")
            done < <(printf '%s\n' "${BUILD_CMDS[@]}" | sort -u)
            BUILD_CMDS=("${build_cmds_sorted[@]}")
        fi

        if [ "${#BUILD_PARTS[@]}" -eq 0 ]; then
            echo "No package-specific changes detected; skipping docker build."
        fi
    fi

    if [ "${#BUILD_PARTS[@]}" -gt 0 ]; then
        BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; $(IFS='; '; echo "${BUILD_CMDS[*]}")"
        CMD=(bash -c "$BUILD_CMD")
    fi
fi

if [ "$DEFAULT_BUILD" -eq 0 ]; then
    # Custom command mode - pass through to docker run script with volume mount
    export DOCKER_VOLUMES_EXTRA="$HOST_TARGET_DIR:$TARGET_DIR"
    bash "$DOCKER_RUN_SCRIPT" "${CMD[@]}"
elif [ "${#CMD[@]}" -gt 0 ]; then
    echo "Running build in Docker container..."
    echo "Building: ${#BUILD_PARTS[@]} package(s)"
    BUILD_RAN=1
    # Pass cargo target cache volume to docker run script
    export DOCKER_VOLUMES_EXTRA="$HOST_TARGET_DIR:$TARGET_DIR"
    bash "$DOCKER_RUN_SCRIPT" "${CMD[@]}"
else
    echo "Skipping build - no changes detected"
fi

if [ "$DEFAULT_BUILD" -eq 1 ]; then
    # Check if binaries exist; if not and we skipped the build, rebuild them now
    missing_binaries=0
    for bin in rustyjack-ui rustyjackd rustyjack-portal rustyjack; do
        src="$HOST_TARGET_DIR/$TARGET/debug/$bin"
        if [ ! -f "$src" ]; then
            missing_binaries=1
            break
        fi
    done

    if [ "$missing_binaries" -eq 1 ] && [ "${#BUILD_PARTS[@]}" -eq 0 ]; then
        echo "WARNING: Expected binaries missing but no build was triggered" >&2
        echo "Building all packages as fallback..." >&2

        BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; cargo build --target $TARGET -p rustyjack-ui; cargo build --target $TARGET -p rustyjack-daemon; cargo build --target $TARGET -p rustyjack-portal; cargo build --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"

        # Pass cargo target cache volume to docker run script
        export DOCKER_VOLUMES_EXTRA="$HOST_TARGET_DIR:$TARGET_DIR"
        BUILD_RAN=1
        bash "$DOCKER_RUN_SCRIPT" bash -c "$BUILD_CMD"

        if [ $? -ne 0 ]; then
            echo "Fallback build failed" >&2
            exit 1
        fi

        echo "Fallback build completed successfully"
    fi

    if [ "$BUILD_RAN" -eq 1 ]; then
        date +%s > "$LAST_BUILD_STAMP" 2>/dev/null || touch "$LAST_BUILD_STAMP"
    fi

    DEST_DIR="$REPO_ROOT/prebuilt/arm64"
    mkdir -p "$DEST_DIR"
    for bin in rustyjack-ui rustyjackd rustyjack-portal rustyjack; do
        src="$HOST_TARGET_DIR/$TARGET/debug/$bin"
        if [ ! -f "$src" ]; then
            echo "Missing binary: $src" >&2
            exit 1
        fi
        cp -f "$src" "$DEST_DIR/$bin"
    done
    echo "Copied binaries to $DEST_DIR"
fi
