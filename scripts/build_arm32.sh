#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="armv7-unknown-linux-gnueabihf"
TARGET_DIR="/work/target-32"
HOST_TARGET_DIR="$REPO_ROOT/target-32"
DOCKER_RUN_SCRIPT="$REPO_ROOT/docker/arm32/run.sh"
BUILD_MODE="debug"
BUILD_PROFILE_FLAG=""
DEFAULT_BUILD=0
CMD=()
BUILD_RAN=0
LAST_BUILD_STAMP="$HOST_TARGET_DIR/.last_build_stamp"
BUILD_INFO_READY=0
BUILD_INFO_EPOCH=""
BUILD_INFO_ISO=""
BUILD_INFO_GIT_HASH="unknown"
BUILD_INFO_GIT_DIRTY="0"
BUILD_INFO_VARIANT="development"
BUILD_INFO_PROFILE="debug"
BUILD_INFO_ENV=""

# Ensure target directory exists on host (for docker volume mount)
mkdir -p "$HOST_TARGET_DIR"

ensure_git_hooks() {
    if [ "${RUSTYJACK_SKIP_HOOKS:-}" = "1" ]; then
        return 0
    fi
    if ! command -v git >/dev/null 2>&1; then
        return 0
    fi
    if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        current_hooks="$(git -C "$REPO_ROOT" config --local --get core.hooksPath 2>/dev/null || true)"
        if [ "$current_hooks" = ".githooks" ]; then
            echo "Git hooks already configured (path: $REPO_ROOT/.githooks)."
        else
            echo "Configuring git hooks (path: $REPO_ROOT/.githooks)..."
            "$REPO_ROOT/scripts/install_git_hooks.sh" || {
                echo "WARN: failed to configure git hooks" >&2
            }
        fi
    fi
}

ensure_git_hooks

prompt_build_mode() {
    local reply=""
    while true; do
        if ! read -r -p "Build release or dev binaries? [r/b]: " reply; then
            reply=""
        fi
        reply="${reply:-b}"
        case "$reply" in
            r|R|release|RELEASE)
                BUILD_MODE="release"
                BUILD_PROFILE_FLAG="--release"
                return 0
                ;;
            b|B|dev|DEV|debug|DEBUG)
                BUILD_MODE="debug"
                BUILD_PROFILE_FLAG=""
                return 0
                ;;
        esac
        echo "Please answer r (release) or b (dev)."
    done
}

compute_build_info() {
    if [ "$BUILD_INFO_READY" -eq 1 ]; then
        return 0
    fi
    BUILD_INFO_READY=1
    BUILD_INFO_EPOCH="$(date -u +%s)"
    BUILD_INFO_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    BUILD_INFO_GIT_HASH="unknown"
    BUILD_INFO_GIT_DIRTY="0"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        BUILD_INFO_GIT_HASH="$(git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")"
        if git status --porcelain 2>/dev/null | grep -q .; then
            BUILD_INFO_GIT_DIRTY="1"
        fi
    fi
    BUILD_INFO_PROFILE="$BUILD_MODE"
    if [ "$BUILD_MODE" = "release" ]; then
        BUILD_INFO_VARIANT="release"
    else
        BUILD_INFO_VARIANT="development"
    fi
    BUILD_INFO_ENV="export RUSTYJACK_BUILD_EPOCH='$BUILD_INFO_EPOCH'; \
export RUSTYJACK_BUILD_ISO='$BUILD_INFO_ISO'; \
export RUSTYJACK_GIT_HASH='$BUILD_INFO_GIT_HASH'; \
export RUSTYJACK_GIT_DIRTY='$BUILD_INFO_GIT_DIRTY'; \
export RUSTYJACK_BUILD_PROFILE='$BUILD_INFO_PROFILE'; \
export RUSTYJACK_BUILD_VARIANT='$BUILD_INFO_VARIANT'; \
export RUSTYJACK_BUILD_TARGET='$TARGET'; \
export RUSTYJACK_BUILD_ARCH='arm32';"
}

stat_epoch() {
    local path="$1"
    if stat -f %m "$path" >/dev/null 2>&1; then
        stat -f %m "$path" 2>/dev/null || echo 0
        return 0
    fi
    if stat -c %Y "$path" >/dev/null 2>&1; then
        stat -c %Y "$path" 2>/dev/null || echo 0
        return 0
    fi
    echo 0
}

latest_source_epoch() {
    local max_epoch=0
    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo 0
        return 0
    fi
    while IFS= read -r -d '' file; do
        case "$file" in
            Cargo.toml|Cargo.lock|.cargo/config|.cargo/config.toml|crates/*) ;;
            *) continue ;;
        esac
        local path="$REPO_ROOT/$file"
        [ -f "$path" ] || continue
        local epoch
        epoch="$(stat_epoch "$path")"
        if [ -n "$epoch" ] && [ "$epoch" -gt "$max_epoch" ] 2>/dev/null; then
            max_epoch="$epoch"
        fi
    done < <(git -C "$REPO_ROOT" ls-files -z)
    echo "$max_epoch"
}

selected_build_epoch() {
    local info="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/build_info.txt"
    if [ -f "$info" ]; then
        local epoch
        epoch="$(grep -E '^build_epoch=' "$info" | head -n 1 | cut -d= -f2-)"
        if [ -n "$epoch" ]; then
            echo "$epoch"
            return 0
        fi
    fi

    local bins=(rustyjack-ui rustyjackd rustyjack-portal rustyjack)
    local min_epoch=0
    for bin in "${bins[@]}"; do
        local path="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/$bin"
        if [ ! -f "$path" ]; then
            echo 0
            return 0
        fi
        local epoch
        epoch="$(stat_epoch "$path")"
        if [ -z "$epoch" ] || [ "$epoch" -le 0 ] 2>/dev/null; then
            continue
        fi
        if [ "$min_epoch" -eq 0 ] || [ "$epoch" -lt "$min_epoch" ]; then
            min_epoch="$epoch"
        fi
    done
    echo "$min_epoch"
}

selected_binaries_up_to_date() {
    local source_epoch
    source_epoch="$(latest_source_epoch)"
    if [ -z "$source_epoch" ] || [ "$source_epoch" -le 0 ] 2>/dev/null; then
        echo "WARN: unable to determine latest source timestamp; skipping freshness check." >&2
        return 0
    fi
    local build_epoch
    build_epoch="$(selected_build_epoch)"
    if [ -z "$build_epoch" ] || [ "$build_epoch" -le 0 ] 2>/dev/null; then
        return 1
    fi
    if [ "$build_epoch" -lt "$source_epoch" ]; then
        return 1
    fi
    return 0
}

if [ "$#" -gt 0 ]; then
    CMD=("$@")
else
    DEFAULT_BUILD=1
    if [ -t 0 ]; then
        prompt_build_mode
    else
        echo "Non-interactive shell detected; defaulting to dev build."
    fi
    PACKAGES=(
        "rustyjack-ui|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-ui|crates/rustyjack-ui"
        "rustyjackd|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon|crates/rustyjack-daemon"
        "rustyjack-portal|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-portal|crates/rustyjack-portal"
        "rustyjack|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli|crates/rustyjack-core"
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
            src="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/$bin"
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
        compute_build_info
        BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; $BUILD_INFO_ENV $(IFS='; '; echo "${BUILD_CMDS[*]}")"
        CMD=(bash -c "$BUILD_CMD")
    fi

    if [ "$DEFAULT_BUILD" -eq 1 ] && [ "${#CMD[@]}" -eq 0 ]; then
        if selected_binaries_up_to_date; then
            echo "Selected $BUILD_MODE binaries appear up-to-date."
        else
            echo "Selected $BUILD_MODE binaries are older than source; rebuilding."
            BUILD_PARTS=()
            BUILD_CMDS=()
            for entry in "${PACKAGES[@]}"; do
                IFS="|" read -r _bin cmd _dir <<< "$entry"
                BUILD_PARTS+=("$cmd")
                BUILD_CMDS+=("$cmd")
            done
            compute_build_info
            BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; $BUILD_INFO_ENV $(IFS='; '; echo "${BUILD_CMDS[*]}")"
            CMD=(bash -c "$BUILD_CMD")
        fi
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
        src="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/$bin"
        if [ ! -f "$src" ]; then
            missing_binaries=1
            break
        fi
    done

    if [ "$missing_binaries" -eq 1 ] && [ "${#BUILD_PARTS[@]}" -eq 0 ]; then
        echo "WARNING: Expected binaries missing but no build was triggered" >&2
        echo "Building all packages as fallback..." >&2

        compute_build_info
        BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; $BUILD_INFO_ENV cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-ui; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-portal; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"

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
        BUILD_INFO_FILE="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/build_info.txt"
        cat > "$BUILD_INFO_FILE" <<EOF
build_epoch=$BUILD_INFO_EPOCH
build_iso=$BUILD_INFO_ISO
git_hash=$BUILD_INFO_GIT_HASH
git_dirty=$BUILD_INFO_GIT_DIRTY
build_profile=$BUILD_INFO_PROFILE
build_variant=$BUILD_INFO_VARIANT
target=$TARGET
arch=arm32
EOF
    fi

    PREBUILT_VARIANT="development"
    if [ "$BUILD_MODE" = "release" ]; then
        PREBUILT_VARIANT="release"
    fi
    DEST_DIR="$REPO_ROOT/prebuilt/arm32/$PREBUILT_VARIANT"
    mkdir -p "$DEST_DIR"
    for bin in rustyjack-ui rustyjackd rustyjack-portal rustyjack; do
        src="$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/$bin"
        if [ ! -f "$src" ]; then
            echo "Missing binary: $src" >&2
            exit 1
        fi
        cp -f "$src" "$DEST_DIR/$bin"
    done
    if [ -f "$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/build_info.txt" ]; then
        cp -f "$HOST_TARGET_DIR/$TARGET/$BUILD_MODE/build_info.txt" "$DEST_DIR/build_info.txt"
    else
        echo "WARNING: build_info.txt not found in target directory" >&2
    fi
    echo "Copied binaries to $DEST_DIR"
fi
