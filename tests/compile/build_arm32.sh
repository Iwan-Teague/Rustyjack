#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET="armv7-unknown-linux-gnueabihf"
TARGET_DIR="/work/target-32"
HOST_TARGET_DIR="$REPO_ROOT/target-32"
DEFAULT_BUILD=0
CMD=()

if [ "$#" -gt 0 ]; then
    CMD=("$@")
else
    DEFAULT_BUILD=1
    PACKAGES=(
        "rustyjack-ui|cargo build --target $TARGET -p rustyjack-ui|rustyjack-ui"
        "rustyjackd|cargo build --target $TARGET -p rustyjack-daemon|rustyjack-daemon"
        "rustyjack-portal|cargo build --target $TARGET -p rustyjack-portal|rustyjack-portal"
        "rustyjack|cargo build --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli|rustyjack-core"
    )

    changed=()
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

    upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    if [ -n "$upstream" ]; then
        diff="$(git diff --name-only "$upstream...HEAD" 2>/dev/null || true)"
    else
        diff="$(git diff --name-only HEAD~1..HEAD 2>/dev/null || true)"
    fi
    if [ -n "$diff" ]; then
        while IFS= read -r file; do
            file="${file#"${file%%[![:space:]]*}"}"
            [ -n "$file" ] && changed+=("$file")
        done <<< "$diff"
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

    if [ "${#changed[@]}" -eq 0 ]; then
        echo "No changed files detected via git; falling back to artifact existence check."
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
        workspace_changed=0
        for f in "${changed[@]}"; do
            case "$f" in
                Cargo.toml|Cargo.lock|*/Cargo.toml|*/Cargo.lock)
                    workspace_changed=1
                    break
                    ;;
            esac
        done

        if [ "$workspace_changed" -eq 1 ]; then
            echo "Workspace Cargo files changed; rebuilding all packages"
            for entry in "${PACKAGES[@]}"; do
                IFS="|" read -r _bin cmd _dir <<< "$entry"
                BUILD_PARTS+=("$cmd")
                BUILD_CMDS+=("$cmd")
            done
        else
            for entry in "${PACKAGES[@]}"; do
                IFS="|" read -r _bin cmd dir <<< "$entry"
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
    bash "$REPO_ROOT/docker/arm32/run.sh" "${CMD[@]}"
elif [ "${#CMD[@]}" -gt 0 ]; then
    echo "Running build in Docker container..."
    echo "Building: ${#BUILD_PARTS[@]} package(s)"
    bash "$REPO_ROOT/docker/arm32/run.sh" "${CMD[@]}"
else
    echo "Skipping build - no changes detected"
fi

if [ "$DEFAULT_BUILD" -eq 1 ]; then
    DEST_DIR="$REPO_ROOT/prebuilt/arm32"
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
