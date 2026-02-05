#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="staged"
BUMP_ALL=0
DRY_RUN=0

usage() {
    echo "Usage: $0 [--staged] [--all] [--dry-run]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --staged)
            MODE="staged"
            ;;
        --all)
            BUMP_ALL=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
 done

if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Not inside a git work tree: $REPO_ROOT" >&2
    exit 1
fi

crates=()
if [ "$BUMP_ALL" -eq 1 ]; then
    while IFS= read -r crate; do
        [ -n "$crate" ] && crates+=("$crate")
    done < <(ls -1 "$REPO_ROOT/crates" 2>/dev/null | sort)
else
    files=()
    while IFS= read -r f; do
        [ -n "$f" ] && files+=("$f")
    done < <(git -C "$REPO_ROOT" diff --name-only --cached)
    if [ "${#files[@]}" -eq 0 ]; then
        echo "No staged changes detected; skipping version bump."
        exit 0
    fi

    crates_raw=()
    for f in "${files[@]}"; do
        f="${f#./}"
        if [[ "$f" == crates/*/* ]]; then
            crate="${f#crates/}"
            crate="${crate%%/*}"
            if [ "$f" = "crates/$crate/Cargo.toml" ]; then
                continue
            fi
            crates_raw+=("$crate")
        fi
    done

    if [ "${#crates_raw[@]}" -gt 0 ]; then
        while IFS= read -r crate; do
            [ -n "$crate" ] && crates+=("$crate")
        done < <(printf '%s\n' "${crates_raw[@]}" | sort -u)
    fi
fi

if [ "${#crates[@]}" -eq 0 ]; then
    echo "No crate changes detected; skipping version bump."
    exit 0
fi

bumped_any=0
for crate in "${crates[@]}"; do
    cargo_toml="$REPO_ROOT/crates/$crate/Cargo.toml"
    if [ ! -f "$cargo_toml" ]; then
        echo "Skipping missing Cargo.toml: $cargo_toml" >&2
        continue
    fi

    output=$(python3 - "$cargo_toml" "$DRY_RUN" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
dry_run = sys.argv[2] == "1"
text = path.read_text()
lines = text.splitlines()

in_package = False
old_version = None
new_version = None
index = None

for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        in_package = stripped == "[package]"
        continue
    if in_package and stripped.startswith("version"):
        m = re.match(r'^version\s*=\s*"([^"]+)"\s*$', stripped)
        if not m:
            raise SystemExit(f"Failed to parse version in {path}")
        old_version = m.group(1)
        m2 = re.match(r'^(\d+)\.(\d+)\.(\d+)(.*)$', old_version)
        if not m2:
            raise SystemExit(f"Unsupported version format: {old_version}")
        major, minor, patch, suffix = m2.groups()
        new_version = f"{major}.{minor}.{int(patch) + 1}{suffix}"
        replacement = re.sub(r'"[^"]+"', f'"{new_version}"', line, count=1)
        lines[i] = replacement
        index = i
        break

if old_version is None or new_version is None or index is None:
    raise SystemExit(f"No [package] version found in {path}")

if not dry_run:
    new_text = "\n".join(lines)
    if text.endswith("\n"):
        new_text += "\n"
    path.write_text(new_text)

print(f"{path} {old_version} -> {new_version}")
PY
)

    echo "$output"
    bumped_any=1

    if [ "$DRY_RUN" -eq 0 ] && [ "$MODE" = "staged" ]; then
        git -C "$REPO_ROOT" add "$cargo_toml"
    fi
 done

if [ "$bumped_any" -eq 0 ]; then
    echo "No versions bumped."
fi
