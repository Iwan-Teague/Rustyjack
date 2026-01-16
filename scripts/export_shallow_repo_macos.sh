#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "git not found in PATH."
  exit 1
fi

if ! command -v zip >/dev/null 2>&1; then
  echo "zip not found in PATH."
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
repo_name="$(basename "$repo_root")"
timestamp="$(date +%Y%m%d-%H%M%S)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/rustyjack_shallow_${timestamp}_XXXXXX")"
clone_dir="${work_dir}/${repo_name}"
zip_path="${repo_root}/${repo_name}_shallow_${timestamp}.zip"

git clone --depth 1 --no-tags --no-local "$repo_root" "$clone_dir"

rm -rf "$clone_dir/.git"

# Keep only rust source, docs, and systemd unit files.
find "$clone_dir" -type f ! \( \
  -name '*.rs' -o \
  -name '*.toml' -o \
  -name '*.lock' -o \
  -name '*.md' -o \
  -name '*.txt' -o \
  -name '*.service' -o \
  -name '*.socket' -o \
  -name 'LICENSE*' -o \
  -name 'COPYING*' -o \
  -name 'NOTICE*' \
\) -delete

find "$clone_dir" -type d -empty -delete

(
  cd "$work_dir"
  zip -r "$zip_path" "$repo_name" >/dev/null
)

rm -rf "$work_dir"

echo "Wrote $zip_path"
