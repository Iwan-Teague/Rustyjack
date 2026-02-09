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

if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync not found in PATH."
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
repo_name="$(basename "$repo_root")"
timestamp="$(date +%Y%m%d-%H%M%S)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/rustyjack_shallow_${timestamp}_XXXXXX")"
clone_dir="${work_dir}/${repo_name}"
zip_path="${repo_root}/${repo_name}_shallow_${timestamp}.zip"

mkdir -p "$clone_dir"

# Shallow export model:
# copy the repo as-is, excluding git metadata and build/binary artifacts.
rsync -a \
  --exclude='.git' \
  --exclude='.git/' \
  --exclude='target' \
  --exclude='target-*' \
  --exclude='build' \
  --exclude='build-*' \
  --exclude='prebuilt' \
  --exclude='bin' \
  --exclude='*.zip' \
  "$repo_root/" "$clone_dir/"

(
  cd "$work_dir"
  zip -r "$zip_path" "$repo_name" >/dev/null
)

rm -rf "$work_dir"

echo "Wrote $zip_path"
