#!/usr/bin/env bash
set -euo pipefail

# Delete all loot artifacts under the configured Rustyjack root.

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [--yes|-y]" >&2
    exit 1
fi

auto_confirm=false
if [[ $# -eq 1 ]]; then
    case "$1" in
        --yes|-y)
            auto_confirm=true
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
fi

if [[ $(id -u) -ne 0 ]]; then
    echo "This script must be run as root so loot created by rustyjack.service can be removed." >&2
    exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
default_root="$(cd "$script_dir/.." && pwd)"
root="${RUSTYJACK_ROOT:-$default_root}"
loot_dir="${root%/}/loot"

if [[ -z "$loot_dir" || "$loot_dir" == "/" ]]; then
    echo "Refusing to operate on an empty or root path (loot_dir='$loot_dir')." >&2
    exit 1
fi

if [[ ! -d "$loot_dir" ]]; then
    echo "Loot directory not found at $loot_dir"
    exit 0
fi

echo "About to permanently delete all files and folders inside:"
echo "  $loot_dir"

if ! $auto_confirm; then
    read -r -p "Type DELETE to proceed: " confirm
    if [[ "$confirm" != "DELETE" ]]; then
        echo "Aborted without removing loot."
        exit 1
    fi
else
    echo "Skipping confirmation because --yes was provided."
fi

if ! find "$loot_dir" -mindepth 1 -print -quit | grep -q .; then
    echo "Loot directory is already empty."
else
    find "$loot_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    echo "Removed all loot under $loot_dir"
fi

mkdir -p "$loot_dir"/{Wireless,Ethernet,reports,Hotspot,Responder} "$loot_dir/Reports"
echo "Recreated base loot directories."
