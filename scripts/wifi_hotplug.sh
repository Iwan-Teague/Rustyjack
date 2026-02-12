#!/bin/bash
# Compatibility shim for legacy rule paths.
# Runtime logic now lives in the Rust binary: /usr/local/bin/rustyjack-hotplugd

set -euo pipefail

if [ ! -x /usr/local/bin/rustyjack-hotplugd ]; then
  echo "rustyjack-hotplugd not installed at /usr/local/bin/rustyjack-hotplugd" >&2
  exit 1
fi

exec /usr/local/bin/rustyjack-hotplugd "$@"
