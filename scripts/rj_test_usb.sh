#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./rj_test_lib.sh
source "$ROOT_DIR/rj_test_lib.sh"

RUN_COMPAT=1
RUN_INTEGRATION=1
RUN_NEGATIVE=1
RUN_ISOLATION=1
USB_DEVICE="${RJ_USB_TEST_DEVICE:-}"

usage() {
  cat <<'USAGE'
Usage: rj_test_usb.sh [options]

Options:
  --device PATH       USB block device (e.g., /dev/sda1). Auto-detected if omitted.
  --no-compat         Skip compatibility checks
  --no-integration    Skip mount/read/write integration checks
  --no-negative       Skip negative checks
  --no-isolation      Skip isolation snapshots
  --no-ui             Ignored (compat with rj_run_tests)
  --ui                Ignored (compat with rj_run_tests)
  --dangerous         Ignored (compat with rj_run_tests)
  --outroot DIR       Output root (default: /var/tmp/rustyjack-tests)
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device) USB_DEVICE="$2"; shift 2 ;;
    --no-compat) RUN_COMPAT=0; shift ;;
    --no-integration) RUN_INTEGRATION=0; shift ;;
    --no-negative) RUN_NEGATIVE=0; shift ;;
    --no-isolation) RUN_ISOLATION=0; shift ;;
    --no-ui|--ui|--dangerous) shift ;;
    --outroot) RJ_OUTROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

rj_init "usb_mount"
rj_require_root

if ! rj_require_cmd rustyjack; then
  rj_write_report
  exit 0
fi

if ! rj_ensure_tool python3 "python3" "Python 3 (USB test JSON parsing)"; then
  rj_write_report
  exit 0
fi

FAIL_CONTEXT_CAPTURED=0
capture_failure_context() {
  if [[ "$FAIL_CONTEXT_CAPTURED" -eq 1 ]]; then
    return 0
  fi
  FAIL_CONTEXT_CAPTURED=1
  rj_log "Capturing USB failure context..."
  if command -v lsblk >/dev/null 2>&1; then
    lsblk -o NAME,KNAME,TYPE,TRAN,SIZE,MOUNTPOINT,FSTYPE >"$OUT/artifacts/lsblk_fail.txt" 2>&1 || true
  fi
  cat /proc/mounts >"$OUT/artifacts/proc_mounts_fail.txt" 2>&1 || true
  if [[ -d /sys/class/block ]]; then
    find /sys/class/block -maxdepth 2 -type f \( -name removable -o -name size -o -name partition \) \
      >"$OUT/artifacts/sys_class_block_files.txt" 2>&1 || true
  fi
  rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd_fail.log"
}
export RJ_FAILURE_HOOK=capture_failure_context

run_as_user() {
  local user="$1"
  shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$user" -- "$@"
  else
    return 127
  fi
}

is_usb_block_sysfs() {
  local sys_path="$1"
  local current
  current="$(readlink -f "$sys_path" 2>/dev/null || true)"
  if [[ -z "$current" ]]; then
    return 1
  fi
  while [[ "$current" != "/" && -n "$current" ]]; do
    if [[ -e "$current/idVendor" && -e "$current/idProduct" ]]; then
      return 0
    fi
    current="$(dirname "$current")"
  done
  return 1
}

block_has_media() {
  local sys_path="$1"
  local sectors
  sectors="$(cat "$sys_path/size" 2>/dev/null || echo 0)"
  [[ "$sectors" =~ ^[0-9]+$ ]] || return 1
  [[ "$sectors" -gt 0 ]]
}

base_block_for_name() {
  local name="$1"
  local sys_path="/sys/class/block/$name"
  if [[ -f "$sys_path/partition" ]]; then
    local real_path parent
    real_path="$(readlink -f "$sys_path" 2>/dev/null || true)"
    if [[ -n "$real_path" ]]; then
      parent="$(basename "$(dirname "$real_path")")"
      if [[ -n "$parent" && "$parent" != "$name" ]]; then
        printf '%s\n' "$parent"
        return 0
      fi
    fi
  fi
  printf '%s\n' "$name"
}

base_device_for() {
  local dev="$1"
  local name="${dev##*/}"
  local base
  base="$(base_block_for_name "$name")"
  printf '/dev/%s\n' "$base"
}

detect_usb_partition_auto() {
  local sys_path name base dev
  for sys_path in /sys/class/block/*; do
    [[ -e "$sys_path" ]] || continue
    [[ -f "$sys_path/partition" ]] || continue
    name="$(basename "$sys_path")"
    dev="/dev/$name"
    [[ -b "$dev" ]] || continue
    block_has_media "$sys_path" || continue
    base="$(base_block_for_name "$name")"
    [[ -d "/sys/class/block/$base" ]] || continue
    if is_usb_block_sysfs "/sys/class/block/$base"; then
      printf '%s\n' "$dev"
      return 0
    fi
  done
  return 1
}

detect_usb_disk_auto() {
  local sys_path name dev
  for sys_path in /sys/block/*; do
    [[ -e "$sys_path" ]] || continue
    name="$(basename "$sys_path")"
    if [[ "$name" == mmcblk* || "$name" == loop* || "$name" == ram* ]]; then
      continue
    fi
    dev="/dev/$name"
    [[ -b "$dev" ]] || continue
    block_has_media "$sys_path" || continue
    if is_usb_block_sysfs "/sys/class/block/$name"; then
      printf '%s\n' "$dev"
      return 0
    fi
  done
  return 1
}

detect_usb_device_auto() {
  detect_usb_partition_auto || detect_usb_disk_auto
}

mount_options_for() {
  local mountpoint="$1"
  awk -v mp="$mountpoint" '$2 == mp { print $4; exit }' /proc/mounts
}

MOUNTPOINT=""
cleanup_mount() {
  if [[ -n "$MOUNTPOINT" ]]; then
    rustyjack system usb-unmount --mountpoint "$MOUNTPOINT" --output json \
      >"$OUT/artifacts/usb_unmount_cleanup.json" 2>&1 || true
  fi
}
trap cleanup_mount EXIT

if [[ $RUN_COMPAT -eq 1 ]]; then
  if [[ -r /proc/mounts ]]; then
    rj_ok "proc_mounts_readable"
  else
    rj_fail "proc_mounts_readable"
  fi
  if [[ -d /sys/class/block ]]; then
    rj_ok "sys_class_block_available"
  else
    rj_fail "sys_class_block_available"
  fi
else
  rj_skip "Compatibility checks disabled"
fi

if [[ -z "$USB_DEVICE" ]]; then
  USB_DEVICE="$(detect_usb_device_auto || true)"
fi

if [[ -z "$USB_DEVICE" ]]; then
  rj_skip "No USB block device detected. Insert a USB drive or pass --device."
  rj_write_report
  exit 0
fi

if [[ ! -b "$USB_DEVICE" ]]; then
  rj_fail "USB device is not a block device: $USB_DEVICE"
  rj_write_report
  exit 0
fi

rj_log "Using USB device: $USB_DEVICE"
BASE_DEVICE="$(base_device_for "$USB_DEVICE")"
rj_log "Base USB disk: $BASE_DEVICE"

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "usb_pre"
fi

if [[ $RUN_INTEGRATION -eq 1 ]]; then
  DETECT_OUT="$OUT/artifacts/usb_detect_preflight.json"
  rj_run_cmd_capture "usb_detect_preflight" "$DETECT_OUT" \
    rustyjack system fde-prepare --device "$BASE_DEVICE" --output json

  DETECT_STATUS="$(rj_json_get "$DETECT_OUT" "data.status" || true)"
  if [[ "$DETECT_STATUS" == "OK" ]]; then
    rj_ok "usb_detectability_preflight ($BASE_DEVICE)"
  else
    rj_fail "usb_detectability_preflight ($BASE_DEVICE)"
  fi

  MOUNT_OUT="$OUT/artifacts/usb_mount_rw.json"
  rj_run_cmd_capture "usb_mount_read_write" "$MOUNT_OUT" \
    rustyjack system usb-mount --device "$USB_DEVICE" --mode read-write --preferred-name rjtest_usb_mount --output json

  MOUNT_STATUS="$(rj_json_get "$MOUNT_OUT" "status" || true)"
  MOUNTPOINT="$(rj_json_get "$MOUNT_OUT" "data.mountpoint" || true)"
  READONLY_FLAG="$(rj_json_get "$MOUNT_OUT" "data.readonly" || true)"

  if [[ "$MOUNT_STATUS" == "ok" ]]; then
    rj_ok "usb_mount_command_ok"
  else
    rj_fail "usb_mount_command_ok"
  fi

  if [[ -n "$MOUNTPOINT" && -d "$MOUNTPOINT" ]]; then
    rj_ok "usb_mountpoint_present ($MOUNTPOINT)"
  else
    rj_fail "usb_mountpoint_present"
  fi

  if [[ "$READONLY_FLAG" == "false" ]]; then
    rj_ok "usb_mount_not_readonly"
  else
    rj_fail "usb_mount_not_readonly"
  fi

  if [[ -n "$MOUNTPOINT" ]]; then
    if grep -qs " $MOUNTPOINT " /proc/mounts; then
      rj_ok "usb_mount_detectable_in_proc_mounts"
    else
      rj_fail "usb_mount_detectable_in_proc_mounts"
    fi

    MOUNT_OPTS="$(mount_options_for "$MOUNTPOINT" || true)"
    if [[ "$MOUNT_OPTS" == *rw* ]]; then
      rj_ok "usb_mount_options_rw ($MOUNT_OPTS)"
    else
      rj_fail "usb_mount_options_rw (${MOUNT_OPTS:-missing})"
    fi

    ROOT_TEST_FILE="$MOUNTPOINT/rj_usb_mount_test_${RJ_RUN_ID}.txt"
    if printf 'rustyjack usb mount root write test\n' >"$ROOT_TEST_FILE"; then
      rj_ok "usb_root_write"
    else
      rj_fail "usb_root_write"
    fi

    if [[ -r "$ROOT_TEST_FILE" ]] && grep -q "root write test" "$ROOT_TEST_FILE"; then
      rj_ok "usb_root_readback"
    else
      rj_fail "usb_root_readback"
    fi

    if id -u rustyjack-ui >/dev/null 2>&1; then
      if command -v runuser >/dev/null 2>&1 || command -v sudo >/dev/null 2>&1; then
        UI_TEST_FILE="$MOUNTPOINT/rj_usb_mount_test_ui_${RJ_RUN_ID}.txt"
        if run_as_user rustyjack-ui bash -c 'set -euo pipefail; p="$1"; printf "rustyjack ui write test\n" >"$p"' _ "$UI_TEST_FILE"; then
          rj_ok "usb_ui_write"
        else
          rj_fail "usb_ui_write"
        fi
        if run_as_user rustyjack-ui bash -c 'set -euo pipefail; p="$1"; grep -q "ui write test" "$p"' _ "$UI_TEST_FILE"; then
          rj_ok "usb_ui_readback"
        else
          rj_fail "usb_ui_readback"
        fi
      else
        rj_skip "runuser/sudo missing; skipping rustyjack-ui read/write check"
      fi
    else
      rj_skip "rustyjack-ui user missing; skipping user-level read/write check"
    fi
  fi

  if [[ -n "$MOUNTPOINT" ]]; then
    UNMOUNT_OUT="$OUT/artifacts/usb_unmount.json"
    rj_run_cmd_capture "usb_unmount" "$UNMOUNT_OUT" \
      rustyjack system usb-unmount --mountpoint "$MOUNTPOINT" --output json

    if grep -qs " $MOUNTPOINT " /proc/mounts; then
      rj_fail "usb_unmounted_from_proc_mounts"
    else
      rj_ok "usb_unmounted_from_proc_mounts"
    fi

    MOUNTPOINT=""
  fi
else
  rj_skip "Integration checks disabled"
fi

if [[ $RUN_NEGATIVE -eq 1 ]]; then
  rj_run_cmd_capture_allow_fail "usb_mount_invalid_device" "$OUT/artifacts/usb_mount_invalid_device.json" \
    rustyjack system usb-mount --device /dev/loop0 --mode read-only --output json
  NEG_STATUS="$(rj_json_get "$OUT/artifacts/usb_mount_invalid_device.json" "status" || true)"
  if [[ "$NEG_STATUS" == "error" ]]; then
    rj_ok "usb_mount_invalid_device_rejected"
  else
    rj_fail "usb_mount_invalid_device_rejected"
  fi
else
  rj_skip "Negative checks disabled"
fi

if [[ $RUN_ISOLATION -eq 1 ]]; then
  rj_snapshot_network "usb_post"
  rj_compare_snapshot "usb_pre" "usb_post" "usb_mount_readonly"
fi

rj_capture_journal "rustyjackd.service" "$OUT/journal/rustyjackd.log"
rj_write_report

rj_log "USB mount tests completed. Output: $OUT"
