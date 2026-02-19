#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="aarch64-unknown-linux-gnu"
TARGET_DIR="/work/target-64"
HOST_TARGET_DIR="$REPO_ROOT/target-64"
DOCKER_RUN_SCRIPT="$REPO_ROOT/docker/arm64/run.sh"
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

# USB export: set by prompt_usb_export_early; empty means skip
USB_EXPORT_DEST=""
USB_AUTO_EJECT=0
USB_SELECTED_MOUNT=""

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

get_usb_mounts() {
    local mounts=()

    if [ "$(uname -s)" = "Darwin" ]; then
        if [ -d /Volumes ]; then
            while IFS= read -r mp; do
                [ -n "$mp" ] && mounts+=("$mp")
            done < <(find /Volumes -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
        fi
    else
        for base in /media /mnt /run/media; do
            [ -d "$base" ] || continue
            while IFS= read -r mp; do
                [ -n "$mp" ] && mounts+=("$mp")
            done < <(find "$base" -maxdepth 2 -mindepth 1 -type d 2>/dev/null)
        done
    fi

    if [ -f /proc/mounts ]; then
        while IFS=" " read -r _dev mp fstype _rest; do
            case "$fstype" in
                vfat|exfat|ntfs|ntfs-3g|fuseblk)
                    case "$mp" in
                        /media/*|/mnt/*|/run/media/*) continue ;;
                        /|/boot*|/sys*|/proc*|/dev*|/run*) continue ;;
                    esac
                    [ -d "$mp" ] && mounts+=("$mp")
                    ;;
            esac
        done < /proc/mounts
    fi

    if [ "${#mounts[@]}" -gt 0 ]; then
        printf '%s\n' "${mounts[@]}" | sort -u
    fi
}

is_mount_writable() {
    local mp="$1"
    local probe="$mp/.rj_write_test.$$"
    if touch "$probe" >/dev/null 2>&1; then
        rm -f "$probe" >/dev/null 2>&1 || true
        return 0
    fi
    return 1
}

mount_flags_for_path() {
    local mp="$1"
    mount | awk -v mp="$mp" '$3 == mp {print; exit}'
}

mount_fstype_for_path() {
    local mp="$1"
    local record
    record="$(mount_flags_for_path "$mp" || true)"
    [ -n "$record" ] || return 1

    local fstype=""
    fstype="$(printf '%s\n' "$record" | awk '{for(i=1;i<=NF;i++) if($i=="type"){print $(i+1); exit}}')"
    if [ -n "$fstype" ]; then
        printf '%s\n' "$fstype"
        return 0
    fi

    if [[ "$record" == *"("*")"* ]]; then
        printf '%s\n' "$record" | awk -F'[()]' '{split($2, a, ","); gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[1]); print a[1]; exit}'
        return 0
    fi
    return 1
}

format_ntfs_mount_exfat_macos() {
    local mp="$1"
    local label="$2"

    if ! command -v diskutil >/dev/null 2>&1; then
        echo "diskutil not found; cannot format USB on macOS." >&2
        return 1
    fi

    local device
    device="$(df -P "$mp" 2>/dev/null | awk 'NR==2 {print $1}')"
    if [ -z "$device" ]; then
        echo "Could not determine device for mount point: $mp" >&2
        return 1
    fi

    echo "Formatting $device as exFAT (label: $label)..." >&2
    if ! diskutil eraseVolume ExFAT "$label" "$device" >&2; then
        echo "Failed to format $device as exFAT." >&2
        return 1
    fi

    local new_mp
    new_mp="$(diskutil info "$device" 2>/dev/null | awk -F': *' '/Mount Point/ {print $2; exit}')"
    if [ -z "$new_mp" ] || [ "$new_mp" = "Not mounted" ]; then
        new_mp="/Volumes/$label"
    fi
    printf '%s\n' "$new_mp"
}

prompt_usb_export_early() {
    local arch="$1"
    local variant="$2"
    local reply=""

    printf "Copy prebuilt binaries to a USB drive after build? [y/N]: "
    if ! read -r reply; then
        reply=""
    fi
    case "$reply" in
        y|Y|yes|YES) ;;
        *)
            echo "USB export skipped."
            USB_EXPORT_DEST=""
            USB_SELECTED_MOUNT=""
            return 0
            ;;
    esac

    local usb_mounts=()
    local writable_mounts=()
    local readonly_mounts=()
    local writable_mounts_printed=0
    while IFS= read -r mp; do
        [ -n "$mp" ] && usb_mounts+=("$mp")
    done < <(get_usb_mounts)

    if [ "${#usb_mounts[@]}" -eq 0 ]; then
        echo "No USB drives detected. USB export will be skipped."
        USB_EXPORT_DEST=""
        USB_SELECTED_MOUNT=""
        return 0
    fi

    echo ""
    echo "Detected USB drives:"
    for mp in "${usb_mounts[@]}"; do
        local size_info=""
        local access_state="read-only"
        if command -v df >/dev/null 2>&1; then
            size_info="$(df -h "$mp" 2>/dev/null | awk 'NR==2 {print $2 " total, " $4 " free"}' || true)"
        fi
        if is_mount_writable "$mp"; then
            access_state="writable"
            writable_mounts+=("$mp")
        else
            readonly_mounts+=("$mp")
        fi
        if [ -n "$size_info" ]; then
            printf "  - %s  (%s, %s)\n" "$mp" "$size_info" "$access_state"
        else
            printf "  - %s  (%s)\n" "$mp" "$access_state"
        fi
    done
    echo ""

    if [ "${#writable_mounts[@]}" -gt 0 ]; then
        echo "Writable USB drives (eligible for export):"
        local i=1
        for mp in "${writable_mounts[@]}"; do
            local size_info=""
            if command -v df >/dev/null 2>&1; then
                size_info="$(df -h "$mp" 2>/dev/null | awk 'NR==2 {print $2 " total, " $3 " used, " $4 " free"}' || true)"
            fi
            if [ -n "$size_info" ]; then
                printf "  [%d] %s  (%s)\n" "$i" "$mp" "$size_info"
            else
                printf "  [%d] %s\n" "$i" "$mp"
            fi
            i=$((i + 1))
        done
        echo ""
        writable_mounts_printed=1
    fi

    if [ "${#readonly_mounts[@]}" -gt 0 ]; then
        echo "Read-only USB drives (detected, but not writable):"
        local readonly_ntfs_mounts=()
        for mp in "${readonly_mounts[@]}"; do
            local flags
            flags="$(mount_flags_for_path "$mp" || true)"
            local fstype
            fstype="$(mount_fstype_for_path "$mp" || true)"
            local size_info=""
            if command -v df >/dev/null 2>&1; then
                size_info="$(df -h "$mp" 2>/dev/null | awk 'NR==2 {print $2 " total, " $4 " free"}' || true)"
            fi
            if [ -n "$fstype" ]; then
                local fstype_lc
                fstype_lc="$(printf '%s' "$fstype" | tr '[:upper:]' '[:lower:]')"
                case "$fstype_lc" in
                    ntfs|ntfs-3g) readonly_ntfs_mounts+=("$mp") ;;
                esac
            fi
            if [ -n "$size_info" ] && [ -n "$flags" ]; then
                echo "  - $mp  ($size_info)"
                echo "    mount: $flags"
            elif [ -n "$size_info" ]; then
                echo "  - $mp  ($size_info)"
            elif [ -n "$flags" ]; then
                echo "  - $mp"
                echo "    mount: $flags"
            else
                echo "  - $mp"
            fi
        done
        echo ""

        if [ "$(uname -s)" = "Darwin" ] && [ "${#readonly_ntfs_mounts[@]}" -gt 0 ]; then
            echo "macOS NTFS volumes are read-only without third-party drivers."
            printf "Format a read-only NTFS USB as exFAT now? This erases all data [y/N]: "
            if ! read -r reply; then
                reply=""
            fi
            case "$reply" in
                y|Y|yes|YES)
                    local i=1
                    echo "NTFS read-only USB drives:"
                    for mp in "${readonly_ntfs_mounts[@]}"; do
                        local size_info=""
                        if command -v df >/dev/null 2>&1; then
                            size_info="$(df -h "$mp" 2>/dev/null | awk 'NR==2 {print $2 " total, " $4 " free"}' || true)"
                        fi
                        if [ -n "$size_info" ]; then
                            printf "  [%d] %s  (%s)\n" "$i" "$mp" "$size_info"
                        else
                            printf "  [%d] %s\n" "$i" "$mp"
                        fi
                        i=$((i + 1))
                    done
                    echo ""

                    local format_selection="" format_target=""
                    while [ -z "$format_target" ]; do
                        printf "Select a drive to format [1-%d] (Enter to cancel): " "${#readonly_ntfs_mounts[@]}"
                        if ! read -r format_selection; then
                            break
                        fi
                        if [ -z "$format_selection" ]; then
                            break
                        fi
                        if [[ "$format_selection" =~ ^[0-9]+$ ]] && [ "$format_selection" -ge 1 ] && [ "$format_selection" -le "${#readonly_ntfs_mounts[@]}" ]; then
                            format_target="${readonly_ntfs_mounts[$((format_selection - 1))]}"
                        else
                            echo "Invalid selection. Please enter a number between 1 and ${#readonly_ntfs_mounts[@]}."
                        fi
                    done

                    if [ -n "$format_target" ]; then
                        local confirm_text=""
                        printf "Type FORMAT to erase %s and create exFAT: " "$format_target"
                        if ! read -r confirm_text; then
                            confirm_text=""
                        fi
                        if [ "$confirm_text" = "FORMAT" ]; then
                            local formatted_mp=""
                            if formatted_mp="$(format_ntfs_mount_exfat_macos "$format_target" "Rustyjack")" && [ -n "$formatted_mp" ]; then
                                echo "Formatted successfully: $formatted_mp"
                                usb_mounts=()
                                writable_mounts=()
                                readonly_mounts=()
                                while IFS= read -r mp; do
                                    [ -n "$mp" ] && usb_mounts+=("$mp")
                                done < <(get_usb_mounts)
                                for mp in "${usb_mounts[@]}"; do
                                    if is_mount_writable "$mp"; then
                                        writable_mounts+=("$mp")
                                    else
                                        readonly_mounts+=("$mp")
                                    fi
                                done
                                writable_mounts_printed=0
                            else
                                echo "Failed to format $format_target as exFAT."
                            fi
                        else
                            echo "Format cancelled."
                        fi
                    fi
                    echo ""
                    ;;
                *) ;;
            esac
        fi
    fi

    if [ "${#writable_mounts[@]}" -eq 0 ]; then
        echo "No writable USB drives detected. USB export will be skipped."
        echo "Tip: On macOS, NTFS volumes are read-only by default."
        echo "Use an exFAT/FAT32 USB, or format NTFS as exFAT in this prompt."
        USB_EXPORT_DEST=""
        USB_SELECTED_MOUNT=""
        return 0
    fi

    if [ "$writable_mounts_printed" -eq 0 ]; then
        echo "Writable USB drives (eligible for export):"
        local i=1
        for mp in "${writable_mounts[@]}"; do
            local size_info=""
            if command -v df >/dev/null 2>&1; then
                size_info="$(df -h "$mp" 2>/dev/null | awk 'NR==2 {print $2 " total, " $3 " used, " $4 " free"}' || true)"
            fi
            if [ -n "$size_info" ]; then
                printf "  [%d] %s  (%s)\n" "$i" "$mp" "$size_info"
            else
                printf "  [%d] %s\n" "$i" "$mp"
            fi
            i=$((i + 1))
        done
        echo ""
    fi

    local selection="" chosen_mp=""
    while [ -z "$chosen_mp" ]; do
        printf "Select a writable drive [1-%d]: " "${#writable_mounts[@]}"
        if ! read -r selection; then
            echo "USB export skipped."
            USB_EXPORT_DEST=""
            USB_SELECTED_MOUNT=""
            return 0
        fi
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#writable_mounts[@]}" ]; then
            chosen_mp="${writable_mounts[$((selection - 1))]}"
        else
            echo "Invalid selection. Please enter a number between 1 and ${#writable_mounts[@]}."
        fi
    done

    local root_dir_name="rustyjack"
    if [ -d "$chosen_mp/Rustyjack" ] && [ ! -d "$chosen_mp/rustyjack" ]; then
        root_dir_name="Rustyjack"
    fi
    USB_SELECTED_MOUNT="$chosen_mp"
    USB_EXPORT_DEST="$chosen_mp/$root_dir_name/prebuilt/$arch/$variant"
    echo "Will copy binaries to $USB_EXPORT_DEST after build."

    printf "Automatically eject USB after successful copy? [Y/n]: "
    if ! read -r reply; then
        reply=""
    fi
    case "$reply" in
        n|N|no|NO) USB_AUTO_EJECT=0 ;;
        *) USB_AUTO_EJECT=1 ;;
    esac
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
export RUSTYJACK_BUILD_ARCH='arm64';"
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

    local bins=(rustyjack-ui rustyjackd rustyjack-portal rustyjack rustyjack-hotplugd rustyjack-shellops)
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

# Called after a successful build: performs the actual file copy.
invoke_usb_export() {
    local src_dir="$1"

    [ -n "$USB_EXPORT_DEST" ] || return 0

    if [ -n "$USB_SELECTED_MOUNT" ] && ! is_mount_writable "$USB_SELECTED_MOUNT"; then
        echo "ERROR: Selected USB mount is not writable: $USB_SELECTED_MOUNT" >&2
        local flags
        flags="$(mount_flags_for_path "$USB_SELECTED_MOUNT" || true)"
        if [ -n "$flags" ]; then
            echo "Mount details: $flags" >&2
        fi
        echo "On macOS, NTFS is typically read-only by default." >&2
        echo "Use exFAT/FAT32 or remount with NTFS write support, then retry." >&2
        return 1
    fi

    echo "Copying binaries to $USB_EXPORT_DEST ..."

    if [ -d "$USB_EXPORT_DEST" ]; then
        echo "Removing existing files in $USB_EXPORT_DEST ..."
        rm -rf "${USB_EXPORT_DEST:?}"/*
    fi

    if ! mkdir -p "$USB_EXPORT_DEST"; then
        echo "ERROR: Failed to create directory $USB_EXPORT_DEST" >&2
        return 1
    fi

    local files=("$src_dir"/*)
    local total_files=0
    for f in "${files[@]}"; do
        [ -f "$f" ] && total_files=$((total_files + 1))
    done

    local current_file=0
    local failed=0

    for f in "${files[@]}"; do
        [ -f "$f" ] || continue
        current_file=$((current_file + 1))
        local fname
        fname="$(basename "$f")"
        local fsize
        fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "0")
        local fsize_mb=$(awk "BEGIN {printf \"%.2f\", $fsize/1024/1024}")

        echo "  [$current_file/$total_files] $fname ($fsize_mb MB)"

        local dest_path="$USB_EXPORT_DEST/$fname"
        if command -v pv >/dev/null 2>&1 && [ "$fsize" -gt 1048576 ]; then
            if pv -p -s "$fsize" "$f" > "$dest_path"; then
                true
            else
                echo "ERROR: Failed to copy $fname" >&2
                failed=1
            fi
        else
            if cp -f "$f" "$dest_path"; then
                echo "    [##################################################] 100%"
            else
                echo "ERROR: Failed to copy $fname" >&2
                failed=1
            fi
        fi
    done

    echo ""
    if [ "$failed" -eq 0 ]; then
        echo "USB export complete: $USB_EXPORT_DEST"
        if [ -n "$USB_AUTO_EJECT" ] && [ "$USB_AUTO_EJECT" = "1" ]; then
            echo "Ejecting USB drive..."

            # Flush all pending writes to disk first
            sync
            sleep 1

            # Get the mount point - more robust approach for both Linux and macOS
            local mount_point
            # Use df -P for POSIX format (consistent columns across platforms)
            mount_point=$(df -P "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $6}')

            if [ -z "$mount_point" ]; then
                # Fallback: use last column (works when df output has odd formatting)
                mount_point=$(df "$USB_EXPORT_DEST" 2>/dev/null | tail -1 | awk '{print $NF}')
            fi

            if [ -n "$mount_point" ]; then
                # Detect OS for appropriate eject command
                local os_type
                os_type=$(uname -s)

                case "$os_type" in
                    Darwin)
                        # macOS: use diskutil for proper ejection
                        local device
                        device=$(df -P "$USB_EXPORT_DEST" 2>/dev/null | awk 'NR==2 {print $1}')
                        if [ -n "$device" ]; then
                            if diskutil eject "$device" 2>/dev/null; then
                                echo "USB drive ejected successfully. Safe to remove."
                            else
                                echo "Failed to eject USB drive. Please eject manually with: diskutil eject $device"
                            fi
                        else
                            echo "Could not determine USB device. Please eject manually."
                        fi
                        ;;
                    Linux)
                        # Linux: use umount
                        if umount "$mount_point" 2>/dev/null; then
                            echo "USB drive ejected successfully. Safe to remove."
                        elif command -v sudo >/dev/null 2>&1 && sudo umount "$mount_point" 2>/dev/null; then
                            echo "USB drive ejected successfully (required sudo). Safe to remove."
                        else
                            echo "Failed to eject USB drive. Please eject manually with: sudo umount $mount_point"
                        fi
                        ;;
                    *)
                        # Unknown OS: try umount anyway
                        if umount "$mount_point" 2>/dev/null; then
                            echo "USB drive ejected successfully. Safe to remove."
                        else
                            echo "Failed to eject USB drive. Please eject manually with: umount $mount_point"
                        fi
                        ;;
                esac
            else
                echo "Could not determine USB mount point. Please eject manually."
            fi
        else
            echo "Remember to eject the USB drive before removing it."
        fi
    else
        echo "USB export completed with errors." >&2
    fi
}

if [ "$#" -gt 0 ]; then
    CMD=("$@")
else
    DEFAULT_BUILD=1
    if [ -t 0 ]; then
        prompt_build_mode
        prompt_usb_export_early "arm64" "$([ "$BUILD_MODE" = "release" ] && echo "release" || echo "development")"
    else
        echo "Non-interactive shell detected; defaulting to dev build."
    fi
    PACKAGES=(
        "rustyjack-ui|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-ui|crates/rustyjack-ui"
        "rustyjackd|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon|crates/rustyjack-daemon"
        "rustyjack-hotplugd|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon --bin rustyjack-hotplugd|crates/rustyjack-daemon"
        "rustyjack-shellops|cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon --bin rustyjack-shellops|crates/rustyjack-daemon"
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
    echo "Building: ${#BUILD_PARTS[@]} packages"
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
    for bin in rustyjack-ui rustyjackd rustyjack-portal rustyjack rustyjack-hotplugd rustyjack-shellops; do
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
        BUILD_CMD="set -euo pipefail; export PATH=/usr/local/cargo/bin:\$PATH; export CARGO_TARGET_DIR=$TARGET_DIR; $BUILD_INFO_ENV cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-ui; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon --bin rustyjack-hotplugd; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-daemon --bin rustyjack-shellops; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-portal; cargo build $BUILD_PROFILE_FLAG --target $TARGET -p rustyjack-core --bin rustyjack --features rustyjack-core/cli"

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
arch=arm64
EOF
    fi

    PREBUILT_VARIANT="development"
    if [ "$BUILD_MODE" = "release" ]; then
        PREBUILT_VARIANT="release"
    fi
    DEST_DIR="$REPO_ROOT/prebuilt/arm64/$PREBUILT_VARIANT"
    mkdir -p "$DEST_DIR"
    for bin in rustyjack-ui rustyjackd rustyjack-portal rustyjack rustyjack-hotplugd rustyjack-shellops; do
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

    # --- USB export (destination selected at startup) ---
    invoke_usb_export "$DEST_DIR"
fi
