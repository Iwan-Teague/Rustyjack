#!/bin/bash
# WiFi Hotplug Handler - Called by udev when USB WiFi device is inserted/removed
# This script runs in background and notifies rustyjack-ui

RUSTYJACK_ROOT="${RUSTYJACK_ROOT:-/opt/rustyjack}"
LOG_FILE="/var/log/rustyjack_wifi_hotplug.log"
NOTIFY_FIFO="/tmp/rustyjack_wifi_notify"
EVENT_FILE="/tmp/rustyjack_wifi_event"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

ACTION="$1"
DEVICE="$2"

log "Hotplug event: ACTION=$ACTION DEVICE=$DEVICE"

case "$ACTION" in
    add)
        log "USB WiFi device inserted: $DEVICE"
        
        # Write event for UI to detect
        cat > "$EVENT_FILE" << EOF
{
    "event": "usb_wifi_inserted",
    "device": "$DEVICE",
    "timestamp": "$(date -Iseconds)",
    "status": "detected"
}
EOF
        
        # Small delay to let USB settle
        sleep 2
        
        # Run driver installer in background
        nohup "$RUSTYJACK_ROOT/scripts/wifi_driver_installer.sh" >> "$LOG_FILE" 2>&1 &
        INSTALLER_PID=$!
        
        log "Started driver installer (PID: $INSTALLER_PID)"
        
        # Update event file
        cat > "$EVENT_FILE" << EOF
{
    "event": "driver_installing",
    "device": "$DEVICE",
    "timestamp": "$(date -Iseconds)",
    "status": "installing",
    "installer_pid": $INSTALLER_PID
}
EOF
        ;;
        
    remove)
        log "USB WiFi device removed: $DEVICE"
        
        cat > "$EVENT_FILE" << EOF
{
    "event": "usb_wifi_removed",
    "device": "$DEVICE",
    "timestamp": "$(date -Iseconds)",
    "status": "removed"
}
EOF
        ;;
        
    interface_add)
        log "WiFi interface added: $DEVICE"
        
        cat > "$EVENT_FILE" << EOF
{
    "event": "interface_ready",
    "interface": "$DEVICE",
    "timestamp": "$(date -Iseconds)",
    "status": "ready"
}
EOF
        ;;
        
    *)
        log "Unknown action: $ACTION"
        ;;
esac

exit 0
