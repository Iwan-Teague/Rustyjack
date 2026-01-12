#!/bin/bash
# Enhanced WiFi Hotplug Handler for Rustyjack
# Handles USB WiFi adapter insertion/removal with actual RPC calls

set -e

RUSTYJACK_ROOT="${RUSTYJACK_ROOT:-/opt/rustyjack}"
DAEMON_SOCKET="/run/rustyjack/rustyjackd.sock"
LOG_FILE="/var/log/rustyjack_wifi_hotplug.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Function to call daemon RPC via socat
call_daemon_rpc() {
    local payload="$1"
    
    if [ ! -S "$DAEMON_SOCKET" ]; then
        log "ERROR: Daemon socket not found: $DAEMON_SOCKET"
        return 1
    fi
    
    log "Sending RPC request: $payload"
    
    # Send JSON-RPC request via socat with 5s timeout
    echo "$payload" | timeout 5 socat - UNIX-CONNECT:"$DAEMON_SOCKET" 2>&1 | tee -a "$LOG_FILE"
    return ${PIPESTATUS[0]}
}

# Check for required tools
for tool in socat iw; do
    if ! command -v "$tool" &> /dev/null; then
        log "ERROR: Required tool '$tool' not found"
        exit 1
    fi
done

ACTION="${1:-unknown}"
DEVICE="${2:-unknown}"

log "========================================"
log "Hotplug event triggered"
log "ACTION: $ACTION"
log "DEVICE: $DEVICE"
log "========================================"

case "$ACTION" in
    add)
        log "USB WiFi device inserted: $DEVICE"
        
        # Wait for device to settle and driver to load
        log "Waiting 2s for device initialization..."
        sleep 2
        
        # Check if new wireless interface appeared
        INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' | tr '\n' ' ')
        log "Detected wireless interfaces: ${INTERFACES:-none}"
        
        # Additional delay for driver stabilization
        log "Waiting additional 2s for driver stabilization..."
        sleep 2
        
        # Call HotplugNotify RPC
        PAYLOAD='{"jsonrpc":"2.0","method":"HotplugNotify","params":{},"id":1}'
        
        if call_daemon_rpc "$PAYLOAD"; then
            log "SUCCESS: Sent HotplugNotify to daemon"
        else
            log "ERROR: Failed to send HotplugNotify to daemon"
            exit 1
        fi
        ;;
        
    remove)
        log "USB WiFi device removed: $DEVICE"
        
        # Notify daemon immediately
        PAYLOAD='{"jsonrpc":"2.0","method":"HotplugNotify","params":{},"id":1}'
        
        if call_daemon_rpc "$PAYLOAD"; then
            log "SUCCESS: Sent HotplugNotify (removal) to daemon"
        else
            log "WARNING: Failed to send HotplugNotify (removal) to daemon"
        fi
        ;;
        
    *)
        log "WARNING: Unknown action: $ACTION"
        exit 0
        ;;
esac

log "Hotplug handler completed successfully"
exit 0
