#!/bin/bash
# Manual hotspot test script
# This replicates what Rustyjack does, step by step, for debugging

set -e

# Configuration
AP_IFACE="${1:-wlan1}"
SSID="${2:-rustyjack-test}"
CHANNEL="${3:-6}"
IP="10.20.30.1"

echo "=========================================="
echo "Manual Hotspot Start Test"
echo "=========================================="
echo "AP Interface: $AP_IFACE"
echo "SSID: $SSID"
echo "Channel: $CHANNEL"
echo "IP: $IP"
echo "=========================================="
echo

# Function to run commands with logging
run_cmd() {
    echo "> $@"
    "$@"
    local ret=$?
    if [ $ret -ne 0 ]; then
        echo "  [ERROR] Command failed with exit code $ret"
        return $ret
    fi
    echo "  [OK]"
    return 0
}

# 1. Stop existing processes
echo "1. Stopping existing hostapd/dnsmasq..."
pkill -f hostapd || true
pkill -f dnsmasq || true
sleep 1

# 2. Stop wpa_supplicant on the interface
echo
echo "2. Stopping wpa_supplicant on $AP_IFACE..."
pkill -f "wpa_supplicant.*$AP_IFACE" || true
sleep 1

# 3. Set interface to unmanaged
echo
echo "3. Setting $AP_IFACE to unmanaged by NetworkManager..."
if command -v nmcli &> /dev/null; then
    run_cmd nmcli device set "$AP_IFACE" managed no || true
else
    echo "  [SKIP] nmcli not available"
fi
sleep 1

# 4. Unblock RF-kill
echo
echo "4. Unblocking RF-kill..."
run_cmd rfkill unblock all
sleep 1

# 5. Show RF-kill status
echo
echo "5. Current RF-kill status:"
rfkill list
echo

# 6. Configure interface
echo "6. Configuring interface $AP_IFACE..."
run_cmd ip link set "$AP_IFACE" down
run_cmd ip addr flush dev "$AP_IFACE"
run_cmd ip addr add "$IP/24" dev "$AP_IFACE"
run_cmd ip link set "$AP_IFACE" up
sleep 2

# 7. Verify interface is up
echo
echo "7. Verifying interface status..."
ip addr show "$AP_IFACE" | grep inet || echo "  [WARNING] No IP assigned"
ip link show "$AP_IFACE" | grep -q "state UP" && echo "  [OK] Interface is UP" || echo "  [ERROR] Interface is not UP"
echo

# 8. Final RF-kill check before hostapd
echo "8. Final RF-kill unblock before hostapd..."
run_cmd rfkill unblock all
sleep 1

# 9. Create hostapd config
echo
echo "9. Creating hostapd config..."
CONF_DIR="/tmp/hotspot_test"
mkdir -p "$CONF_DIR"

cat > "$CONF_DIR/hostapd.conf" <<EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0
EOF

echo "  [OK] Config written to $CONF_DIR/hostapd.conf"
cat "$CONF_DIR/hostapd.conf"
echo

# 10. Start hostapd
echo "10. Starting hostapd..."
echo "Command: hostapd -B $CONF_DIR/hostapd.conf"
hostapd -B "$CONF_DIR/hostapd.conf"
local ret=$?
if [ $ret -ne 0 ]; then
    echo "  [ERROR] hostapd failed to start"
    echo
    echo "Checking syslog for errors:"
    tail -20 /var/log/syslog | grep -i hostapd || echo "No recent hostapd logs"
    exit 1
fi

sleep 3

# 11. Check if hostapd is running
echo
echo "11. Checking if hostapd is running..."
if pgrep -f "hostapd.*$CONF_DIR" > /dev/null; then
    echo "  [OK] hostapd is running (PID: $(pgrep -f "hostapd.*$CONF_DIR"))"
else
    echo "  [ERROR] hostapd is not running!"
    echo
    echo "Recent syslog entries:"
    tail -30 /var/log/syslog | grep -i hostapd
    exit 1
fi

echo
echo "=========================================="
echo "SUCCESS! Hotspot is running"
echo "=========================================="
echo "SSID: $SSID"
echo "Interface: $AP_IFACE"
echo "IP: $IP"
echo
echo "To stop:"
echo "  pkill -f hostapd"
echo "  ip addr flush dev $AP_IFACE"
echo "  nmcli device set $AP_IFACE managed yes"
echo
echo "To check status:"
echo "  iw dev $AP_IFACE info"
echo "  journalctl -n 50 | grep hostapd"
echo "=========================================="
