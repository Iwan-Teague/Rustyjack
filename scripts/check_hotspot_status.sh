#!/bin/bash
# Hotspot debugging helper script
# Run this on the Pi to check RF-kill and NetworkManager status

echo "=========================================="
echo "Rustyjack Hotspot Status Check"
echo "=========================================="
echo

echo "1. RF-kill Status:"
echo "------------------"
rfkill list
echo

echo "2. NetworkManager Device Status:"
echo "--------------------------------"
nmcli device status 2>/dev/null || echo "NetworkManager not available"
echo

echo "3. Wireless Interfaces:"
echo "----------------------"
iw dev
echo

echo "4. Running Hotspot Processes:"
echo "----------------------------"
echo "hostapd:"
ps aux | grep -E '[h]ostapd' || echo "  Not running"
echo
echo "dnsmasq:"
ps aux | grep -E '[d]nsmasq.*rustyjack' || echo "  Not running"
echo

echo "5. wpa_supplicant Processes:"
echo "---------------------------"
ps aux | grep -E '[w]pa_supplicant' || echo "  Not running"
echo

echo "6. Hotspot State File:"
echo "---------------------"
if [ -f /tmp/rustyjack_hotspot/state.json ]; then
    echo "Found state file:"
    cat /tmp/rustyjack_hotspot/state.json
else
    echo "No state file (hotspot not running)"
fi
echo

echo "7. Interface IP Addresses:"
echo "-------------------------"
ip -4 addr show | grep -E "^[0-9]+:|inet " | sed 's/^[0-9]*: //'
echo

echo "8. Recent Rustyjack Logs:"
echo "------------------------"
journalctl -u rustyjack --no-pager -n 30 | grep -E "\[HOTSPOT\]|rfkill"
echo

echo "=========================================="
echo "Commands to manually fix RF-kill issues:"
echo "=========================================="
echo "# Unblock all RF-kill devices:"
echo "sudo rfkill unblock all"
echo
echo "# Set interface to unmanaged (replace wlan1 with your AP interface):"
echo "sudo nmcli device set wlan1 managed no"
echo
echo "# Kill interfering processes:"
echo "sudo pkill -f 'wpa_supplicant.*wlan1'"
echo "sudo pkill -f hostapd"
echo "sudo pkill -f dnsmasq"
echo
echo "# Bring interface down and up:"
echo "sudo ip link set wlan1 down"
echo "sudo ip link set wlan1 up"
echo
echo "# Check if interface can do AP mode:"
echo "iw list | grep -A 10 'Supported interface modes'"
echo
