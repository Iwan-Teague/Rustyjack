# Rustyjack Hotspot - Quick Command Reference

## Emergency Recovery (Do This First!)
```bash
cd ~/Rustyjack/scripts
chmod +x recover_service.sh
sudo ./recover_service.sh
```

## Deploy the Fix
```bash
cd ~/Rustyjack
git pull
cargo build --release
sudo systemctl restart rustyjack
journalctl -u rustyjack -f
```

## Health Checks
```bash
# Check SD card health
sudo ./scripts/check_sd_health.sh

# Check hotspot status
sudo ./scripts/check_hotspot_status.sh

# Check RF-kill
sudo rfkill list

# Check NetworkManager
nmcli device status

# Check running processes
ps aux | grep -E "hostapd|dnsmasq|rustyjack"
```

## Service Control
```bash
# View logs (real-time)
journalctl -u rustyjack -f

# View recent logs
journalctl -u rustyjack -n 100

# Restart service
sudo systemctl restart rustyjack

# Stop service
sudo systemctl stop rustyjack

# Start service
sudo systemctl start rustyjack

# Check status
sudo systemctl status rustyjack
```

## Manual Hotspot Control
```bash
# Start hotspot manually (for testing)
cd ~/Rustyjack/scripts
sudo ./test_hotspot_manual.sh wlan0 test-ssid 6

# Stop hotspot manually
sudo pkill -f hostapd
sudo pkill -f dnsmasq
sudo nmcli device set wlan0 managed yes
sudo ip addr flush dev wlan0
```

## Fix RF-kill Issues
```bash
# Unblock all wireless devices
sudo rfkill unblock all

# Check status
sudo rfkill list

# Set interface to unmanaged
sudo nmcli device set wlan0 managed no

# Kill wpa_supplicant
sudo pkill -f "wpa_supplicant.*wlan0"
```

## SD Card Issues
```bash
# Check for I/O errors
sudo dmesg | grep -i "i/o error"
journalctl -n 100 | grep -i "input/output"

# Check if root is read-only
mount | grep "on / type"

# Remount root as read-write
sudo mount -o remount,rw /

# Check disk space
df -h

# Backup data (from another computer)
scp -r root@rustyjack:/root/Rustyjack ~/backup/
scp -r root@rustyjack:/root/loot ~/backup/
```

## Interface Management
```bash
# List all network interfaces
ip link show

# Check interface status
iw dev

# Bring interface down
sudo ip link set wlan0 down

# Bring interface up
sudo ip link set wlan0 up

# Flush IP addresses
sudo ip addr flush dev wlan0

# Add IP address
sudo ip addr add 10.20.30.1/24 dev wlan0

# Check if interface supports AP mode
iw list | grep -A 10 "Supported interface modes"
```

## Process Management
```bash
# Find hostapd PID
pgrep -f hostapd

# Find dnsmasq PID
pgrep -f dnsmasq

# Kill process by PID
sudo kill <PID>

# Kill process by name
sudo pkill -f hostapd
sudo pkill -f dnsmasq
sudo pkill -f wpa_supplicant
```

## Debugging
```bash
# Run rustyjack manually (see errors directly)
sudo ~/Rustyjack/target/release/rustyjack-ui

# Check hostapd config
cat /tmp/rustyjack_hotspot/hostapd.conf

# Check dnsmasq config
cat /tmp/rustyjack_hotspot/dnsmasq.conf

# Check hotspot state
cat /tmp/rustyjack_hotspot/state.json

# Test hostapd manually
sudo hostapd -dd /tmp/rustyjack_hotspot/hostapd.conf

# Check system logs
sudo tail -50 /var/log/syslog | grep -E "hostapd|dnsmasq|rfkill"
```

## Common Issues & Fixes

### Issue: RF-kill blocking
```bash
sudo rfkill unblock all
sudo nmcli device set wlan0 managed no
sudo pkill -f "wpa_supplicant.*wlan0"
```

### Issue: Service won't start
```bash
sudo systemctl reset-failed rustyjack
sudo mount -o remount,rw /
cd ~/Rustyjack && cargo build --release
sudo systemctl start rustyjack
```

### Issue: Hotspot won't start again after stop
```bash
# This should be fixed in the new code!
# But if issues persist:
sudo rfkill unblock all
sudo nmcli device set wlan0 managed no
sudo systemctl restart rustyjack
```

### Issue: NetworkManager interfering
```bash
sudo nmcli device set wlan0 managed no
sudo systemctl restart NetworkManager
```

### Issue: Can't connect to hotspot
```bash
# Check hostapd is running
ps aux | grep hostapd

# Check dnsmasq is running
ps aux | grep dnsmasq

# Check interface has IP
ip addr show wlan0 | grep inet

# Check RF-kill
sudo rfkill list
```

## File Locations
```
Hotspot configs:    /tmp/rustyjack_hotspot/
State file:         /tmp/rustyjack_hotspot/state.json
Binary:             /root/Rustyjack/target/release/rustyjack-ui
Service file:       /etc/systemd/system/rustyjack.service
Scripts:            /root/Rustyjack/scripts/
Logs:               journalctl -u rustyjack
```

## Quick Test Sequence
```bash
# 1. Start hotspot from UI
# 2. Check it's running:
ps aux | grep -E "hostapd|dnsmasq"
sudo rfkill list
iw dev wlan0 info

# 3. Connect from phone
# 4. Stop hotspot from UI
# 5. Check it stopped cleanly:
ps aux | grep -E "hostapd|dnsmasq"  # Should be empty
nmcli device status  # wlan0 should be managed

# 6. Start hotspot again - should work immediately!
```
