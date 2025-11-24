#!/bin/bash
# WiFi Setup Helper for Raspberry Pi
# Fixes rfkill block and configures WiFi

set -e
COUNTRY=""
NONINTERACTIVE=0

# parse args: --country|-c <code> and -y/--yes for non-interactive
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c|--country)
            COUNTRY="$2"; shift 2;;
        -y|--yes|--noninteractive)
            NONINTERACTIVE=1; shift;;
        --help)
            echo "Usage: sudo ./setup_wifi.sh [-c|--country <CC>] [-y|--yes]"; exit 0;;
        *)
            # unknown arg
            echo "Unknown arg: $1"; echo "Usage: sudo ./setup_wifi.sh [-c|--country <CC>] [-y|--yes]"; exit 1;;
    esac
done

echo "=========================================="
echo "Rustyjack WiFi Setup Helper"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[ERROR] This script must be run as root"
    echo "Usage: sudo ./setup_wifi.sh"
    exit 1
fi

echo "[STEP 1] Checking WiFi hardware..."
if ! lsmod | grep -q brcmfmac; then
    echo "[WARNING] WiFi driver (brcmfmac) not loaded. This may be normal for some Pi models."
else
    echo "[OK] WiFi driver loaded"
fi

echo ""
echo "[STEP 2] Checking rfkill status..."
rfkill list all

echo ""
echo "[STEP 3] Unblocking WiFi via rfkill..."
rfkill unblock wifi
rfkill unblock all

echo ""
echo "[STEP 4] Setting WiFi country code..."
echo "Common country codes:"
echo "  US - United States"
echo "  GB - United Kingdom"
echo "  DE - Germany"
echo "  FR - France"
echo "  CA - Canada"
echo "  AU - Australia"
echo "  JP - Japan"
echo ""
# Use provided flag/env or prompt when interactive
COUNTRY_CODE="${COUNTRY:-${WIFI_COUNTRY:-}}"
if [ -z "$COUNTRY_CODE" ]; then
    # If interactive, attempt to detect or let user confirm; otherwise default to US
    if [ "$NONINTERACTIVE" -eq 1 ]; then
        COUNTRY_CODE=US
        echo "[INFO] No country provided in non-interactive mode — defaulting to $COUNTRY_CODE"
    else
        # Try to detect via locale if available
        DETECTED=""
        if [ -n "${LANG:-}" ] && echo "$LANG" | grep -q "_"; then
            DETECTED=$(echo "$LANG" | awk -F[_.] '{print toupper($2)}') || true
        fi
        if [ -z "$DETECTED" ] && command -v curl >/dev/null 2>&1; then
            DETECTED=$(curl -fsS --max-time 3 https://ipapi.co/country/ 2>/dev/null || true)
            DETECTED=$(echo "$DETECTED" | tr '[:lower:]' '[:upper:]')
        fi

        if [ -n "$DETECTED" ]; then
            read -p "Detected country $DETECTED — press Enter to accept or type another (e.g., US): " input
            if [ -n "$input" ]; then
                COUNTRY_CODE="$input"
            else
                COUNTRY_CODE="$DETECTED"
            fi
        else
            # Fall back to US if user hits enter
            read -p "Enter your country code (e.g., US) [default US]: " input
            if [ -z "$input" ]; then
                COUNTRY_CODE=US
            else
                COUNTRY_CODE="$input"
            fi
        fi
    fi
fi

# Convert to uppercase
COUNTRY_CODE=$(echo "$COUNTRY_CODE" | tr '[:lower:]' '[:upper:]')

# Update wpa_supplicant configuration
if [ -f /etc/wpa_supplicant/wpa_supplicant.conf ]; then
    # Check if country line exists
    if grep -q "^country=" /etc/wpa_supplicant/wpa_supplicant.conf; then
        sed -i "s/^country=.*/country=$COUNTRY_CODE/" /etc/wpa_supplicant/wpa_supplicant.conf
        echo "[OK] Updated country code in wpa_supplicant.conf"
    else
        sed -i "1s/^/country=$COUNTRY_CODE\n/" /etc/wpa_supplicant/wpa_supplicant.conf
        echo "[OK] Added country code to wpa_supplicant.conf"
    fi
fi

# Set via raspi-config method (if available)
if command -v raspi-config &> /dev/null; then
    raspi-config nonint do_wifi_country "$COUNTRY_CODE" 2>/dev/null || echo "[WARNING] raspi-config wifi country set failed (may not be available)"
fi

echo ""
echo "[STEP 5] Bringing up WiFi interfaces..."
for iface in wlan0 wlan1 wlan2; do
    if ip link show "$iface" &> /dev/null; then
        echo "  - Bringing up $iface"
        ip link set "$iface" up || echo "    [WARNING] Failed to bring up $iface"
        sleep 1
    fi
done

echo ""
echo "[STEP 6] Verifying WiFi status..."
echo ""
rfkill list wifi

echo ""
echo "[STEP 7] Scanning for networks (this may take 10 seconds)..."
for iface in wlan0 wlan1 wlan2; do
    if ip link show "$iface" &> /dev/null 2>&1; then
        echo ""
        echo "Scanning on $iface:"
        timeout 10 iw dev "$iface" scan 2>/dev/null | grep "SSID:" | head -5 || echo "  [INFO] No networks found or scan failed"
    fi
done

echo ""
echo "=========================================="
echo "[SUCCESS] WiFi setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Check available networks:"
echo "   sudo iw dev wlan0 scan | grep SSID"
echo ""
echo "2. Connect to a network using Rustyjack:"
echo "   - Navigate to Main Menu → WiFi Manager → Scan for networks"
echo "   - Or use: rustyjack wifi scan"
echo ""
echo "3. Or manually connect:"
echo "   sudo nmcli dev wifi connect \"YOUR_SSID\" password \"YOUR_PASSWORD\""
echo ""
echo "4. Verify connection:"
echo "   ip addr show wlan0"
echo ""
echo "Current WiFi interfaces:"
ip -br link show | grep wlan || echo "  [WARNING] No wlan interfaces found"
echo ""
