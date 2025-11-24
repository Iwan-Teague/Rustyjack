# WiFi Setup Guide for Raspberry Pi

## Quick Fix for "Wi-Fi blocked by rfkill"

### Option 1: Automated Setup Script (Recommended)

On your Pi via SSH (connected through Ethernet):

```bash
cd ~/Rustyjack
sudo chmod +x setup_wifi.sh
sudo ./setup_wifi.sh
```

The script will:
1. Check WiFi hardware
2. Unblock rfkill
3. Set WiFi country code (required by regulations)
4. Bring up WiFi interfaces
5. Scan for networks

### Option 2: Manual Setup

#### Step 1: Unblock WiFi
```bash
sudo rfkill unblock wifi
sudo rfkill unblock all
```

#### Step 2: Set Country Code (Required!)
```bash
sudo raspi-config
```
- Select: **5 Localisation Options**
- Select: **L4 WLAN Country**
- Choose your country (e.g., US, GB, DE)
- Exit and reboot

**Or via command line:**
```bash
sudo raspi-config nonint do_wifi_country US  # Replace US with your country code
```

#### Step 3: Verify WiFi Status
```bash
rfkill list wifi
```
Should show: `Soft blocked: no` and `Hard blocked: no`

#### Step 4: Bring Up Interface
```bash
sudo ip link set wlan0 up
```

#### Step 5: Scan for Networks
```bash
sudo iw dev wlan0 scan | grep SSID
```

## Connecting to WiFi

### Method 1: Using Rustyjack (After WiFi is unblocked)

From the device GUI:
1. **Main Menu → WiFi Manager → Scan for networks**
2. Select your network
3. Enter password (if using saved profile)

Or via CLI:
```bash
rustyjack wifi scan --interface wlan0
rustyjack wifi profile connect --ssid "YourNetwork" --password "YourPassword"
```

### Method 2: Using NetworkManager
```bash
# List available networks
nmcli dev wifi list

# Connect
sudo nmcli dev wifi connect "YourSSID" password "YourPassword"

# Check connection
nmcli connection show
```

### Method 3: Using wpa_supplicant (Manual)

1. Edit configuration:
```bash
sudo nano /etc/wpa_supplicant/wpa_supplicant.conf
```

2. Add network configuration:
```
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={
    ssid="YourNetworkName"
    psk="YourPassword"
    key_mgmt=WPA-PSK
}
```

3. Restart services:
```bash
sudo systemctl restart wpa_supplicant
sudo systemctl restart dhcpcd
```

4. Verify connection:
```bash
ip addr show wlan0
ping -c 4 8.8.8.8
```

## Troubleshooting

### Problem: "Operation not possible due to RF-kill"
**Solution:**
```bash
sudo rfkill unblock wifi
sudo ip link set wlan0 up
```

### Problem: "No wireless extensions"
**Solution:** Your interface might not support wireless. Check:
```bash
iw list  # Should show capabilities
lsusb    # Check if USB WiFi adapter is detected
```

### Problem: WiFi works but no internet
**Solution:**
```bash
# Check if you have an IP
ip addr show wlan0

# Check default route
ip route show

# Try to get IP via DHCP
sudo dhclient wlan0

# Check DNS
cat /etc/resolv.conf
```

### Problem: Country code keeps resetting
**Solution:** Make it permanent:
```bash
sudo raspi-config nonint do_wifi_country US
echo "country=US" | sudo tee -a /etc/wpa_supplicant/wpa_supplicant.conf
```

### Problem: WiFi interface not showing
**Solution:**
```bash
# Check if kernel module is loaded
lsmod | grep brcmfmac

# Load module if missing
sudo modprobe brcmfmac

# Check dmesg for errors
dmesg | grep -i wifi
dmesg | grep -i brcm
```

## Common Country Codes

| Code | Country |
|------|---------|
| US | United States |
| GB | United Kingdom |
| DE | Germany |
| FR | France |
| CA | Canada |
| AU | Australia |
| JP | Japan |
| CN | China |
| IN | India |
| NL | Netherlands |
| IT | Italy |
| ES | Spain |
| SE | Sweden |
| NO | Norway |
| BR | Brazil |

## After WiFi is Working

### Test Connectivity
```bash
# Check interface status
ip addr show wlan0

# Test local network
ping -c 4 192.168.1.1  # Your router

# Test internet
ping -c 4 8.8.8.8

# Test DNS
ping -c 4 google.com
```

### Use Rustyjack WiFi Features
```bash
# Hardware detection (see all interfaces)
rustyjack hardware detect

# Scan networks
rustyjack wifi scan

# View WiFi status
rustyjack wifi status

# List saved profiles
rustyjack wifi profile list
```

### Make WiFi Auto-Connect on Boot

1. Save network profile in Rustyjack:
```bash
rustyjack wifi profile connect --ssid "YourNetwork" --password "YourPassword" --remember
```

2. Or configure wpa_supplicant (see Method 3 above)

3. Enable services:
```bash
sudo systemctl enable wpa_supplicant
sudo systemctl enable dhcpcd
```

## Regulatory Information

**Why country code is required:**
- WiFi operates on radio frequencies regulated by each country
- Different countries allow different channels and power levels
- Setting the correct country code ensures legal compliance
- Failure to set it will block WiFi by default (rfkill)

**Legal Notice:** Always set the correct country code for your physical location. Using an incorrect country code may violate local regulations and cause interference with other devices.

## Pi Zero W 2 Specific Notes

The Raspberry Pi Zero W 2 has:
- **Built-in WiFi**: Cypress CYW43455 (802.11ac, 2.4/5GHz)
- **Interface name**: Usually `wlan0`
- **Driver**: `brcmfmac`

If built-in WiFi isn't working:
```bash
# Check if firmware is loaded
ls -la /lib/firmware/brcm/

# Re-enable WiFi in config.txt (if disabled)
sudo nano /boot/firmware/config.txt
# Ensure this line exists and is NOT commented:
# dtparam=wifi=on

# Reboot
sudo reboot
```

## Quick Command Reference

```bash
# Unblock WiFi
sudo rfkill unblock wifi

# Set country
sudo raspi-config nonint do_wifi_country US

# Bring up interface
sudo ip link set wlan0 up

# Scan networks
sudo iw dev wlan0 scan | grep SSID

# Connect (NetworkManager)
sudo nmcli dev wifi connect "SSID" password "PASSWORD"

# Check connection
ip addr show wlan0
ping -c 4 8.8.8.8

# View Rustyjack hardware
rustyjack hardware detect
```

---

**After following this guide, WiFi should be working and you can disconnect the Ethernet cable!**
