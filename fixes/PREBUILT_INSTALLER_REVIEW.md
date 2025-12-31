# Prebuilt Installer Review & Fixes

## Original Issues Found

### ❌ Critical Missing Components

1. **No APT package installation**
   - Missing: `isc-dhcp-client`, `network-manager`, `wpasupplicant`, `hostapd`, `dnsmasq`, `rfkill`
   - Missing: Firmware packages (`firmware-realtek`, `firmware-atheros`, etc.)
   - Impact: Rustyjack won't have required system utilities

2. **No hardware setup**
   - Missing: I2C/SPI enablement (`dtparam=i2c_arm=on`, `dtparam=spi=on`)
   - Missing: Kernel module loading (`i2c-bcm2835`, `spi_bcm2835`, `spidev`)
   - Missing: SPI overlay (`dtoverlay=spi0-2cs`)
   - Missing: GPIO pull-up configuration for buttons
   - Impact: Display and buttons won't work

3. **No /boot/firmware/config.txt handling**
   - Missing: Config file detection and creation
   - Missing: `add_dtparam` function
   - Impact: Hardware won't be configured

4. **No old binary removal**
   - Issue: Installing over existing binary without removing it first
   - Impact: Could cause issues if old binary is running or locked

### ⚠️ Minor Issues

5. **Directory creation typo**
   - Line 164: `sudo mkdir -p "$PROJECT_ROOT/loot"/ {Wireless,Ethernet,reports}`
   - Should be: `sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Ethernet,reports}`
   - Impact: Creates wrong directory structure

6. **Missing health checks**
   - No SPI device verification
   - No Wi‑Fi control check (wpa_cli/nmcli)
   - No service status verification

7. **Service description**
   - Says "(prebuilt)" but doesn't indicate it's a release or debug build
   - Should clarify binary type

---

## What Was Fixed

### ✅ Added Missing Components

1. **APT Package Installation** (Lines 127-216)
   ```bash
   PACKAGES=(
     wpasupplicant network-manager
     isc-dhcp-client hostapd dnsmasq rfkill
     git i2c-tools curl
   )
   FIRMWARE_PACKAGES=(
     firmware-linux-nonfree firmware-realtek firmware-atheros 
     firmware-ralink firmware-misc-nonfree
   )
   ```

2. **Hardware Setup** (Lines 218-246)
   ```bash
   # I2C/SPI enablement
   add_dtparam dtparam=i2c_arm=on
   add_dtparam dtparam=i2c1=on
   add_dtparam dtparam=spi=on
   add_dtparam dtparam=wifi=on
   
   # Kernel modules
   MODULES=(i2c-bcm2835 i2c-dev spi_bcm2835 spidev)
   
   # SPI overlay
   echo 'dtoverlay=spi0-2cs' | sudo tee -a "$CFG"
   
   # GPIO pull-ups for buttons
   echo 'gpio=6,19,5,26,13,21,20,16=pu' | sudo tee -a "$CFG"
   ```

3. **Config File Handling** (Lines 127-143)
   ```bash
   CFG=/boot/firmware/config.txt; [[ -f $CFG ]] || CFG=/boot/config.txt
   add_dtparam() {
     # Function to add dtparam entries
   }
   ```

4. **Old Binary Removal** (Lines 259-261)
   ```bash
   step "Removing old binary (if present)..."
   sudo rm -f /usr/local/bin/$BINARY_NAME
   ```

5. **Fixed Directory Creation** (Line 267)
   ```bash
   # Fixed: removed space before {Wireless,Ethernet,reports}
   sudo mkdir -p "$PROJECT_ROOT/loot"/{Wireless,Ethernet,reports}
   ```

6. **Health Checks** (Lines 304-337)
   ```bash
   # SPI device check
   if ls /dev/spidev* 2>/dev/null | grep -q spidev0.0; then
     info "[OK] SPI device found"
   fi
   
   # Wi-Fi control check
   if cmd wpa_cli || cmd nmcli; then
     info "[OK] Wi-Fi control tools found"
   fi
   
   # Service status check
   if systemctl is-active --quiet rustyjack.service; then
     info "[OK] Rustyjack service is running"
   fi
   ```

---

## Comparison: Before vs After

| Feature | Original | Fixed | Status |
|---------|----------|-------|--------|
| APT packages | ❌ Missing | ✅ Added | FIXED |
| I2C/SPI setup | ❌ Missing | ✅ Added | FIXED |
| GPIO pull-ups | ❌ Missing | ✅ Added | FIXED |
| Config.txt handling | ❌ Missing | ✅ Added | FIXED |
| Old binary removal | ❌ Missing | ✅ Added | FIXED |
| Directory creation | ⚠️ Typo | ✅ Fixed | FIXED |
| Health checks | ⚠️ Basic | ✅ Complete | FIXED |
| DNS/resolver mgmt | ✅ Present | ✅ Present | OK |
| Service creation | ✅ Present | ✅ Present | OK |
| Helper scripts | ✅ Present | ✅ Present | OK |
| Udev rules | ✅ Present | ✅ Present | OK |

---

## What It Does Now (After Fixes)

### 1. Environment Setup
- ✅ Ensures root filesystem is read-write
- ✅ Bootstraps DNS resolvers
- ✅ Detects /boot/firmware/config.txt or /boot/config.txt

### 2. System Packages
- ✅ Installs Wi‑Fi control tools (wpasupplicant, network-manager)
- ✅ Installs networking tools (isc-dhcp-client, hostapd, dnsmasq, rfkill)
- ✅ Installs firmware packages (Realtek, Atheros, Ralink)
- ✅ Handles missing packages gracefully

### 3. Hardware Configuration
- ✅ Enables I2C and SPI in config.txt
- ✅ Loads kernel modules (i2c-bcm2835, spi_bcm2835, spidev)
- ✅ Adds SPI overlay (spi0-2cs)
- ✅ Configures GPIO pull-ups for buttons

### 4. Binary Installation
- ✅ Validates prebuilt binary exists
- ✅ Checks binary architecture (ARM32)
- ✅ Stops existing service
- ✅ **Removes old binary first**
- ✅ Installs new binary to /usr/local/bin/

### 5. Runtime Directories
- ✅ Creates loot directories (Wireless, Ethernet, reports)
- ✅ Creates WiFi profiles directory
- ✅ Sets correct permissions
- ✅ Creates sample WiFi profile

### 6. Helper Scripts & Rules
- ✅ Installs WiFi driver installer script
- ✅ Installs WiFi hotplug script
- ✅ Installs udev rules for USB WiFi auto-detection

### 7. Service Management
- ✅ Creates systemd service
- ✅ Enables service
- ✅ Starts service immediately

### 8. DNS/Network Control
- ✅ Claims /etc/resolv.conf for Rustyjack
- ✅ Disables competing DNS managers (systemd-resolved, dhcpcd, resolvconf)
- ✅ Configures NetworkManager to not touch resolv.conf

### 9. Health Checks
- ✅ Verifies SPI device exists
- ✅ Checks Wi‑Fi control tools installation
- ✅ Confirms wpa_cli/nmcli presence
- ✅ Validates binary installation
- ✅ Checks service status

### 10. Reboot
- ✅ Reboots to apply hardware changes (can be skipped with SKIP_REBOOT=1)

---

## Usage

### Basic Usage
```bash
# For ARM32 (32-bit Pi OS)
sudo PREBUILT_DIR=prebuilt/arm32 ./install_rustyjack_prebuilt.sh

# For ARM64 (64-bit Pi OS)
sudo PREBUILT_DIR=prebuilt/arm64 ./install_rustyjack_prebuilt.sh

# For ARM64 with specific binary
sudo PREBUILT_DIR=target-64/aarch64-unknown-linux-gnu/release ./install_rustyjack_prebuilt.sh
```

### Skip Reboot
```bash
sudo SKIP_REBOOT=1 PREBUILT_DIR=prebuilt/arm32 ./install_rustyjack_prebuilt.sh
```

### Custom Project Root
```bash
sudo PROJECT_ROOT=/opt/rustyjack PREBUILT_DIR=prebuilt/arm32 ./install_rustyjack_prebuilt.sh
```

---

## Differences from install_rustyjack_dev.sh

| Feature | Dev Installer | Prebuilt Installer | Notes |
|---------|---------------|-------------------|-------|
| Build Rust code | ✅ Yes (debug) | ❌ No | Prebuilt uses existing binary |
| Cargo/rustup check | ✅ Yes | ❌ No | Not needed for prebuilt |
| Build tools packages | ✅ Yes | ❌ No | No compilation needed |
| Kernel headers | ✅ Yes | ❌ No | Only for DKMS drivers |
| Swap space check | ✅ Yes | ❌ No | Only needed for compilation |
| RUST_BACKTRACE | ✅ Yes | ❌ No | Debug feature |
| Service description | "DEBUG BUILD" | "prebuilt" | Clarifies origin |
| Everything else | ✅ | ✅ | **Now identical** |

**The prebuilt installer now has feature parity with the dev installer, except for build-specific steps.**

---

## Testing Checklist

After running the fixed prebuilt installer, verify:

### Hardware
- [ ] `/dev/spidev0.0` exists
- [ ] `/dev/i2c-1` exists
- [ ] Buttons respond (GPIOs 6, 19, 5, 26, 13, 21, 20, 16)
- [ ] Display works (ST7735S on SPI)

### Software
- [ ] `/usr/local/bin/rustyjack-ui` exists and is executable
- [ ] `systemctl status rustyjack.service` shows "active (running)"
- [ ] `journalctl -u rustyjack.service -n 50` shows startup logs
- [ ] `which wpa_cli` and `which nmcli` return paths
- [ ] `rfkill list` shows wireless devices

### Network
- [ ] `/etc/resolv.conf` is a regular file (not symlink)
- [ ] `/etc/NetworkManager/NetworkManager.conf` has `dns=none`
- [ ] `systemctl status systemd-resolved` shows "inactive"
- [ ] `systemctl status dhcpcd` shows "inactive" or not found

### Files
- [ ] `/root/Rustyjack/loot/Wireless/` exists
- [ ] `/root/Rustyjack/wifi/profiles/sample.json` exists
- [ ] `/etc/udev/rules.d/99-rustyjack-wifi.rules` exists
- [ ] `/etc/systemd/system/rustyjack.service` exists

---

## Conclusion

### Original Status: ❌ BROKEN
The prebuilt installer was **missing critical setup steps** and would fail to configure hardware properly.

### Current Status: ✅ FIXED
The prebuilt installer now:
- ✅ Installs all required system packages
- ✅ Configures hardware (I2C, SPI, GPIOs)
- ✅ Removes old binaries before installing
- ✅ Has proper health checks
- ✅ Matches the dev installer's functionality (minus build steps)

### Logic Assessment: ✅ NOW SOUND
The installer will now properly set up Rustyjack on a fresh Raspberry Pi using a prebuilt binary.
