#!/bin/bash
# WiFi USB Dongle Driver Auto-Installer
# Detects chipset and installs appropriate drivers

set -e

RUSTYJACK_ROOT="${RUSTYJACK_ROOT:-/opt/rustyjack}"
LOG_FILE="/var/log/rustyjack_wifi_driver.log"
STATUS_FILE="/tmp/rustyjack_wifi_status"
LOCK_FILE="/tmp/rustyjack_wifi_install.lock"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $msg" >> "$LOG_FILE"
    
    case "$level" in
        INFO)  echo -e "${BLUE}[INFO]${NC} $msg" ;;
        OK)    echo -e "${GREEN}[OK]${NC} $msg" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $msg" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $msg" ;;
    esac
}

set_status() {
    echo "$1" > "$STATUS_FILE"
}

cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# Prevent multiple instances
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if kill -0 "$pid" 2>/dev/null; then
        log "WARN" "Another installation is already running (PID: $pid)"
        exit 1
    fi
fi
echo $$ > "$LOCK_FILE"

# Database of known WiFi chipsets and their drivers
# Format: VENDOR_ID:PRODUCT_ID:CHIPSET_NAME:DRIVER_PACKAGE:DRIVER_TYPE
declare -A WIFI_DRIVERS=(
    # Realtek RTL8812AU/RTL8821AU - Very popular for monitor mode
    ["0bda:8812"]="RTL8812AU:realtek-rtl88xxau-dkms:dkms"
    ["0bda:881a"]="RTL8821AU:realtek-rtl88xxau-dkms:dkms"
    ["0bda:8811"]="RTL8811AU:realtek-rtl88xxau-dkms:dkms"
    
    # Realtek RTL8814AU - High-power adapter
    ["0bda:8813"]="RTL8814AU:realtek-rtl88xxau-dkms:dkms"
    
    # Realtek RTL88x2BU
    ["0bda:b812"]="RTL8812BU:rtl88x2bu-dkms:dkms"
    ["0bda:c812"]="RTL8812BU:rtl88x2bu-dkms:dkms"
    # TP-Link TL-WN823N (RTL8192EU)
    ["2357:0109"]="RTL8192EU:rtl8192eu-dkms:dkms"
    
    # Realtek RTL8188EUS - Built-in usually, but sometimes needs firmware
    ["0bda:8179"]="RTL8188EUS:firmware-realtek:firmware"
    
    # Realtek RTL8192EU
    ["0bda:818b"]="RTL8192EU:rtl8192eu-dkms:dkms"
    
    # Ralink/MediaTek MT7610U
    ["148f:7610"]="MT7610U:firmware-misc-nonfree:firmware"
    ["0e8d:7610"]="MT7610U:firmware-misc-nonfree:firmware"
    
    # Ralink RT5370 - Very common cheap adapter
    ["148f:5370"]="RT5370:firmware-ralink:firmware"
    ["148f:5372"]="RT5370:firmware-ralink:firmware"
    
    # Ralink RT3070
    ["148f:3070"]="RT3070:firmware-ralink:firmware"
    
    # Atheros AR9271 - Popular for pentesting (Alfa AWUS036NHA)
    ["0cf3:9271"]="AR9271:firmware-atheros:firmware"
    
    # MediaTek MT7601U
    ["148f:7601"]="MT7601U:firmware-misc-nonfree:firmware"
    ["0e8d:7601"]="MT7601U:firmware-misc-nonfree:firmware"
    
    # Realtek RTL8723BU
    ["0bda:b720"]="RTL8723BU:rtl8723bu-dkms:dkms"
    
    # TP-Link specific (use same Realtek drivers)
    ["2357:010c"]="RTL8812AU:realtek-rtl88xxau-dkms:dkms"
    ["2357:0101"]="RTL8812AU:realtek-rtl88xxau-dkms:dkms"
    ["2357:0115"]="RTL8812AU:realtek-rtl88xxau-dkms:dkms"
    
    # Alfa Network adapters
    ["0bda:8187"]="RTL8187:rtl8187-dkms:kernel"  # Built into kernel
    ["0cf3:7015"]="AR9271:firmware-atheros:firmware"
)

# Chipsets that are built into the kernel and need no extra drivers
declare -A BUILTIN_CHIPSETS=(
    ["0bda:8176"]="RTL8188CUS"
    ["0bda:8178"]="RTL8192CU"
    ["0bda:8179"]="RTL8188EUS"
    ["148f:5370"]="RT5370"
    ["148f:3070"]="RT3070"
    ["0cf3:9271"]="AR9271"
    ["148f:7601"]="MT7601U"
)

detect_new_wifi_devices() {
    log "INFO" "Scanning for USB WiFi devices..."
    
    local devices=()
    
    # Get all USB devices with wireless capability
    for device in /sys/bus/usb/devices/*/; do
        if [ -f "${device}idVendor" ] && [ -f "${device}idProduct" ]; then
            local vendor=$(cat "${device}idVendor" 2>/dev/null)
            local product=$(cat "${device}idProduct" 2>/dev/null)
            local usb_id="${vendor}:${product}"
            
            # Check if this is a known WiFi device
            if [ -n "${WIFI_DRIVERS[$usb_id]}" ] || [ -n "${BUILTIN_CHIPSETS[$usb_id]}" ]; then
                devices+=("$usb_id")
                log "INFO" "Found WiFi device: $usb_id"
            fi
        fi
    done
    
    # Also check lsusb for more comprehensive detection
    if command -v lsusb &>/dev/null; then
        while IFS= read -r line; do
            local usb_id=$(echo "$line" | grep -oP 'ID \K[0-9a-f]{4}:[0-9a-f]{4}')
            if [ -n "$usb_id" ] && [ -n "${WIFI_DRIVERS[$usb_id]}" ]; then
                if [[ ! " ${devices[*]} " =~ " ${usb_id} " ]]; then
                    devices+=("$usb_id")
                    log "INFO" "Found WiFi device via lsusb: $usb_id"
                fi
            fi
        done < <(lsusb 2>/dev/null)
    fi
    
    echo "${devices[@]}"
}

check_interface_exists() {
    local chipset="$1"
    local timeout="${2:-10}"
    local elapsed=0
    
    log "INFO" "Waiting for network interface to appear (timeout: ${timeout}s)..."
    
    while [ $elapsed -lt $timeout ]; do
        # Check for new wireless interfaces
        for iface in /sys/class/net/*/wireless; do
            if [ -d "$iface" ]; then
                local ifname=$(basename $(dirname "$iface"))
                if [ "$ifname" != "lo" ]; then
                    log "OK" "Interface $ifname is available"
                    echo "$ifname"
                    return 0
                fi
            fi
        done
        
        sleep 1
        ((elapsed++))
    done
    
    return 1
}

check_monitor_mode_support() {
    local iface="$1"

    local phy_link="/sys/class/net/$iface/phy80211"
    if [ -L "$phy_link" ]; then
        local phy=$(basename "$(readlink -f "$phy_link")")
        local debug_file="/sys/kernel/debug/ieee80211/$phy/supported_iftypes"
        if [ -r "$debug_file" ]; then
            if grep -q "monitor" "$debug_file"; then
                log "OK" "Interface $iface supports monitor mode"
                return 0
            fi
            log "WARN" "Interface $iface does not advertise monitor mode"
            return 1
        fi
    fi

    log "INFO" "Monitor mode verification skipped for $iface (debugfs not available)"
    return 1
}

install_dkms_prerequisites() {
    log "INFO" "Installing DKMS prerequisites..."
    set_status "INSTALLING_PREREQUISITES"
    
    # Check if we have internet
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        log "ERROR" "No internet connection available"
        return 1
    fi
    
    apt-get update -qq || {
        log "ERROR" "Failed to update package lists"
        return 1
    }
    
    # Install build essentials and DKMS
    apt-get install -y -qq \
        dkms \
        build-essential \
        linux-headers-$(uname -r) \
        bc \
        libelf-dev \
        2>/dev/null || {
        log "WARN" "Some prerequisites may have failed to install"
    }
    
    log "OK" "Prerequisites installed"
    return 0
}

install_driver_package() {
    local package="$1"
    local driver_type="$2"
    
    log "INFO" "Installing driver package: $package"
    set_status "INSTALLING_DRIVER:$package"
    
    case "$driver_type" in
        dkms)
            # DKMS drivers need headers and build tools
            install_dkms_prerequisites || return 1
            
            # Try apt first
            if apt-cache show "$package" &>/dev/null; then
                apt-get install -y "$package" || {
                    log "WARN" "Package not in apt, trying alternative sources..."
                }
            fi
            
            # For realtek-rtl88xxau-dkms, may need to add repository or build from source
            if [ "$package" = "realtek-rtl88xxau-dkms" ]; then
                if ! dpkg -l | grep -q "realtek-rtl88xxau"; then
                    log "INFO" "Building RTL88xxAU driver from source..."
                    install_rtl88xxau_from_source || return 1
                fi
            elif [ "$package" = "rtl88x2bu-dkms" ]; then
                if ! dpkg -l | grep -q "rtl88x2bu"; then
                    log "INFO" "Building RTL88x2BU driver from source..."
                    install_rtl88x2bu_from_source || return 1
                fi
            elif [ "$package" = "rtl8192eu-dkms" ]; then
                if ! dpkg -l | grep -q "8192eu"; then
                    log "INFO" "Building RTL8192EU driver from source..."
                    install_rtl8192eu_from_source || return 1
                fi
            fi
            ;;
            
        firmware)
            # Firmware packages are usually straightforward
            apt-get install -y "$package" || {
                log "ERROR" "Failed to install firmware package: $package"
                return 1
            }
            ;;
            
        kernel)
            # Already in kernel, just need to modprobe
            log "INFO" "Driver is built into kernel, loading module..."
            ;;
    esac
    
    log "OK" "Driver package installed: $package"
    return 0
}

install_rtl88xxau_from_source() {
    local build_dir="/tmp/rtl8812au-build"
    
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Clone the aircrack-ng maintained driver (best for monitor mode)
    log "INFO" "Cloning RTL8812AU driver repository..."
    git clone --depth=1 https://github.com/aircrack-ng/rtl8812au.git . || {
        log "ERROR" "Failed to clone RTL8812AU repository"
        return 1
    }
    
    # Build for ARM (Raspberry Pi)
    log "INFO" "Building driver (this may take a few minutes)..."
    
    # Detect architecture
    if uname -m | grep -q "aarch64"; then
        sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/' Makefile
        sed -i 's/CONFIG_PLATFORM_ARM64_RPI = n/CONFIG_PLATFORM_ARM64_RPI = y/' Makefile
    elif uname -m | grep -q "arm"; then
        sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/' Makefile
        sed -i 's/CONFIG_PLATFORM_ARM_RPI = n/CONFIG_PLATFORM_ARM_RPI = y/' Makefile
    fi
    
    make -j$(nproc) || {
        log "ERROR" "Failed to compile driver"
        return 1
    }
    
    make install || {
        log "ERROR" "Failed to install driver"
        return 1
    }
    
    # Load the module
    modprobe 88XXau || modprobe 8812au || {
        log "WARN" "Could not load module immediately, may need reboot"
    }
    
    cd /
    rm -rf "$build_dir"
    
    log "OK" "RTL8812AU driver installed successfully"
    return 0
}

install_rtl88x2bu_from_source() {
    local build_dir="/tmp/rtl88x2bu-build"
    
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    log "INFO" "Cloning RTL88x2BU driver repository..."
    git clone --depth=1 https://github.com/morrownr/88x2bu-20210702.git . || {
        log "ERROR" "Failed to clone RTL88x2BU repository"
        return 1
    }
    
    log "INFO" "Building driver..."
    
    # Use the install script if available
    if [ -f "install-driver.sh" ]; then
        chmod +x install-driver.sh
        ./install-driver.sh NoPrompt || {
            log "ERROR" "Driver installation script failed"
            return 1
        }
    else
        make -j$(nproc) && make install || {
            log "ERROR" "Failed to build/install driver"
            return 1
        }
    fi
    
    cd /
    rm -rf "$build_dir"
    
    log "OK" "RTL88x2BU driver installed successfully"
    return 0
}

install_rtl8192eu_from_source() {
    local build_dir="/tmp/rtl8192eu-build"

    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"

    log "INFO" "Cloning RTL8192EU driver repository..."
    git clone --depth=1 https://github.com/clnhub/rtl8192eu-linux.git . || {
        log "ERROR" "Failed to clone RTL8192EU repository"
        return 1
    }

    log "INFO" "Building driver..."
    make -j$(nproc) || {
        log "ERROR" "Failed to compile RTL8192EU driver"
        return 1
    }

    make install || {
        log "ERROR" "Failed to install RTL8192EU driver"
        return 1
    }

    modprobe 8192eu || log "WARN" "Module 8192eu not loaded immediately; a reboot may be required"

    cd /
    rm -rf "$build_dir"

    log "OK" "RTL8192EU driver installed successfully"
    return 0
}

verify_wifi_operational() {
    local iface="$1"
    local max_attempts=30
    local attempt=0
    
    log "INFO" "Verifying WiFi interface is operational..."
    set_status "VERIFYING:$iface"
    
    while [ $attempt -lt $max_attempts ]; do
        # Check if interface exists
        if [ -d "/sys/class/net/$iface" ]; then
            # Check if it's a wireless interface
            if [ -d "/sys/class/net/$iface/wireless" ]; then
                # Try to bring it up
                ip link set "$iface" up 2>/dev/null || true
                
                # Check if it's UP
                if ip link show "$iface" 2>/dev/null | grep -q "UP"; then
                    log "OK" "Interface $iface is UP and operational"
                    
                    return 0
                fi
            fi
        fi
        
        sleep 1
        ((attempt++))
    done
    
    log "ERROR" "Interface $iface failed verification after ${max_attempts} seconds"
    return 1
}

get_all_wifi_interfaces() {
    local interfaces=()
    
    for iface in /sys/class/net/*/wireless; do
        if [ -d "$iface" ]; then
            local ifname=$(basename $(dirname "$iface"))
            interfaces+=("$ifname")
        fi
    done
    
    echo "${interfaces[@]}"
}

process_device() {
    local usb_id="$1"
    
    log "INFO" "Processing device: $usb_id"
    
    # Check if it's a known device
    local driver_info="${WIFI_DRIVERS[$usb_id]}"
    local builtin="${BUILTIN_CHIPSETS[$usb_id]}"
    
    if [ -n "$builtin" ]; then
        log "INFO" "Device $usb_id ($builtin) uses built-in kernel driver"
        set_status "BUILTIN:$builtin"
        
        # Just need to wait for the interface
        local iface=$(check_interface_exists "$builtin" 15)
        if [ -n "$iface" ]; then
            verify_wifi_operational "$iface" && return 0
        fi
        
        # Try loading firmware
        log "INFO" "Attempting to load firmware for $builtin..."
        case "$builtin" in
            RT5370|RT3070)
                apt-get install -y -qq firmware-ralink 2>/dev/null
                ;;
            AR9271)
                apt-get install -y -qq firmware-atheros 2>/dev/null
                ;;
            MT7601U)
                apt-get install -y -qq firmware-misc-nonfree 2>/dev/null
                ;;
            RTL8188*)
                apt-get install -y -qq firmware-realtek 2>/dev/null
                ;;
        esac
        
        # Reload USB device
        log "INFO" "Reloading USB device..."
        for dev in /sys/bus/usb/devices/*/idVendor; do
            local dir=$(dirname "$dev")
            local vid=$(cat "$dir/idVendor" 2>/dev/null)
            local pid=$(cat "$dir/idProduct" 2>/dev/null)
            if [ "${vid}:${pid}" = "$usb_id" ]; then
                echo 0 > "$dir/authorized" 2>/dev/null || true
                sleep 1
                echo 1 > "$dir/authorized" 2>/dev/null || true
                break
            fi
        done
        
        sleep 3
        iface=$(check_interface_exists "$builtin" 10)
        if [ -n "$iface" ]; then
            verify_wifi_operational "$iface" && return 0
        fi
        
        log "ERROR" "Failed to activate built-in driver for $builtin"
        return 1
    fi
    
    if [ -z "$driver_info" ]; then
        log "ERROR" "Unknown device: $usb_id - no driver information available"
        set_status "UNKNOWN:$usb_id"
        return 1
    fi
    
    # Parse driver info
    IFS=':' read -r chipset package driver_type <<< "$driver_info"
    
    log "INFO" "Device: $chipset, Package: $package, Type: $driver_type"
    set_status "DETECTED:$chipset"
    
    # Get current interfaces before installation
    local before_interfaces=$(get_all_wifi_interfaces)
    
    # Install the driver
    if ! install_driver_package "$package" "$driver_type"; then
        log "ERROR" "Failed to install driver for $chipset"
        set_status "INSTALL_FAILED:$chipset"
        return 1
    fi
    
    # Wait for new interface to appear
    sleep 3
    
    local after_interfaces=$(get_all_wifi_interfaces)
    local new_iface=""
    
    # Find the new interface
    for iface in $after_interfaces; do
        if [[ ! " $before_interfaces " =~ " $iface " ]]; then
            new_iface="$iface"
            break
        fi
    done
    
    # If no new interface, check if any interface works
    if [ -z "$new_iface" ]; then
        new_iface=$(check_interface_exists "$chipset" 15)
    fi
    
    if [ -z "$new_iface" ]; then
        log "ERROR" "No new WiFi interface detected after driver installation"
        log "INFO" "A reboot may be required"
        set_status "REBOOT_REQUIRED:$chipset"
        return 2
    fi
    
    # Verify the interface is working
    if verify_wifi_operational "$new_iface"; then
        set_status "SUCCESS:$chipset:$new_iface"
        
        # Check monitor mode support
        check_monitor_mode_support "$new_iface"
        
        return 0
    else
        log "ERROR" "Interface $new_iface is not operational"
        set_status "NOT_OPERATIONAL:$chipset:$new_iface"
        return 1
    fi
}

notify_rustyjack() {
    local status="$1"
    local details="$2"
    
    # Write status for rustyjack-ui to read
    cat > /tmp/rustyjack_wifi_result.json << EOF
{
    "status": "$status",
    "details": "$details",
    "timestamp": "$(date -Iseconds)",
    "interfaces": [$(for i in $(get_all_wifi_interfaces); do echo "\"$i\","; done | sed 's/,$//')]
}
EOF
    
    # Send to Discord if enabled
    if [ -f "$RUSTYJACK_ROOT/discord_webhook.txt" ]; then
        local webhook=$(cat "$RUSTYJACK_ROOT/discord_webhook.txt" | head -1)
        if [ -n "$webhook" ] && [ "$webhook" != "YOUR_DISCORD_WEBHOOK_URL_HERE" ]; then
            curl -s -H "Content-Type: application/json" \
                -d "{\"content\": \"WiFi Driver: $status - $details\"}" \
                "$webhook" 2>/dev/null || true
        fi
    fi
}

main() {
    log "INFO" "=== RustyJack WiFi Driver Installer ==="
    log "INFO" "Kernel: $(uname -r)"
    log "INFO" "Architecture: $(uname -m)"
    
    set_status "SCANNING"
    
    # Detect WiFi devices
    local devices=$(detect_new_wifi_devices)
    
    if [ -z "$devices" ]; then
        log "WARN" "No known USB WiFi devices detected"
        
        # Show all USB devices for debugging
        log "INFO" "Connected USB devices:"
        lsusb 2>/dev/null | while read line; do
            log "INFO" "  $line"
        done
        
        set_status "NO_DEVICES"
        notify_rustyjack "NO_DEVICES" "No USB WiFi adapters detected"
        exit 0
    fi
    
    local success_count=0
    local fail_count=0
    local reboot_needed=0
    local results=()
    
    for usb_id in $devices; do
        log "INFO" "--- Processing $usb_id ---"
        
        if process_device "$usb_id"; then
            ((success_count++))
            results+=("$usb_id: SUCCESS")
        else
            local exit_code=$?
            if [ $exit_code -eq 2 ]; then
                ((reboot_needed++))
                results+=("$usb_id: REBOOT_REQUIRED")
            else
                ((fail_count++))
                results+=("$usb_id: FAILED")
            fi
        fi
    done
    
    log "INFO" "=== Installation Summary ==="
    log "INFO" "Success: $success_count, Failed: $fail_count, Reboot needed: $reboot_needed"
    
    for result in "${results[@]}"; do
        log "INFO" "  $result"
    done
    
    # Final status
    if [ $success_count -gt 0 ]; then
        local ifaces=$(get_all_wifi_interfaces)
        notify_rustyjack "SUCCESS" "Installed $success_count driver(s). Interfaces: $ifaces"
        set_status "COMPLETE:SUCCESS:$ifaces"
        exit 0
    elif [ $reboot_needed -gt 0 ]; then
        notify_rustyjack "REBOOT_REQUIRED" "Driver installed but reboot required"
        set_status "COMPLETE:REBOOT_REQUIRED"
        exit 2
    else
        notify_rustyjack "FAILED" "Failed to install drivers for $fail_count device(s)"
        set_status "COMPLETE:FAILED"
        exit 1
    fi
}

# Run main function
main "$@"
