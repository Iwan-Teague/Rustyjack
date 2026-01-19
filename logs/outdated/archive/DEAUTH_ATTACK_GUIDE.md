# Deauthentication Attack Implementation Guide
Created: 2026-01-07

> Note: Archived doc. Current builds no longer use external tcpdump, ettercap, ncat, arp-scan, or arpspoof/dsniff; references below are historical.


## Overview

This document explains how deauthentication attacks work, the **native Rust implementation** in RustyJack using `rustyjack-wireless`, hardware requirements, and technical details.

## No External Dependencies

RustyJack uses a **pure Rust implementation** for all wireless operations. **No aircrack-ng suite is required.**

| Feature | Implementation |
|---------|----------------|
| Monitor Mode | Native via nl80211 netlink |
| Packet Injection | Raw sockets with radiotap |
| Deauth Attacks | `rustyjack-wireless` crate |
| Handshake Capture | Native EAPOL parsing |
| Channel Management | Direct kernel interface |

---

## How Deauthentication Attacks Work

### IEEE 802.11 Management Frames

WiFi networks use three types of frames:
1. **Management Frames** - Used for network management (authentication, association, beacons)
2. **Control Frames** - Used for frame acknowledgment and medium access
3. **Data Frames** - Carry actual payload data

Deauthentication attacks exploit **management frames**, specifically:

| Frame Type | Subtype | Purpose |
|------------|---------|---------|
| Deauthentication | 0x0C (12) | Forces client disconnection |
| Disassociation | 0x0A (10) | Similar effect, different reason codes |

### Why It Works

In WPA2/WPA3 networks:
- **Data frames** are encrypted and authenticated
- **Management frames** are **NOT encrypted** (only data integrity in WPA3)
- Any device in monitor mode can forge these frames

### Attack Flow

```
1. Attacker → Monitor Mode (via rustyjack-wireless)
2. Attacker → Captures AP BSSID and Client MACs
3. Attacker → Spoofs Deauth frames (AP → Client)
4. Client → Disconnects (trusts the "AP")
5. Client → Reconnects automatically
6. Attacker → Captures 4-way WPA handshake (native EAPOL parsing)
7. Attacker → Can crack handshake offline
```

### Deauthentication Frame Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    802.11 Frame Header                       │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Frame    │ Duration │ Address 1│ Address 2│ Address 3       │
│ Control  │ ID       │ (Dest)   │ (Source) │ (BSSID)         │
│ 2 bytes  │ 2 bytes  │ 6 bytes  │ 6 bytes  │ 6 bytes         │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│ Sequence Control: 2 bytes                                    │
├──────────────────────────────────────────────────────────────┤
│ Reason Code: 2 bytes (e.g., 0x0007 = Class 3 frame)          │
└──────────────────────────────────────────────────────────────┘

Frame Control for Deauth:
  - Protocol Version: 00
  - Type: 00 (Management)
  - Subtype: 1100 (Deauthentication)
  - Flags: ToDS=0, FromDS=0, etc.
```

### Common Reason Codes

| Code | Meaning |
|------|---------|
| 1 | Unspecified reason |
| 2 | Previous authentication no longer valid |
| 3 | Station leaving the BSS |
| 4 | Disassociated due to inactivity |
| 6 | Class 2 frame from non-authenticated station |
| 7 | Class 3 frame from non-associated station |

---

## RustyJack Architecture

### Native Rust Implementation

```
┌─────────────────────────────────────────────────────────────┐
│                     rustyjack-ui                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ launch_deauth_attack()                              │    │
│  │   - Validates BSSID, channel, interface            │    │
│  │   - Shows progress dialog                           │    │
│  │   - Dispatches WifiCommand::Deauth                  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     rustyjack-core                           │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ handle_wifi_deauth() → wireless_native.rs           │    │
│  │   1. Validate BSSID/MAC format                      │    │
│  │   2. Create WirelessInterface (rustyjack-wireless)  │    │
│  │   3. Enable monitor mode (native nl80211)           │    │
│  │   4. Set channel (native netlink)                   │    │
│  │   5. Create DeauthAttacker                          │    │
│  │   6. Send deauth bursts (raw socket injection)      │    │
│  │   7. Capture handshakes (native EAPOL parsing)      │    │
│  │   8. Restore interface (automatic cleanup)          │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   rustyjack-wireless                         │
│  - WirelessInterface: Monitor mode, channel control          │
│  - DeauthAttacker: Frame injection, attack execution         │
│  - HandshakeCapture: Native EAPOL packet parsing             │
│  - All native Rust - no external tools required!             │
└─────────────────────────────────────────────────────────────┘
```

### Key Data Structures

```rust
/// Configuration for a deauthentication attack
pub struct DeauthConfig {
    pub interface: String,        // Wireless interface (wlan0)
    pub bssid: String,            // Target AP MAC (AA:BB:CC:DD:EE:FF)
    pub ssid: Option<String>,     // Target SSID (for display/logging)
    pub channel: u8,              // AP channel (1-14, 36-165)
    pub client: Option<String>,   // Target specific client MAC
    pub packets_per_burst: u32,   // Packets per burst (default: 64)
    pub burst_interval_ms: u64,   // Milliseconds between bursts (default: 100)
    pub duration_secs: u64,       // Attack duration in seconds
    pub capture_handshake: bool,  // Whether to capture handshake
}

/// Results from a deauthentication attack
pub struct DeauthResult {
    pub success: bool,
    pub packets_sent: u64,
    pub bursts_completed: u32,
    pub handshake_captured: bool,
    pub handshake_path: Option<PathBuf>,
    pub duration: Duration,
    pub error: Option<String>,
}
```

### Native Wireless Crate Features

The `rustyjack-wireless` crate provides:

```rust
// Monitor mode management
let interface = WirelessInterface::new("wlan0")?;
interface.enable_monitor_mode()?;
interface.set_channel(6)?;

// Deauthentication attacks
let attacker = DeauthAttacker::new(&interface)?;
let stats = attacker.attack(
    bssid,
    target_client,  // None = broadcast
    packet_count,
)?;

// Handshake capture
let capturer = HandshakeCapture::new(&interface)?;
capturer.start_capture(bssid)?;
// ... wait for handshake ...
if let Some(handshake) = capturer.get_handshake() {
    handshake.save_to_file("handshake.cap")?;
}

// Cleanup is automatic via Drop trait
```

---

## Hardware Requirements

### Monitor Mode + Packet Injection

For deauthentication attacks, you **MUST** have:

1. **Monitor Mode** - Capture all 802.11 frames (not just your SSID)
2. **Packet Injection** - Transmit arbitrary raw 802.11 frames

### Recommended Chipsets

| Chipset | Driver | Monitor | Injection | Notes |
|---------|--------|---------|-----------|-------|
| **Atheros AR9271** | ath9k_htc | Yes | Yes | Best compatibility |
| **Realtek RTL8812AU** | rtl8812au | Yes | Yes | 5GHz support |
| **Realtek RTL8814AU** | rtl8814au | Yes | Yes | High power |
| **Ralink RT3070** | rt2800usb | Yes | Yes | Good, older |
| **MediaTek MT7612U** | mt76x2u | Yes | Yes | Modern |

### Popular Adapters

| Adapter | Chipset | Price | Notes |
|---------|---------|-------|-------|
| Alfa AWUS036NHA | AR9271 | ~$30 | 2.4GHz only, best for learning |
| Alfa AWUS036ACH | RTL8812AU | ~$50 | Dual-band, high power |
| Alfa AWUS036ACHM | MT7612U | ~$45 | Newer, good driver support |
| Panda PAU09 | RT3070 | ~$20 | Budget option |

### Raspberry Pi Built-in WiFi

| Model | Chip | Monitor | Injection |
|-------|------|---------|-----------|
| Pi 3B/3B+ | BCM43438 | Limited | No |
| Pi 4 | BCM43455 | Limited | No |
| Pi Zero W | BCM43438 | Limited | No |

**Warning:** Built-in Pi WiFi does NOT reliably support packet injection. Use an external adapter!

### Testing Your Adapter

```bash
# Check if interface supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Check for nl80211 support (required for native implementation)
iw dev wlan0 info

# Verify raw socket access (as root)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 info  # Should show "type monitor"
```

---

## Technical Implementation Details

### Native Monitor Mode (nl80211)

RustyJack uses netlink sockets to control wireless interfaces:

```rust
// Simplified flow in rustyjack-wireless
pub fn enable_monitor_mode(&self) -> Result<()> {
    // 1. Bring interface down
    self.set_interface_down()?;
    
    // 2. Set interface type to monitor via nl80211
    self.set_interface_type(NL80211_IFTYPE_MONITOR)?;
    
    // 3. Bring interface up
    self.set_interface_up()?;
    
    Ok(())
}
```

### Raw Packet Injection

Deauth frames are sent using raw AF_PACKET sockets:

```rust
// Create raw socket for packet injection
let socket = socket(
    AddressFamily::Packet,
    SockType::Raw,
    SockFlag::empty(),
    None,
)?;

// Build deauth frame with radiotap header
let mut packet = Vec::new();
packet.extend_from_slice(&RADIOTAP_HEADER);
packet.extend_from_slice(&build_deauth_frame(bssid, target, reason_code));

// Inject packet
sendto(socket, &packet, &sockaddr)?;
```

### EAPOL Handshake Capture

Native parsing of 802.11 frames to capture WPA handshakes:

```rust
// Capture and parse EAPOL frames
fn parse_eapol_message(data: &[u8]) -> Option<EapolMessage> {
    // Check for EAPOL ether type (0x888E)
    // Parse key information to determine message number (1-4)
    // Extract nonces, MIC, etc.
}

// A complete handshake needs messages 1+2 or 2+3
fn is_handshake_complete(messages: &[Option<EapolMessage>; 4]) -> bool {
    (messages[0].is_some() && messages[1].is_some()) ||
    (messages[1].is_some() && messages[2].is_some())
}
```

---

## Security Considerations

### Legal Notice

Warning: **Deauthentication attacks are illegal without explicit authorization!**

- Only test on networks you own or have written permission to test
- Unauthorized deauth attacks violate FCC regulations (in the US)
- Many countries have computer misuse laws that apply

### Defensive Measures

| Protection | How It Helps |
|------------|--------------|
| **WPA3-SAE** | Management frame protection (802.11w) |
| **802.11w (PMF)** | Protected Management Frames |
| **Wireless IDS** | Detect deauth floods |
| **Client isolation** | Limits broadcast deauth effectiveness |

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| "Failed to enable monitor mode" | Install correct driver, check adapter compatibility |
| "Permission denied" | Run as root, or use `sudo` |
| "Interface not found" | Check interface name with `ip link` |
| No handshakes captured | Ensure clients are active, try targeting specific client |
| Wrong channel | Scan for target BSSID channel first |
| Interface stuck in monitor mode | Run `sudo ip link set wlan0 down && sudo iw dev wlan0 set type managed && sudo ip link set wlan0 up` |

### Debug Commands

```bash
# List wireless interfaces
ip link | grep wlan

# Check interface capabilities
iw phy phy0 info | grep -A 10 "Supported interface modes"

# Check current mode
iw dev wlan0 info

# Manually enable monitor mode (for testing)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Set channel
sudo iw dev wlan0 set channel 6

# See all wireless traffic (requires monitor mode)
sudo tcpdump -i wlan0 -e -s 0 type mgt subtype deauth
```

---

## References

- [802.11 Frame Types](https://en.wikipedia.org/wiki/802.11_Frame_Types)
- [Radiotap Headers](https://www.radiotap.org/)
- [WPA2 4-Way Handshake](https://www.wifi-professionals.com/2019/01/4-way-handshake)
- [Linux Wireless Subsystem](https://wireless.wiki.kernel.org/)
- [nl80211 Documentation](https://wireless.wiki.kernel.org/en/developers/documentation/nl80211)
