# rustyjack-evasion

A reusable Rust library for network evasion and obfuscation techniques. Designed for security tools, penetration testing, and privacy applications.

## Features

- **MAC Address Randomization**: Generate random or vendor-specific MAC addresses
- **TX Power Control**: Adjust wireless transmission power for stealth operations
- **Passive Mode**: Monitor-only mode with no transmissions
- **State Management**: Save and restore original network interface state
- **Vendor Database**: Common WiFi device vendor OUIs for blending in

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rustyjack-evasion = "0.1"
```

## Quick Start

```rust
use rustyjack_evasion::{MacManager, TxPowerLevel, quick_randomize_mac};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Quick randomize (stateless)
    let new_mac = quick_randomize_mac("wlan0")?;
    println!("New MAC: {}", new_mac);
    
    // Or with state management
    let mut manager = MacManager::new()?;
    
    // Randomize MAC (original is saved)
    let state = manager.randomize("wlan0")?;
    println!("Changed from {} to {}", state.original_mac, state.current_mac);
    
    // Do operations...
    
    // Restore original (automatic on drop, or manual)
    manager.restore("wlan0")?;
    
    Ok(())
}
```

## MAC Address Randomization

### Random MAC

```rust
use rustyjack_evasion::mac::{MacManager, MacAddress};

let mut manager = MacManager::new()?;
let state = manager.randomize("wlan0")?;

// The generated MAC:
// - Has locally administered bit set (IEEE requirement)
// - Has multicast bit cleared (unicast address)
// - Uses cryptographically secure randomness
```

### Vendor-Specific MAC

Generate a MAC that looks like a specific device vendor:

```rust
use rustyjack_evasion::mac::{MacManager, MacGenerationStrategy};

let mut manager = MacManager::new()?;

// Look like an iPhone
let state = manager.set_with_strategy("wlan0", MacGenerationStrategy::Vendor("apple"))?;

// Look like a Samsung device
let state = manager.set_with_strategy("wlan0", MacGenerationStrategy::Vendor("samsung"))?;
```

Available vendors:
- Apple (iPhone, iPad, MacBook)
- Samsung (Galaxy devices)
- Google (Pixel, Chromebook)
- Intel, Dell, HP, Lenovo (laptops)
- TP-Link, Netgear, Cisco (network equipment)
- And more...

## TX Power Control

Adjust transmission power for stealth or maximum range:

```rust
use rustyjack_evasion::txpower::{TxPowerManager, TxPowerLevel};

let mut manager = TxPowerManager::new();

// Stealth mode - minimum range
manager.set_power("wlan0", TxPowerLevel::Stealth)?;

// Maximum range
manager.set_power("wlan0", TxPowerLevel::Maximum)?;

// Custom power level
manager.set_power("wlan0", TxPowerLevel::Custom(15))?;

// Power levels:
// - Stealth: 1 dBm (minimum range)
// - Low: 5 dBm
// - Medium: 12 dBm
// - High: 18 dBm (default)
// - Maximum: 30 dBm (adapter dependent)
```

## Passive Mode

Monitor-only mode with no transmissions:

```rust
use rustyjack_evasion::passive::{PassiveManager, PassiveConfig};

let mut manager = PassiveManager::new();

// Enable passive monitor mode
let monitor_iface = manager.enable("wlan0")?;
// Creates "wlan0mon" with minimum TX power

// Or with configuration
let config = PassiveConfig::new("wlan0")
    .channel(6)
    .duration(300);
    
let result = manager.start_capture(&config)?;
```

## Configuration

Persist settings across sessions:

```rust
use rustyjack_evasion::config::EvasionConfig;

// Load or create config
let mut config = EvasionConfig::load("evasion.json")
    .unwrap_or_default();

// Modify settings
config.mac.auto_randomize = true;
config.mac.preferred_vendor = Some("apple".to_string());
config.tx_power.stealth_during_recon = true;

// Save
config.save("evasion.json")?;
```

## State Management

Track and restore all interface modifications:

```rust
use rustyjack_evasion::state::StateManager;

let mut manager = StateManager::new();

// Record changes (done automatically by other managers)
// ...

// Restore everything
manager.restore_all()?;

// Save state for later (e.g., across reboots)
manager.save_to_file("interface_state.json")?;
```

## Platform Requirements

- **Linux only**: Uses `ip`, `iw`, and `iwconfig` commands
- **Root required**: Most operations need root or `CAP_NET_ADMIN`
- **Wireless driver support**: Some features depend on driver capabilities

## Security Considerations

1. **MAC randomization** uses `getrandom` for cryptographically secure random bytes
2. **Locally administered bit** is always set per IEEE 802 standards
3. **Auto-restore on drop** prevents leaving interfaces in modified state
4. **State persistence** allows recovery after crashes/reboots

## Error Handling

All operations return `Result<T, EvasionError>`:

```rust
use rustyjack_evasion::{MacManager, EvasionError};

match MacManager::new()?.randomize("wlan0") {
    Ok(state) => println!("Success: {}", state.current_mac),
    Err(EvasionError::PermissionDenied(op)) => {
        eprintln!("Need root for: {}", op);
    }
    Err(EvasionError::NotSupported(msg)) => {
        eprintln!("Driver doesn't support: {}", msg);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please ensure:
- Code passes `cargo clippy`
- Tests pass with `cargo test`
- Documentation is updated
