# rustyjack-netlink

Pure Rust replacement for `ip`, `dhclient`, `rfkill`, `pkill`/`pgrep`, `dnsmasq` (DHCP+DNS), `wpa_supplicant`/`wpa_cli`, and **ARP tools** using Linux APIs.

## Features

**Interface Management** (replaces `ip link`):
- Bring interfaces up/down
- List all network interfaces with status
- Get interface index and MAC address
- Query interface addresses

**Address Management** (replaces `ip addr`):
- Add/delete IP addresses to interfaces
- Flush all addresses from an interface
- Support for both IPv4 and IPv6

**Route Management** (replaces `ip route`):
- Add/delete default routes
- List all routes
- Gateway configuration

**DHCP Client** (replaces `dhclient`):
- Release DHCP leases (flush addresses)
- Renew leases (stub - pending full DHCP implementation)

**DHCP Server** (replaces `dnsmasq` DHCP functionality):
- RFC 2131 compliant DHCP server
- Address pool management with configurable ranges
- Per-MAC lease tracking with expiration
- Thread-safe concurrent access
- Optional packet logging
- Hostname tracking

**DNS Server** (replaces `dnsmasq` DNS functionality):
- RFC 1035 compliant DNS server
- Wildcard DNS spoofing for captive portals
- Custom domain-to-IP mappings
- Pass-through mode with upstream DNS
- Query logging and statistics
- Thread-safe operation

**RF Kill Management** (replaces `rfkill`):
- List all rfkill devices with status
- Block/unblock individual devices by index
- Block/unblock all devices of a type (wlan, bluetooth, etc.)
- Block/unblock all devices
- Find rfkill index by network interface name
- Query device state (soft/hard blocked)

**Process Management** (replaces `pgrep`/`pkill`):
- Find processes by name or command line pattern
- Send signals to processes (SIGTERM, SIGKILL)
- Check if processes are running
- Kill processes by exact name or pattern
- Direct `/proc` filesystem access (no text parsing)

**ARP Suite** (replaces `arp-scan`, `arpspoof`, `arping`):
- Scan subnets for live hosts
- Get MAC addresses for IP addresses
- ARP spoofing for MITM attacks
- Bidirectional ARP poisoning
- Quick host alive checks
- Full control over ARP packets

**WPA Supplicant** (replaces `wpa_supplicant`/`wpa_cli`):
- Control wpa_supplicant via Unix control socket
- Connect to wireless networks (WPA/WPA2/Open)
- Reconnect/disconnect/reassociate commands
- Network scanning and scan results
- Add/remove/configure network profiles
- Query connection status and signal strength
- Wait for connection completion with timeout
- Start/stop wpa_supplicant daemon

## Usage

All operations are async and require a tokio runtime:

```rust
use rustyjack_netlink::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Bring interface up
    set_interface_up("eth0").await?;
    
    // List all interfaces
    let interfaces = list_interfaces().await?;
    for iface in interfaces {
        println!("{}: {:?}", iface.name, iface.mac);
        println!("  Up: {}, Running: {}", iface.is_up, iface.is_running);
        for addr in iface.addresses {
            println!("  {}/{}", addr.address, addr.prefix_len);
        }
    }
    
    // Add an IP address
    use std::net::IpAddr;
    let addr = "192.168.1.100".parse::<IpAddr>()?;
    add_address("eth0", addr, 24).await?;
    
    // Add default route
    let gateway = "192.168.1.1".parse::<IpAddr>()?;
    add_default_route(gateway, "eth0").await?;
    
    // Release DHCP (flush addresses)
    dhcp_release("eth0").await?;
    
    // rfkill operations
    use rustyjack_netlink::{RfkillManager, RfkillType};
    let rfkill = RfkillManager::new();
    
    // List all rfkill devices
    let devices = rfkill.list()?;
    for dev in devices {
        println!("rfkill{}: {} - {}", dev.idx, dev.type_.name(), dev.state_string());
    }
    
    // Unblock all wireless devices
    rfkill.unblock_type(RfkillType::Wlan)?;
    
    // Find and unblock by interface name
    if let Some(idx) = rfkill.find_index_by_interface("wlan0")? {
        rfkill.unblock(idx)?;
    }
    
    // Process management
    use rustyjack_netlink::process;
    
    // Find all hostapd processes
    let pids = process::pgrep("hostapd")?;
    println!("Found {} hostapd processes", pids.len());
    
    // Kill all dnsmasq processes
    let killed = process::pkill_force("dnsmasq")?;
    println!("Killed {} processes", killed);
    
    // Check if process is running
    if process::process_running("wpa_supplicant")? {
        println!("wpa_supplicant is running");
    }
    
    // ARP operations
    use rustyjack_netlink::arp;
    
    // Scan subnet for live hosts
    let scanner = arp::ArpScanner::new();
    let hosts = scanner.scan_subnet("192.168.1.0/24", "eth0")?;
    for host in hosts {
        println!("{} is at {}", host.ip, host.mac_string());
    }
    
    // Quick check if host is alive
    if scanner.is_alive("192.168.1.1".parse()?, "eth0")? {
        println!("Gateway is up!");
    }
    
    // Get MAC address for IP
    if let Some(mac) = scanner.get_mac("192.168.1.50".parse()?, "eth0")? {
        println!("MAC: {}", arp::format_mac_address(&mac));
    }
    
    // ARP spoofing (MITM)
    let mut spoofer = arp::ArpSpoofer::new();
    let config = arp::ArpSpoofConfig {
        target_ip: "192.168.1.50".parse()?,
        spoof_ip: "192.168.1.1".parse()?,  // Gateway
        attacker_mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
        interface: "eth0".to_string(),
        interval_ms: 1000,
        restore_on_stop: true,
    };
    spoofer.start_continuous(config)?;
    
    // WPA supplicant operations
    use rustyjack_netlink::{WpaManager, WpaNetworkConfig};
    
    let wpa = WpaManager::new("wlan0")?;
    
    // Check status
    let status = wpa.status()?;
    println!("Connected to: {:?}", status.ssid);
    println!("State: {}", status.wpa_state);
    
    // Reconnect to current network
    wpa.reconnect()?;
    
    // Connect to a new network
    let config = WpaNetworkConfig {
        ssid: "MyNetwork".to_string(),
        psk: Some("password123".to_string()),
        scan_ssid: false,
        priority: 0,
        ..Default::default()
    };
    let network_id = wpa.connect_network(&config)?;
    
    // Wait for connection
    wpa.wait_for_connection(std::time::Duration::from_secs(30))?;
    
    Ok(())
}
```

## Manager API

For more control, use the manager structs directly:

```rust
use rustyjack_netlink::{InterfaceManager, RouteManager, DhcpClient};

let iface_mgr = InterfaceManager::new()?;
let route_mgr = RouteManager::new()?;
let dhcp = DhcpClient::new()?;

// Each manager maintains its own netlink handle
iface_mgr.set_interface_up("wlan0").await?;
route_mgr.delete_default_route().await?;
```

## Platform Support

**Linux only** - uses Linux-specific netlink sockets. Code is gated with `#[cfg(target_os = "linux")]` so it compiles on other platforms but functions are not available.

## Dependencies

- `rtnetlink` - High-level netlink library
- `tokio` - Async runtime
- `futures` - Stream processing
- `libc` - Flag constants (IFF_UP, IFF_RUNNING, etc.)

## Current Status

✅ **Complete:**
- Interface up/down/list/query
- Address add/delete/flush
- Route add/delete/list
- DHCP release (address flushing)

🚧 **Pending:**
- Full DHCP client implementation (discovery/offer/request/ack)
- DHCP option parsing (DNS servers, domain, etc.)
- Lease renewal tracking
- MAC address setting via netlink (currently done via `ip link set`)

## Replaces

This crate eliminates calls to:
- `ip link set <interface> up/down`
- `ip addr add/del/show/flush`
- `ip route add/del/show default`
- `ip -4 addr show dev <interface>`
- `dhclient -r <interface>` (release)
- `dhclient <interface>` (acquire/renew)
- `dnsmasq` (DHCP+DNS server functionality)
- `rfkill list`
- `rfkill block/unblock <index>`
- `rfkill block/unblock all`
- `rfkill block/unblock wlan` (or other types)
- `pgrep <name>` (find processes)
- `pgrep -f <pattern>` (find by command line)
- `pkill <name>` (kill by name)
- `pkill -f <pattern>` (kill by pattern)
- `pkill -9 <name>` (force kill)
- `arp-scan <subnet>` (scan for hosts)
- `arping <ip>` (check if alive)
- `arpspoof -t <target> -r <gateway>` (MITM)
- `wpa_cli -i <interface> <command>` (control wpa_supplicant)
- `wpa_supplicant -B -i <interface> -c <config>` (start daemon)

## Integration

Used throughout Rustyjack codebase wherever `Command::new("ip")` or `Command::new("dhclient")` previously appeared. Provides better error handling, no text parsing, and eliminates external process overhead.


### DHCP Server Usage

Start a DHCP server on an interface (replaces dnsmasq for DHCP):

```rust
use rustyjack_netlink::{DhcpServer, DhcpConfig};
use std::net::Ipv4Addr;
use std::thread;

let config = DhcpConfig {
    interface: "wlan0".to_string(),
    server_ip: Ipv4Addr::new(10, 20, 30, 1),
    subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
    range_start: Ipv4Addr::new(10, 20, 30, 10),
    range_end: Ipv4Addr::new(10, 20, 30, 200),
    router: Some(Ipv4Addr::new(10, 20, 30, 1)),
    dns_servers: vec![
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(8, 8, 4, 4),
    ],
    lease_time_secs: 43200, // 12 hours
    log_packets: true,
};

let mut server = DhcpServer::new(config)?;
server.start()?;

// Serve DHCP requests in background thread
let handle = thread::spawn(move || {
    server.serve().unwrap();
});

// Get current leases
let leases = server.get_leases();
for lease in leases {
    println!("IP: {}, MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        lease.ip,
        lease.mac[0], lease.mac[1], lease.mac[2],
        lease.mac[3], lease.mac[4], lease.mac[5]);
    if let Some(hostname) = &lease.hostname {
        println!("  Hostname: {}", hostname);
    }
    println!("  Remaining: {}s", lease.remaining_secs());
}

// Stop server
server.stop();
handle.join().ok();
```

**Features:**
- RFC 2131 compliant DHCP server
- Address pool management with configurable ranges
- Lease tracking with expiration
- Hostname support from clients
- Configurable DNS servers and default gateway
- Broadcast and unicast reply support
- Optional packet logging for debugging
- Thread-safe lease management
- Automatic lease cleanup on expiration

### DNS Server Usage

Start a DNS server for hotspot/captive portal (replaces dnsmasq for DNS):

```rust
use rustyjack_netlink::{DnsServer, DnsConfig, DnsRule};
use std::net::Ipv4Addr;
use std::collections::HashMap;

// Wildcard DNS spoofing (redirect all queries to one IP)
let config = DnsConfig {
    interface: "wlan0".to_string(),
    listen_ip: Ipv4Addr::new(10, 20, 30, 1),
    default_rule: DnsRule::WildcardSpoof(Ipv4Addr::new(10, 20, 30, 1)),
    custom_rules: HashMap::new(),
    upstream_dns: Some(Ipv4Addr::new(8, 8, 8, 8)),
    log_queries: true,
};

let mut server = DnsServer::new(config)?;
server.start()?;

// Add custom domain rules
server.add_rule("example.com".to_string(), Ipv4Addr::new(192, 168, 1, 100));

// Get statistics
let (queries, spoofs) = server.get_stats();
println!("Total queries: {}, Spoofed: {}", queries, spoofs);

// Stop server
server.stop()?;
```

**DNS Rules:**

```rust
// 1. Wildcard spoofing (captive portal)
DnsRule::WildcardSpoof(Ipv4Addr::new(10, 0, 0, 1))  // All domains → 10.0.0.1

// 2. Exact domain match
DnsRule::ExactMatch {
    domain: "evil.com".to_string(),
    ip: Ipv4Addr::new(192, 168, 1, 50),
}

// 3. Pass-through (forward to upstream)
DnsRule::PassThrough
```

**Features:**
- RFC 1035 compliant DNS server
- Wildcard DNS spoofing for captive portals
- Custom per-domain IP mappings
- Pass-through mode with upstream DNS forwarding
- Query logging and statistics tracking
- Thread-safe operation
- A record (IPv4) queries supported
- Proper error handling with detailed messages
- Automatic RCODE responses (NOERROR, NXDOMAIN, etc.)

### WPA Supplicant Usage

Control wpa_supplicant for wireless authentication (replaces `wpa_cli`):

```rust
use rustyjack_netlink::{WpaManager, WpaNetworkConfig, WpaState};
use std::time::Duration;

// Connect to wpa_supplicant control socket
let wpa = WpaManager::new("wlan0")?;

// Check if responsive
wpa.ping()?;

// Get current status
let status = wpa.status()?;
println!("SSID: {:?}", status.ssid);
println!("BSSID: {:?}", status.bssid);
println!("State: {}", status.wpa_state);
println!("IP: {:?}", status.ip_address);

// Reconnect to current network
wpa.reconnect()?;

// Disconnect
wpa.disconnect()?;

// Scan for networks
wpa.scan()?;
std::thread::sleep(Duration::from_secs(2));
let results = wpa.scan_results()?;
for network in results {
    println!("{}: {} ({})", 
        network.get("ssid").unwrap(),
        network.get("signal").unwrap(),
        network.get("flags").unwrap());
}

// Connect to a network (high-level API)
let config = WpaNetworkConfig {
    ssid: "MyNetwork".to_string(),
    psk: Some("mypassword".to_string()),
    key_mgmt: "WPA-PSK".to_string(),
    scan_ssid: false,  // Set true for hidden networks
    priority: 0,
};

let network_id = wpa.connect_network(&config)?;
println!("Added network ID: {}", network_id);

// Wait for connection to complete
match wpa.wait_for_connection(Duration::from_secs(30)) {
    Ok(status) => {
        println!("Connected! IP: {:?}", status.ip_address);
    }
    Err(e) => {
        println!("Connection failed: {}", e);
        wpa.remove_network(network_id)?;
    }
}

// Low-level network management
let net_id = wpa.add_network()?;
wpa.set_network(net_id, "ssid", "\"TestNet\"")?;
wpa.set_network(net_id, "psk", "\"password\"")?;
wpa.set_network(net_id, "scan_ssid", "1")?;  // Hidden network
wpa.enable_network(net_id)?;

// List all configured networks
let networks = wpa.list_networks()?;
for net in networks {
    println!("ID: {}, SSID: {}, Flags: {}",
        net.get("network_id").unwrap(),
        net.get("ssid").unwrap(),
        net.get("flags").unwrap());
}

// Get signal strength
let signal = wpa.signal_poll()?;
println!("RSSI: {} dBm", signal.get("rssi").unwrap());
println!("Link speed: {} Mbps", signal.get("linkspeed").unwrap());

// Save configuration to persistent storage
wpa.save_config()?;
```

**Helper Functions:**

```rust
use rustyjack_netlink::{is_wpa_running, start_wpa_supplicant, stop_wpa_supplicant};

// Check if wpa_supplicant is running
if is_wpa_running("wlan0")? {
    println!("wpa_supplicant is active");
}

// Start wpa_supplicant daemon
start_wpa_supplicant("wlan0", None)?;  // Uses default config

// Or with custom config
start_wpa_supplicant("wlan0", Some("/etc/wpa_supplicant.conf"))?;

// Stop wpa_supplicant daemon
stop_wpa_supplicant("wlan0")?;
```

**Features:**
- Direct control socket communication (no process spawning)
- Complete wpa_cli command coverage
- Connection state tracking and waiting
- Network profile management (add/remove/configure)
- Scan operations and result parsing
- Signal strength polling
- Automatic error handling with context
- Support for WPA/WPA2-PSK, open, and hidden networks
- Configuration persistence
- Start/stop daemon management
