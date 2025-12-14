use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "rustyjack-core",
    author,
    version,
    about = "Rust orchestration core for Rustyjack"
)]
pub struct Cli {
    /// Override the Rustyjack install root (defaults to /root/Rustyjack or current directory)
    #[arg(long, global = true)]
    pub root: Option<PathBuf>,

    /// Output format for command responses
    #[arg(
        long = "output",
        value_enum,
        default_value_t = OutputFormat::Json,
        global = true
    )]
    pub output_format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(subcommand)]
    Scan(ScanCommand),
    #[command(subcommand)]
    Notify(NotifyCommand),
    #[command(subcommand)]
    Wifi(WifiCommand),
    #[command(subcommand)]
    Responder(ResponderCommand),
    #[command(subcommand)]
    Mitm(MitmCommand),
    #[command(subcommand)]
    DnsSpoof(DnsSpoofCommand),
    #[command(subcommand)]
    Loot(LootCommand),
    #[command(subcommand)]
    Process(ProcessCommand),
    #[command(subcommand)]
    Status(StatusCommand),
    #[command(subcommand)]
    Reverse(ReverseCommand),
    #[command(subcommand)]
    System(SystemCommand),
    #[command(subcommand)]
    Bridge(BridgeCommand),

    #[command(subcommand)]
    Hardware(HardwareCommand),
    #[command(subcommand)]
    Ethernet(EthernetCommand),
    #[command(subcommand)]
    Hotspot(HotspotCommand),
}

#[derive(Subcommand, Debug)]
pub enum ScanCommand {
    Run(ScanRunArgs),
}

#[derive(Subcommand, Debug)]
pub enum EthernetCommand {
    /// Discover hosts on the local network (ICMP sweep)
    Discover(EthernetDiscoverArgs),
    /// Quick TCP port scan on a target
    PortScan(EthernetPortScanArgs),
    /// Build an Ethernet device inventory (hostnames/services/OS hints)
    Inventory(EthernetInventoryArgs),
    /// Pipeline: classify human devices, ARP poison, capture + DNS spoof
    SiteCredCapture(EthernetSiteCredArgs),
}

#[derive(Subcommand, Debug)]
pub enum HotspotCommand {
    /// Start a NATed hotspot (hostapd + dnsmasq)
    Start(HotspotStartArgs),
    /// Stop the hotspot and clean up
    Stop,
    /// Show hotspot status
    Status,
}

#[derive(Args, Debug)]
pub struct EthernetDiscoverArgs {
    /// Optional interface override (defaults to best interface)
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional CIDR target (defaults to interface network)
    #[arg(long)]
    pub target: Option<String>,

    /// Timeout per host in milliseconds
    #[arg(long, default_value_t = 500)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct EthernetPortScanArgs {
    /// Target IPv4 address (defaults to gateway if omitted)
    #[arg(long)]
    pub target: Option<String>,

    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,

    /// Ports to scan (comma-separated, default top common ports)
    #[arg(long)]
    pub ports: Option<String>,

    /// Connect timeout per port (ms)
    #[arg(long, default_value_t = 500)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct EthernetInventoryArgs {
    /// Optional interface override (defaults to best interface)
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional CIDR target (defaults to interface network)
    #[arg(long)]
    pub target: Option<String>,

    /// Timeout for probes in milliseconds
    #[arg(long, default_value_t = 800)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct EthernetSiteCredArgs {
    /// Optional interface override (defaults to best Ethernet)
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional CIDR target (defaults to interface network)
    #[arg(long)]
    pub target: Option<String>,

    /// DNS spoof site template name (folder under DNSSpoof/sites)
    #[arg(long)]
    pub site: String,

    /// Maximum number of "human" hosts to poison (set very high to target all detected humans)
    #[arg(long, default_value_t = 8)]
    pub max_hosts: usize,

    /// Timeout for discovery/port peek (ms)
    #[arg(long, default_value_t = 800)]
    pub timeout_ms: u64,
}

#[derive(Args, Debug)]
pub struct HotspotStartArgs {
    /// Interface to host the hotspot (AP mode)
    #[arg(long, default_value = "wlan0")]
    pub ap_interface: String,
    /// Upstream interface for Internet access (eth0/wlan0/etc)
    #[arg(long, default_value = "eth0")]
    pub upstream_interface: String,
    /// Hotspot SSID
    #[arg(long, default_value = "rustyjack")]
    pub ssid: String,
    /// Hotspot password (WPA2, 8-63 chars). Empty for open network.
    #[arg(long, default_value = "rustyjack")]
    pub password: String,
    /// Wi-Fi channel (2.4 GHz)
    #[arg(long, default_value_t = 6)]
    pub channel: u8,
}

#[derive(Args, Debug)]
pub struct ScanRunArgs {
    /// Friendly name for the scan profile (used for loot filenames)
    #[arg(long)]
    pub label: String,

    /// Individual nmap arguments (repeat for each entry, e.g., --nmap-arg -sV)
    #[arg(long = "nmap-arg")]
    pub nmap_args: Vec<String>,

    /// Optional interface to use instead of auto-detection
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional CIDR target network (defaults to best interface network)
    #[arg(long)]
    pub target: Option<String>,

    /// Explicit path for the scan output file
    #[arg(long = "output-path")]
    pub output_path: Option<PathBuf>,

    /// Disable Discord notifications for this run
    #[arg(long = "no-discord")]
    pub no_discord: bool,
}

#[derive(Subcommand, Debug)]
pub enum NotifyCommand {
    #[command(subcommand)]
    Discord(DiscordCommand),
}

#[derive(Subcommand, Debug)]
pub enum DiscordCommand {
    /// Send a manual Discord notification
    Send(DiscordSendArgs),
    /// Check whether a webhook is configured
    Status,
}

#[derive(Args, Debug)]
pub struct DiscordSendArgs {
    /// Title used in the Discord embed
    #[arg(long)]
    pub title: String,

    /// Optional plain-text message to include
    #[arg(long)]
    pub message: Option<String>,

    /// Optional file to upload with the notification
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Optional target/host context for embed description
    #[arg(long)]
    pub target: Option<String>,

    /// Optional interface context for embed description
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ResponderCommand {
    /// Start Responder on the requested/auto interface
    On(ResponderArgs),
    /// Stop any running Responder instance
    Off,
}

#[derive(Args, Debug)]
pub struct ResponderArgs {
    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum MitmCommand {
    /// Launch ARP spoof + tcpdump capture
    Start(MitmStartArgs),
    /// Stop running MITM/sniff processes
    Stop,
}

#[derive(Args, Debug)]
pub struct MitmStartArgs {
    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional CIDR network override for informational display
    #[arg(long)]
    pub network: Option<String>,

    /// Maximum number of hosts to target (safety cap)
    #[arg(long, default_value_t = 8)]
    pub max_hosts: usize,

    /// Optional label for loot directory naming
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum WifiCommand {
    /// List all detected network interfaces
    List,
    /// Show status for a specific interface (defaults to best)
    Status(WifiStatusArgs),
    /// Determine the best interface for operations
    Best(WifiBestArgs),
    /// Set the preferred/default interface
    Switch(WifiSwitchArgs),
    /// Scan for Wi-Fi networks
    Scan(WifiScanArgs),
    /// Manage Wi-Fi profiles
    #[command(subcommand)]
    Profile(WifiProfileCommand),
    /// Disconnect a Wi-Fi interface
    Disconnect(WifiDisconnectArgs),
    /// Manage routing/default interface
    #[command(subcommand)]
    Route(WifiRouteCommand),
    /// Launch deauthentication attack on target network
    Deauth(WifiDeauthArgs),
    /// Launch Evil Twin attack (fake AP)
    EvilTwin(WifiEvilTwinArgs),
    /// Capture PMKID from target network
    PmkidCapture(WifiPmkidArgs),
    /// Sniff probe requests from nearby devices
    ProbeSniff(WifiProbeSniffArgs),
    /// Crack captured handshake/PMKID
    Crack(WifiCrackArgs),
    /// Launch Karma attack (respond to all probe requests)
    Karma(WifiKarmaArgs),
    /// Post-connection reconnaissance
    #[command(subcommand)]
    Recon(WifiReconCommand),
}

#[derive(Args, Debug)]
pub struct WifiStatusArgs {
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Args, Debug)]
pub struct WifiBestArgs {
    #[arg(long)]
    pub prefer_wifi: bool,
}

#[derive(Args, Debug)]
pub struct WifiSwitchArgs {
    #[arg(long)]
    pub interface: String,
}

#[derive(Args, Debug)]
pub struct WifiScanArgs {
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Args, Debug)]
pub struct WifiDeauthArgs {
    /// Target network BSSID (MAC address of AP, e.g., AA:BB:CC:DD:EE:FF)
    #[arg(long)]
    pub bssid: String,
    /// Target network SSID (for logging/display)
    #[arg(long)]
    pub ssid: Option<String>,
    /// Interface to use for attack (must support monitor mode)
    #[arg(long)]
    pub interface: String,
    /// Channel number of the target AP
    #[arg(long)]
    pub channel: u8,
    /// Duration in seconds for the attack (default: 120)
    #[arg(long, default_value_t = 120)]
    pub duration: u32,
    /// Number of deauth packets per burst (default: 64)
    #[arg(long, default_value_t = 64)]
    pub packets: u32,
    /// Target client MAC address (omit for broadcast attack on all clients)
    #[arg(long)]
    pub client: Option<String>,
    /// Continuous mode: keep sending deauth packets throughout duration
    #[arg(long, default_value_t = true)]
    pub continuous: bool,
    /// Interval between deauth bursts in seconds (default: 1)
    #[arg(long, default_value_t = 1)]
    pub interval: u32,
}

#[derive(Args, Debug)]
pub struct WifiEvilTwinArgs {
    /// SSID to impersonate
    #[arg(long)]
    pub ssid: String,
    /// Interface for the fake AP
    #[arg(long)]
    pub interface: String,
    /// Channel for the fake AP
    #[arg(long, default_value_t = 6)]
    pub channel: u8,
    /// Target BSSID to deauth clients from (optional)
    #[arg(long)]
    pub target_bssid: Option<String>,
    /// Duration in seconds (default: 300 = 5 minutes)
    #[arg(long, default_value_t = 300)]
    pub duration: u32,
    /// Use open network (captive portal style)
    #[arg(long, default_value_t = true)]
    pub open: bool,
}

#[derive(Args, Debug)]
pub struct WifiPmkidArgs {
    /// Interface to use
    #[arg(long)]
    pub interface: String,
    /// Target BSSID (optional, for targeted capture)
    #[arg(long)]
    pub bssid: Option<String>,
    /// Target SSID (optional)
    #[arg(long)]
    pub ssid: Option<String>,
    /// Channel (0 = hop channels)
    #[arg(long, default_value_t = 0)]
    pub channel: u8,
    /// Capture duration in seconds
    #[arg(long, default_value_t = 60)]
    pub duration: u32,
}

#[derive(Args, Debug)]
pub struct WifiProbeSniffArgs {
    /// Interface to use
    #[arg(long)]
    pub interface: String,
    /// Duration in seconds
    #[arg(long, default_value_t = 60)]
    pub duration: u32,
    /// Channel to sniff on (0 = hop)
    #[arg(long, default_value_t = 0)]
    pub channel: u8,
}

#[derive(Args, Debug)]
pub struct WifiCrackArgs {
    /// Path to handshake file (.cap, .pcap, .hc22000)
    #[arg(long)]
    pub file: String,
    /// SSID of the network (required for cracking)
    #[arg(long)]
    pub ssid: Option<String>,
    /// Crack mode: quick, pins, ssid, wordlist
    #[arg(long, default_value = "quick")]
    pub mode: String,
    /// Path to wordlist file (for wordlist mode)
    #[arg(long)]
    pub wordlist: Option<String>,
}

#[derive(Args, Debug)]
pub struct WifiKarmaArgs {
    /// Interface for probe sniffing (must support monitor mode)
    #[arg(long)]
    pub interface: String,
    /// Optional second interface for fake AP (enables full Karma with AP)
    #[arg(long)]
    pub ap_interface: Option<String>,
    /// Duration in seconds (default: 300 = 5 minutes)
    #[arg(long, default_value_t = 300)]
    pub duration: u32,
    /// Channel to operate on (0 = hop channels)
    #[arg(long, default_value_t = 0)]
    pub channel: u8,
    /// Create fake AP for captured SSIDs
    #[arg(long, default_value_t = false)]
    pub with_ap: bool,
    /// SSIDs to respond to (comma-separated, empty = all)
    #[arg(long)]
    pub ssid_whitelist: Option<String>,
    /// SSIDs to ignore (comma-separated)
    #[arg(long)]
    pub ssid_blacklist: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum WifiReconCommand {
    /// Discover gateway, DNS servers, and DHCP server
    Gateway(WifiReconGatewayArgs),
    /// ARP scan to discover devices on local subnet
    ArpScan(WifiReconArpScanArgs),
    /// Scan common network services on discovered devices
    ServiceScan(WifiReconServiceScanArgs),
    /// Discover mDNS/Bonjour devices
    MdnsScan(WifiReconMdnsScanArgs),
    /// Monitor bandwidth usage
    Bandwidth(WifiReconBandwidthArgs),
    /// Capture DNS queries
    DnsCapture(WifiReconDnsCaptureArgs),
}

#[derive(Args, Debug)]
pub struct WifiReconGatewayArgs {
    /// Interface to query (defaults to active connection)
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Args, Debug)]
pub struct WifiReconArpScanArgs {
    /// Interface to scan on
    #[arg(long)]
    pub interface: String,
}

#[derive(Args, Debug)]
pub struct WifiReconServiceScanArgs {
    /// Interface to scan on
    #[arg(long)]
    pub interface: String,
}

#[derive(Args, Debug)]
pub struct WifiReconMdnsScanArgs {
    /// Duration in seconds to listen for mDNS announcements
    #[arg(long, default_value_t = 10)]
    pub duration: u64,
}

#[derive(Args, Debug)]
pub struct WifiReconBandwidthArgs {
    /// Interface to monitor
    #[arg(long)]
    pub interface: String,
    /// Duration in seconds to monitor
    #[arg(long, default_value_t = 10)]
    pub duration: u64,
}

#[derive(Args, Debug)]
pub struct WifiReconDnsCaptureArgs {
    /// Interface to capture on
    #[arg(long)]
    pub interface: String,
    /// Duration in seconds to capture
    #[arg(long, default_value_t = 60)]
    pub duration: u64,
}

#[derive(Subcommand, Debug)]
pub enum WifiProfileCommand {
    /// List saved Wi-Fi profiles
    List,
    /// Save or update a Wi-Fi profile
    Save(WifiProfileSaveArgs),
    /// Connect using a saved profile or explicit credentials
    Connect(WifiProfileConnectArgs),
    /// Delete a saved Wi-Fi profile
    Delete(WifiProfileDeleteArgs),
}

#[derive(Args, Debug)]
pub struct WifiProfileSaveArgs {
    #[arg(long)]
    pub ssid: String,
    #[arg(long)]
    pub password: String,
    #[arg(long, default_value = "auto")]
    pub interface: String,
    #[arg(long, default_value_t = 1)]
    pub priority: u8,
    #[arg(long)]
    pub auto_connect: Option<bool>,
}

#[derive(Args, Debug)]
pub struct WifiProfileConnectArgs {
    /// Optional saved profile name (defaults to sanitized SSID)
    #[arg(long)]
    pub profile: Option<String>,
    /// Raw SSID (required if --profile not provided)
    #[arg(long)]
    pub ssid: Option<String>,
    /// Optional password for protected networks
    #[arg(long)]
    pub password: Option<String>,
    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,
    /// Remember supplied credentials as a profile
    #[arg(long)]
    pub remember: bool,
}

#[derive(Args, Debug)]
pub struct WifiProfileDeleteArgs {
    /// Profile/SSID identifier to delete
    #[arg(long)]
    pub ssid: String,
}

#[derive(Args, Debug)]
pub struct WifiDisconnectArgs {
    /// Interface to disconnect (defaults to active Wi-Fi)
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum WifiRouteCommand {
    /// Show default route and DNS information
    Status,
    /// Force an interface to become the default route
    Ensure(WifiRouteEnsureArgs),
    /// Backup the current routing configuration
    Backup,
    /// Restore routing from the last backup
    Restore,
    /// Set the metric/priority for an interface
    SetMetric(WifiRouteMetricArgs),
}

#[derive(Args, Debug)]
pub struct WifiRouteEnsureArgs {
    #[arg(long)]
    pub interface: String,
}

#[derive(Args, Debug)]
pub struct WifiRouteMetricArgs {
    #[arg(long)]
    pub interface: String,
    #[arg(long, default_value_t = 100)]
    pub metric: u32,
}

#[derive(Subcommand, Debug)]
pub enum DnsSpoofCommand {
    /// Start DNS spoofing for the selected template
    Start(DnsSpoofStartArgs),
    /// Stop the spoofing services
    Stop,
}

#[derive(Args, Debug)]
pub struct DnsSpoofStartArgs {
    /// Site template to serve (must exist under DNSSpoof/sites)
    #[arg(long)]
    pub site: String,

    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,

    /// Optional loot directory base to store captures (per-network)
    #[arg(long)]
    pub loot_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum LootCommand {
    /// List loot files for a given tool
    List(LootListArgs),
    /// Read a specific loot file
    Read(LootReadArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LootKind {
    Nmap,
    Responder,
    Dnsspoof,
    Ethernet,
    /// Wireless attack captures (deauth, handshakes, etc.)
    Wireless,
}

#[derive(Args, Debug)]
pub struct LootListArgs {
    #[arg(long, value_enum)]
    pub kind: LootKind,
}

#[derive(Args, Debug)]
pub struct LootReadArgs {
    /// Absolute or relative path to the loot file
    #[arg(long)]
    pub path: std::path::PathBuf,

    /// Limit the number of lines returned
    #[arg(long, default_value_t = 1000)]
    pub max_lines: usize,
}

#[derive(Subcommand, Debug)]
pub enum ProcessCommand {
    /// Terminate processes by exact name
    Kill(ProcessKillArgs),
    /// Check if specific processes are running
    Status(ProcessStatusArgs),
}

#[derive(Args, Debug)]
pub struct ProcessKillArgs {
    /// Process names to kill (repeat for multiple targets)
    #[arg(long = "name")]
    pub names: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ProcessStatusArgs {
    /// Process names to check (repeat for multiple targets)
    #[arg(long = "name")]
    pub names: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum StatusCommand {
    /// Report running-state information for attack modules
    Summary,
    /// Provide a network health dashboard
    Network,
}

#[derive(Subcommand, Debug)]
pub enum HardwareCommand {
    /// Scan and detect all available network hardware
    Detect,
}

#[derive(Subcommand, Debug)]
pub enum ReverseCommand {
    /// Launch a reverse shell via ncat
    Launch(ReverseLaunchArgs),
}

#[derive(Args, Debug)]
pub struct ReverseLaunchArgs {
    /// Target IP address to connect back to
    #[arg(long)]
    pub target: String,

    /// Target port to connect back to
    #[arg(long, default_value_t = 4444)]
    pub port: u16,

    /// Shell to expose on connect (default /bin/bash)
    #[arg(long, default_value = "/bin/bash")]
    pub shell: String,

    /// Optional interface to source traffic from
    #[arg(long)]
    pub interface: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SystemCommand {
    /// Backup, update from git, and restart the Rustyjack service
    Update(SystemUpdateArgs),
    /// Randomize hostname to a plausible, non-identifying value
    RandomizeHostname,
    /// Prepare a USB key for full disk encryption (formats device)
    FdePrepare(SystemFdePrepareArgs),
    /// Migrate root into encrypted volume (destructive; defaults to dry run)
    FdeMigrate(SystemFdeMigrateArgs),
}

#[derive(Args, Debug)]
pub struct SystemUpdateArgs {
    /// Systemd service to restart after updating
    #[arg(long, default_value = "rustyjack")]
    pub service: String,

    /// Git remote to fetch/reset
    #[arg(long, default_value = "origin")]
    pub remote: String,

    /// Git branch to reset to
    #[arg(long, default_value = "main")]
    pub branch: String,

    /// Directory where the backup archive should be written
    #[arg(long)]
    pub backup_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SystemFdePrepareArgs {
    /// Target removable USB device (e.g., /dev/sda)
    #[arg(long)]
    pub device: String,
}

#[derive(Args, Debug)]
pub struct SystemFdeMigrateArgs {
    /// Target block device for encrypted root (unused partition)
    #[arg(long)]
    pub target: String,
    /// Path to keyfile (e.g., /mnt/usb/rustyjack.key)
    #[arg(long)]
    pub keyfile: String,
    /// Perform destructive actions; omit to run dry-run only
    #[arg(long, default_value_t = false)]
    pub execute: bool,
}

#[derive(Subcommand, Debug)]
pub enum BridgeCommand {
    /// Create a transparent bridge between two interfaces and capture traffic
    Start(BridgeStartArgs),
    /// Tear down the bridge and stop capturing
    Stop(BridgeStopArgs),
}

#[derive(Args, Debug)]
pub struct BridgeStartArgs {
    #[arg(long = "interface-a", default_value = "eth0")]
    pub interface_a: String,
    #[arg(long = "interface-b", default_value = "eth1")]
    pub interface_b: String,
}

#[derive(Args, Debug)]
pub struct BridgeStopArgs {
    #[arg(long = "interface-a", default_value = "eth0")]
    pub interface_a: String,
    #[arg(long = "interface-b", default_value = "eth1")]
    pub interface_b: String,
}


