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
    Autopilot(AutopilotCommand),
    #[command(subcommand)]
    Hardware(HardwareCommand),
}

#[derive(Subcommand, Debug)]
pub enum ScanCommand {
    Run(ScanRunArgs),
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

#[derive(Subcommand, Debug)]
pub enum AutopilotCommand {
    /// Start autopilot with specified mode
    Start(AutopilotStartArgs),
    /// Stop autopilot
    Stop,
    /// Get current autopilot status
    Status,
}

#[derive(Args, Debug)]
pub struct AutopilotStartArgs {
    /// Autopilot mode to run
    #[arg(long, value_enum, default_value_t = AutopilotMode::Standard)]
    pub mode: AutopilotMode,
    
    /// Optional interface override
    #[arg(long)]
    pub interface: Option<String>,
    
    /// Run scan phase
    #[arg(long, default_value_t = true)]
    pub scan: bool,
    
    /// Run MITM attack
    #[arg(long, default_value_t = true)]
    pub mitm: bool,
    
    /// Run Responder
    #[arg(long, default_value_t = true)]
    pub responder: bool,
    
    /// DNS spoofing site template (empty to skip)
    #[arg(long)]
    pub dns_spoof: Option<String>,
    
    /// Max duration in seconds (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub duration: u64,
    
    /// Interval between status checks in seconds
    #[arg(long, default_value_t = 30)]
    pub check_interval: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AutopilotMode {
    /// Standard mode: scan -> MITM -> responder
    Standard,
    /// Aggressive mode: all attacks simultaneously
    Aggressive,
    /// Stealth mode: slow scan, passive monitoring
    Stealth,
    /// Credential harvesting focus
    Harvest,
}
