use std::collections::HashMap;

use anyhow::{anyhow, Result};

#[derive(Clone)]
pub enum MenuAction {
    Submenu(&'static str),
    RefreshConfig,
    SaveConfig,
    SetColor(ColorTarget),
    RestartSystem,
    SecureShutdown,
    Loot(LootSection),
    DiscordUpload,
    ViewDashboards,
    ToggleDiscord,
    ToggleLogs,
    TransferToUSB,
    HardwareDetect,
    DeauthAttack,
    ScanNetworks,
    ConnectKnownNetwork,
    // New wireless attack actions
    EvilTwinAttack,
    ProbeSniff,
    PmkidCapture,
    CrackHandshake,
    /// Install USB WiFi drivers
    InstallWifiDrivers,
    /// Karma attack - respond to all probes
    KarmaAttack,
    /// WiFi status/route actions (post-connection)
    WifiStatus,
    WifiDisconnect,
    WifiEnsureRoute,
    /// Post-connection recon actions
    ReconGateway,
    ReconArpScan,
    ReconServiceScan,
    ReconMdnsScan,
    ReconBandwidth,
    ReconDnsCapture,
    ManageSavedNetworks,
    /// Post-connection wireless offensive actions
    ResponderOn,
    ResponderOff,
    ToggleResponder,
    DnsSpoofStart,
    DnsSpoofStop,
    ToggleDnsSpoof,
    ReverseShell,
    /// Autopilot control
    AutopilotStart(rustyjack_core::cli::AutopilotMode),
    AutopilotStop,
    AutopilotStatus,
    /// Attack pipelines - automated sequences
    AttackPipeline(PipelineType),
    /// Toggle MAC randomization on/off
    ToggleMacRandomization,
    /// Randomize MAC address now
    RandomizeMacNow,
    ImportWifiFromUsb,
    ImportWebhookFromUsb,
    /// Set MAC to a specific vendor OUI
    SetVendorMac,
    /// Restore original MAC
    RestoreMac,
    /// Toggle hostname randomization on/off
    ToggleHostnameRandomization,
    /// Randomize hostname now
    RandomizeHostnameNow,
    /// Set operation mode (stealth/default/aggressive/custom)
    SetOperationMode(&'static str),
    /// Set TX power
    SetTxPower(TxPowerSetting),
    /// Toggle passive mode
    TogglePassiveMode,
    /// Enter passive recon mode
    PassiveRecon,
    /// Ethernet LAN discovery
    EthernetDiscovery,
    /// Ethernet quick port scan
    EthernetPortScan,
    /// Ethernet device inventory
    EthernetInventory,
    /// Ethernet pipelines submenu entry
    EthernetSiteCredPipeline,
    /// Run Ethernet site credential capture pipeline
    EthernetSiteCredCapture,
    /// View MITM/DNS spoof status
    EthernetMitmStatus,
    /// Stop Ethernet MITM/DNS spoofing
    EthernetMitmStop,
    /// Build a per-network report from loot
    BuildNetworkReport,
    /// Ethernet MITM / ARP spoof capture
    EthernetMitm,
    /// Load encryption key from USB
    EncryptionLoadKey,
    /// Generate encryption key to USB
    EncryptionGenerateKey,
    /// Toggle master encryption
    ToggleEncryptionMaster,
    /// Toggle webhook encryption
    ToggleEncryptWebhook,
    /// Toggle loot encryption
    ToggleEncryptLoot,
    /// Toggle Wi-Fi profile encryption
    ToggleEncryptWifiProfiles,
    /// Enter full disk encryption flow
    FullDiskEncryptionSetup,
    /// Start encrypted root migration (uses prepared key)
    FullDiskEncryptionMigrate,
    /// Purge everything related to Rustyjack
    CompletePurge,
    /// Purge log files from loot
    PurgeLogs,
    /// Hotspot management
    Hotspot,
    /// Placeholder for informational entries (no action)
    ShowInfo,
}

/// Pipeline types for automated attacks
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PipelineType {
    /// Get WiFi password automatically
    GetPassword,
    /// Capture all handshakes in range
    MassCapture,
    /// Stealth reconnaissance
    StealthRecon,
    /// Credential harvesting (evil twin + karma)
    CredentialHarvest,
    /// Full automated pentest
    FullPentest,
}

/// TX Power settings
#[derive(Clone, Copy)]
pub enum TxPowerSetting {
    Stealth,
    Low,
    Medium,
    High,
    Maximum,
}

#[derive(Clone)]
pub struct MenuEntry {
    pub label: String,
    pub action: MenuAction,
}

impl MenuEntry {
    fn new(label: &str, action: MenuAction) -> Self {
        Self {
            label: label.to_string(),
            action,
        }
    }
}

pub enum MenuNode {
    Static(fn() -> Vec<MenuEntry>),
}

pub struct MenuTree {
    nodes: HashMap<&'static str, MenuNode>,
}

impl MenuTree {
    pub fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert("a", MenuNode::Static(main_menu));
        nodes.insert("aea", MenuNode::Static(colors_menu));
        nodes.insert("af", MenuNode::Static(system_menu));
        nodes.insert("ah", MenuNode::Static(loot_menu));
        nodes.insert("aw", MenuNode::Static(wifi_menu));
        nodes.insert("aw", MenuNode::Static(wireless_menu));
        nodes.insert("awa", MenuNode::Static(wifi_access_menu));
        nodes.insert("awar", MenuNode::Static(wifi_access_recon_menu));
        nodes.insert("awao", MenuNode::Static(wifi_access_offence_menu));
        nodes.insert("awc", MenuNode::Static(wifi_connected_menu));
        nodes.insert("awcr", MenuNode::Static(wifi_connected_recon_menu));
        nodes.insert("awco", MenuNode::Static(wifi_connected_offence_menu));
        nodes.insert("aops", MenuNode::Static(operation_mode_menu));
        nodes.insert("as", MenuNode::Static(settings_menu));
        nodes.insert("asl", MenuNode::Static(logs_menu));
        nodes.insert("asd", MenuNode::Static(discord_menu));
        nodes.insert("asc", MenuNode::Static(config_menu));
        nodes.insert("ap", MenuNode::Static(pipeline_menu));
        nodes.insert("ao", MenuNode::Static(obfuscation_menu)); // Obfuscation & Evasion
        nodes.insert("aom", MenuNode::Static(mac_menu)); // MAC address submenu
        nodes.insert("aoh", MenuNode::Static(hostname_menu)); // Hostname submenu
        nodes.insert("aopp", MenuNode::Static(operating_menu)); // Operating mode submenu
        nodes.insert("atx", MenuNode::Static(tx_power_menu));
        nodes.insert("aeth", MenuNode::Static(ethernet_menu));
        nodes.insert("aethp", MenuNode::Static(ethernet_pipeline_menu));
        nodes.insert("apt", MenuNode::Static(autopilot_menu));
        nodes.insert("enc", MenuNode::Static(encryption_menu));
        nodes.insert("encadv", MenuNode::Static(encryption_advanced_menu));
        Self { nodes }
    }

    pub fn entries(&self, menu: &str) -> Result<Vec<MenuEntry>> {
        let node = self
            .nodes
            .get(menu)
            .ok_or_else(|| anyhow!("unknown menu {menu}"))?;
        match node {
            MenuNode::Static(builder) => Ok(builder()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ColorTarget {
    Background,
    #[allow(dead_code)]
    Border,
    Text,
    SelectedText,
    SelectedBackground,
    Toolbar,
}

#[derive(Clone, Copy)]
pub enum LootSection {
    Wireless,
    Ethernet,
}

fn main_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Dashboards", MenuAction::ViewDashboards),
        MenuEntry::new("Operation Mode", MenuAction::Submenu("aops")),
        MenuEntry::new("Hardware Detect", MenuAction::HardwareDetect),
        MenuEntry::new("Wireless", MenuAction::Submenu("aw")),
        MenuEntry::new("Ethernet", MenuAction::Submenu("aeth")),
        MenuEntry::new("Obfuscation", MenuAction::Submenu("ao")),
        MenuEntry::new("Encryption", MenuAction::Submenu("enc")),
        MenuEntry::new("Loot", MenuAction::Submenu("ah")),
        MenuEntry::new("Settings", MenuAction::Submenu("as")),
    ]
}

fn wifi_menu() -> Vec<MenuEntry> {
    // Legacy menu, kept for safety but replaced by awa/awc
    vec![
        MenuEntry::new("Select Target Network", MenuAction::ScanNetworks),
        MenuEntry::new("Attack Pipelines", MenuAction::Submenu("ap")),
    ]
}

fn wireless_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Get Connected", MenuAction::Submenu("awa")),
        MenuEntry::new("Manage Saved Networks", MenuAction::ManageSavedNetworks),
        MenuEntry::new("Post Connection", MenuAction::Submenu("awc")),
        MenuEntry::new("Hotspot", MenuAction::Hotspot),
    ]
}

fn wifi_access_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Select Target Network", MenuAction::ScanNetworks),
        MenuEntry::new("Connect Network", MenuAction::ConnectKnownNetwork),
        MenuEntry::new("Pipelines", MenuAction::Submenu("ap")),
        MenuEntry::new("Recon", MenuAction::Submenu("awar")),
        MenuEntry::new("Offence", MenuAction::Submenu("awao")),
        MenuEntry::new("Import WiFi from USB", MenuAction::ImportWifiFromUsb),
    ]
}

fn wifi_connected_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Ensure Route", MenuAction::WifiEnsureRoute),
        MenuEntry::new("Recon", MenuAction::Submenu("awcr")),
        MenuEntry::new("Offence", MenuAction::Submenu("awco")),
        MenuEntry::new("Disconnect WiFi", MenuAction::WifiDisconnect),
    ]
}

fn wifi_access_recon_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Probe Sniff", MenuAction::ProbeSniff),
        MenuEntry::new("PMKID Capture", MenuAction::PmkidCapture),
    ]
}

fn wifi_access_offence_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Deauth Attack", MenuAction::DeauthAttack),
        MenuEntry::new("Evil Twin AP", MenuAction::EvilTwinAttack),
        MenuEntry::new("Karma Attack", MenuAction::KarmaAttack),
        MenuEntry::new("Crack Handshake", MenuAction::CrackHandshake),
    ]
}

fn wifi_connected_recon_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("WiFi Status", MenuAction::WifiStatus),
        MenuEntry::new("Gateway Info", MenuAction::ReconGateway),
        MenuEntry::new("ARP Scan", MenuAction::ReconArpScan),
        MenuEntry::new("Service Scan", MenuAction::ReconServiceScan),
        MenuEntry::new("mDNS Discovery", MenuAction::ReconMdnsScan),
        MenuEntry::new("Bandwidth Monitor", MenuAction::ReconBandwidth),
        MenuEntry::new("DNS Capture", MenuAction::ReconDnsCapture),
    ]
}

fn wifi_connected_offence_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Responder [OFF]", MenuAction::ToggleResponder),
        MenuEntry::new("DNS Spoof [OFF]", MenuAction::ToggleDnsSpoof),
        MenuEntry::new("Reverse Shell", MenuAction::ReverseShell),
    ]
}

fn ethernet_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("LAN Discovery", MenuAction::EthernetDiscovery),
        MenuEntry::new("Port Scan", MenuAction::EthernetPortScan),
        MenuEntry::new("Device Inventory", MenuAction::EthernetInventory),
        MenuEntry::new("MITM Capture", MenuAction::EthernetMitm),
        MenuEntry::new("MITM Status", MenuAction::EthernetMitmStatus),
        MenuEntry::new("Stop MITM/DNS", MenuAction::EthernetMitmStop),
        MenuEntry::new("Pipelines", MenuAction::EthernetSiteCredPipeline),
        MenuEntry::new("Autopilot", MenuAction::Submenu("apt")),
    ]
}

fn ethernet_pipeline_menu() -> Vec<MenuEntry> {
    vec![MenuEntry::new(
        "Site Cred Capture",
        MenuAction::EthernetSiteCredCapture,
    )]
}

fn encryption_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Encryption [OFF]", MenuAction::ToggleEncryptionMaster),
        MenuEntry::new("Webhook [OFF]", MenuAction::ToggleEncryptWebhook),
        MenuEntry::new("Loot [OFF]", MenuAction::ToggleEncryptLoot),
        MenuEntry::new("WiFi Profiles [OFF]", MenuAction::ToggleEncryptWifiProfiles),
        MenuEntry::new("Load Key from USB", MenuAction::EncryptionLoadKey),
        MenuEntry::new("Generate Key on USB", MenuAction::EncryptionGenerateKey),
        MenuEntry::new("Advanced", MenuAction::Submenu("encadv")),
    ]
}

fn encryption_advanced_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Full Disk Encryption", MenuAction::FullDiskEncryptionSetup),
        MenuEntry::new(
            "Run Migration (dry/destructive)",
            MenuAction::FullDiskEncryptionMigrate,
        ),
    ]
}

fn pipeline_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(
            "Get WiFi Password",
            MenuAction::AttackPipeline(PipelineType::GetPassword),
        ),
        MenuEntry::new(
            "Mass Capture",
            MenuAction::AttackPipeline(PipelineType::MassCapture),
        ),
        MenuEntry::new(
            "Stealth Recon",
            MenuAction::AttackPipeline(PipelineType::StealthRecon),
        ),
        MenuEntry::new(
            "Harvest Creds",
            MenuAction::AttackPipeline(PipelineType::CredentialHarvest),
        ),
        MenuEntry::new(
            "Full Pentest",
            MenuAction::AttackPipeline(PipelineType::FullPentest),
        ),
    ]
}

fn autopilot_menu() -> Vec<MenuEntry> {
    use rustyjack_core::cli::AutopilotMode;
    vec![
        MenuEntry::new(
            "Start Standard",
            MenuAction::AutopilotStart(AutopilotMode::Standard),
        ),
        MenuEntry::new(
            "Start Aggressive",
            MenuAction::AutopilotStart(AutopilotMode::Aggressive),
        ),
        MenuEntry::new(
            "Start Stealth",
            MenuAction::AutopilotStart(AutopilotMode::Stealth),
        ),
        MenuEntry::new(
            "Start Harvest",
            MenuAction::AutopilotStart(AutopilotMode::Harvest),
        ),
        MenuEntry::new("Stop Autopilot", MenuAction::AutopilotStop),
        MenuEntry::new("Status / Refresh", MenuAction::AutopilotStatus),
    ]
}

#[allow(dead_code)]
fn stealth_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Randomize MAC", MenuAction::RandomizeMacNow),
        MenuEntry::new("Restore MAC", MenuAction::RestoreMac),
        MenuEntry::new("TX Power", MenuAction::Submenu("atx")),
    ]
}

/// Obfuscation & Evasion menu - toggles and stealth options
fn obfuscation_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("MAC Address", MenuAction::Submenu("aom")),
        MenuEntry::new("Hostname", MenuAction::Submenu("aoh")),
        MenuEntry::new("TX Power", MenuAction::Submenu("atx")),
    ]
}

fn mac_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("MAC Random: ???", MenuAction::ToggleMacRandomization),
        MenuEntry::new("Randomize Now", MenuAction::RandomizeMacNow),
        MenuEntry::new("Set Vendor MAC", MenuAction::SetVendorMac),
        MenuEntry::new("Restore MAC", MenuAction::RestoreMac),
    ]
}

fn hostname_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(
            "Hostname Random: ???",
            MenuAction::ToggleHostnameRandomization,
        ),
        MenuEntry::new("Randomize Now", MenuAction::RandomizeHostnameNow),
    ]
}

fn operating_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Passive: ???", MenuAction::TogglePassiveMode),
        MenuEntry::new("Passive Recon", MenuAction::PassiveRecon),
    ]
}

fn operation_mode_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Stealth (RX-only)", MenuAction::SetOperationMode("stealth")),
        MenuEntry::new("Default", MenuAction::SetOperationMode("default")),
        MenuEntry::new("Aggressive", MenuAction::SetOperationMode("aggressive")),
        MenuEntry::new("Custom", MenuAction::SetOperationMode("custom")),
    ]
}

fn tx_power_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(
            "Stealth (1dBm)",
            MenuAction::SetTxPower(TxPowerSetting::Stealth),
        ),
        MenuEntry::new("Low (5dBm)", MenuAction::SetTxPower(TxPowerSetting::Low)),
        MenuEntry::new(
            "Medium (12dBm)",
            MenuAction::SetTxPower(TxPowerSetting::Medium),
        ),
        MenuEntry::new("High (18dBm)", MenuAction::SetTxPower(TxPowerSetting::High)),
        MenuEntry::new("Maximum", MenuAction::SetTxPower(TxPowerSetting::Maximum)),
    ]
}

fn settings_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Discord", MenuAction::Submenu("asd")),
        MenuEntry::new("Colors", MenuAction::Submenu("aea")),
        MenuEntry::new("Logs", MenuAction::Submenu("asl")),
        MenuEntry::new("Config", MenuAction::Submenu("asc")),
        MenuEntry::new("System", MenuAction::Submenu("af")),
        MenuEntry::new("WiFi Drivers", MenuAction::InstallWifiDrivers),
    ]
}

fn logs_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Logs: ???", MenuAction::ToggleLogs),
        MenuEntry::new("Purge Logs", MenuAction::PurgeLogs),
    ]
}

fn discord_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Toggle Discord", MenuAction::ToggleDiscord),
        MenuEntry::new("Import Whook from USB", MenuAction::ImportWebhookFromUsb),
        MenuEntry::new("Upload Loot", MenuAction::DiscordUpload),
    ]
}

fn colors_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Background", MenuAction::SetColor(ColorTarget::Background)),
        MenuEntry::new("Text", MenuAction::SetColor(ColorTarget::Text)),
        MenuEntry::new(
            "Selected Text",
            MenuAction::SetColor(ColorTarget::SelectedText),
        ),
        MenuEntry::new(
            "Selected BG",
            MenuAction::SetColor(ColorTarget::SelectedBackground),
        ),
        MenuEntry::new("Toolbar", MenuAction::SetColor(ColorTarget::Toolbar)),
    ]
}

fn config_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Refresh Config", MenuAction::RefreshConfig),
        MenuEntry::new("Save Config", MenuAction::SaveConfig),
    ]
}

fn system_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Restart", MenuAction::RestartSystem),
        MenuEntry::new("Secure Shutdown", MenuAction::SecureShutdown),
        MenuEntry::new("Complete Purge", MenuAction::CompletePurge),
    ]
}

fn loot_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Wireless Captures", MenuAction::Loot(LootSection::Wireless)),
        MenuEntry::new("Ethernet Loot", MenuAction::Loot(LootSection::Ethernet)),
        MenuEntry::new("Reports", MenuAction::BuildNetworkReport),
        MenuEntry::new("Transfer to USB", MenuAction::TransferToUSB),
    ]
}

pub fn menu_title(id: &str) -> &'static str {
    match id {
        "a" => "Main Menu",
        "aea" => "Colors",
        "af" => "System",
        "ah" => "Loot",
        "aw" => "Wireless",
        "awa" => "Get Connected",
        "awar" => "Wireless Recon",
        "awao" => "Wireless Offence",
        "awc" => "Post Connection",
        "awcr" => "Connected Recon",
        "awco" => "Connected Offence",
        "aeth" => "Ethernet Recon",
        "aethp" => "Ethernet Pipelines",
        "apt" => "Autopilot",
        "as" => "Settings",
        "asl" => "Logs",
        "asd" => "Discord",
        "asc" => "Config",
        "ap" => "Attack Pipelines",
        "ao" => "Obfuscation & Evasion",
        "aom" => "MAC Address",
        "aopp" => "Operating Mode",
        "atx" => "TX Power",
        "enc" => "Encryption",
        "encadv" => "Encryption: Advanced",
        _ => "Menu",
    }
}
