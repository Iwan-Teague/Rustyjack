use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::config::ColorScheme;

#[allow(dead_code)]
#[derive(Clone)]
pub enum MenuAction {
    Submenu(&'static str),
    RefreshConfig,
    SaveConfig,
    SetColor(ColorTarget),
    ApplyThemePreset,
    RestartSystem,
    SystemUpdate,
    SecureShutdown,
    Loot(LootSection),
    DiscordUpload,
    ViewDashboards,
    ToggleDiscord,
    ToggleLogs,
    DisplayBackendInfo,
    DisplayRotationInfo,
    DisplayResolutionInfo,
    DisplayOffsetInfo,
    RunDisplayDiscovery,
    RunDisplayCalibration,
    ResetDisplayCalibration,
    ResetDisplayCache,
    ShowDisplayDiagnostics,
    ExportLogsToUsb,
    TransferToUSB,
    HardwareDetect,
    DeauthAttack,
    ScanNetworks,
    ConnectKnownNetwork,
    /// Select active network interface (isolation enforcement)
    SelectActiveInterface,
    /// View current active interface
    ViewInterfaceStatus,
    // New wireless attack actions
    EvilTwinAttack,
    ProbeSniff,
    PmkidCapture,
    CrackHandshake,
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
    DnsSpoofStart,
    DnsSpoofStop,
    ToggleDnsSpoof,
    ReverseShell,
    /// Attack pipelines - automated sequences
    AttackPipeline(PipelineType),
    /// Toggle MAC randomization on/off
    ToggleMacRandomization,
    /// Toggle per-network MAC pinning on/off
    TogglePerNetworkMac,
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
    /// Toggle daemon ops categories
    ToggleOps(OpsCategory),
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpsCategory {
    Wifi,
    Ethernet,
    Hotspot,
    Portal,
    Storage,
    Power,
    Update,
    System,
    Dev,
    Offensive,
    Loot,
    Process,
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
        nodes.insert("aw", MenuNode::Static(wireless_menu));
        nodes.insert("awa", MenuNode::Static(wifi_access_menu));
        nodes.insert("awar", MenuNode::Static(wifi_access_recon_menu));
        nodes.insert("awao", MenuNode::Static(wifi_access_offence_menu));
        nodes.insert("awc", MenuNode::Static(wifi_connected_menu));
        nodes.insert("awcr", MenuNode::Static(wifi_connected_recon_menu));
        nodes.insert("awco", MenuNode::Static(wifi_connected_offence_menu));
        nodes.insert("aops", MenuNode::Static(operation_mode_menu));
        nodes.insert("aopst", MenuNode::Static(ops_menu));
        nodes.insert("as", MenuNode::Static(settings_menu));
        nodes.insert("asl", MenuNode::Static(logs_menu));
        nodes.insert("asd", MenuNode::Static(discord_menu));
        nodes.insert("asc", MenuNode::Static(config_menu));
        nodes.insert("asdp", MenuNode::Static(display_menu));
        nodes.insert("asif", MenuNode::Static(interface_menu));
        nodes.insert("ap", MenuNode::Static(pipeline_menu));
        nodes.insert("ao", MenuNode::Static(obfuscation_menu)); // Obfuscation & Evasion
        nodes.insert("aom", MenuNode::Static(mac_menu)); // MAC address submenu
        nodes.insert("aoh", MenuNode::Static(hostname_menu)); // Hostname submenu
        nodes.insert("aopp", MenuNode::Static(operating_menu)); // Operating mode submenu
        nodes.insert("atx", MenuNode::Static(tx_power_menu));
        nodes.insert("aeth", MenuNode::Static(ethernet_menu));
        nodes.insert("aethp", MenuNode::Static(ethernet_pipeline_menu));
        nodes.insert("enc", MenuNode::Static(encryption_menu));
        nodes.insert("encadv", MenuNode::Static(encryption_advanced_menu));
        nodes.insert("encusb", MenuNode::Static(encryption_usb_menu));
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

    #[cfg(test)]
    pub fn node_ids(&self) -> Vec<&'static str> {
        self.nodes.keys().copied().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorTarget {
    Background,
    Border,
    Text,
    SelectedText,
    SelectedBackground,
    Toolbar,
}

impl ColorTarget {
    pub const ALL: [Self; 6] = [
        Self::Background,
        Self::Border,
        Self::Text,
        Self::SelectedText,
        Self::SelectedBackground,
        Self::Toolbar,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Background => "Background",
            Self::Border => "Border",
            Self::Text => "Text",
            Self::SelectedText => "Selected Text",
            Self::SelectedBackground => "Selected BG",
            Self::Toolbar => "Toolbar",
        }
    }

    pub fn get(self, colors: &ColorScheme) -> &str {
        match self {
            Self::Background => &colors.background,
            Self::Border => &colors.border,
            Self::Text => &colors.text,
            Self::SelectedText => &colors.selected_text,
            Self::SelectedBackground => &colors.selected_background,
            Self::Toolbar => &colors.toolbar,
        }
    }

    pub fn set(self, colors: &mut ColorScheme, value: &str) {
        match self {
            Self::Background => colors.background = value.to_string(),
            Self::Border => colors.border = value.to_string(),
            Self::Text => colors.text = value.to_string(),
            Self::SelectedText => colors.selected_text = value.to_string(),
            Self::SelectedBackground => colors.selected_background = value.to_string(),
            Self::Toolbar => colors.toolbar = value.to_string(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum LootSection {
    Wireless,
    Ethernet,
    Reports,
}

fn main_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Dashboards", MenuAction::ViewDashboards),
        MenuEntry::new("Operation Mode", MenuAction::Submenu("aops")),
        MenuEntry::new("Operations", MenuAction::Submenu("aopst")),
        MenuEntry::new("Hardware Sanity Check", MenuAction::HardwareDetect),
        MenuEntry::new("Wireless", MenuAction::Submenu("aw")),
        MenuEntry::new("Ethernet", MenuAction::Submenu("aeth")),
        MenuEntry::new("Obfuscation", MenuAction::Submenu("ao")),
        MenuEntry::new("Encryption", MenuAction::Submenu("enc")),
        MenuEntry::new("Loot", MenuAction::Submenu("ah")),
        MenuEntry::new("Settings", MenuAction::Submenu("as")),
    ]
}

#[allow(dead_code)]
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
        MenuEntry::new("Post Connection", MenuAction::Submenu("awc")),
        MenuEntry::new("Hotspot", MenuAction::Hotspot),
        MenuEntry::new("Manage Saved Networks", MenuAction::ManageSavedNetworks),
    ]
}

fn wifi_access_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Select Target Network", MenuAction::ScanNetworks),
        MenuEntry::new("Add Network Profile", MenuAction::ConnectKnownNetwork),
        MenuEntry::new("Pipelines", MenuAction::Submenu("ap")),
        MenuEntry::new("Recon", MenuAction::Submenu("awar")),
        MenuEntry::new("Offence", MenuAction::Submenu("awao")),
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
        MenuEntry::new("DNS Spoof [OFF]", MenuAction::ToggleDnsSpoof),
        MenuEntry::new("Reverse Shell", MenuAction::ReverseShell),
    ]
}

fn ops_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("WiFi Ops", MenuAction::ToggleOps(OpsCategory::Wifi)),
        MenuEntry::new("Ethernet Ops", MenuAction::ToggleOps(OpsCategory::Ethernet)),
        MenuEntry::new("Hotspot Ops", MenuAction::ToggleOps(OpsCategory::Hotspot)),
        MenuEntry::new("Portal Ops", MenuAction::ToggleOps(OpsCategory::Portal)),
        MenuEntry::new("Storage Ops", MenuAction::ToggleOps(OpsCategory::Storage)),
        MenuEntry::new("Power Ops", MenuAction::ToggleOps(OpsCategory::Power)),
        MenuEntry::new("Update Ops", MenuAction::ToggleOps(OpsCategory::Update)),
        MenuEntry::new("System Ops", MenuAction::ToggleOps(OpsCategory::System)),
        MenuEntry::new("Dev Ops", MenuAction::ToggleOps(OpsCategory::Dev)),
        MenuEntry::new(
            "Offensive Ops",
            MenuAction::ToggleOps(OpsCategory::Offensive),
        ),
        MenuEntry::new("Loot Ops", MenuAction::ToggleOps(OpsCategory::Loot)),
        MenuEntry::new("Process Ops", MenuAction::ToggleOps(OpsCategory::Process)),
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
        MenuEntry::new("USB Settings", MenuAction::Submenu("encusb")),
        MenuEntry::new("Advanced", MenuAction::Submenu("encadv")),
    ]
}

fn encryption_advanced_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Full Disk Encryption", MenuAction::FullDiskEncryptionSetup),
        MenuEntry::new("Migration (dry/de)", MenuAction::FullDiskEncryptionMigrate),
    ]
}

fn encryption_usb_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Load Key from USB", MenuAction::EncryptionLoadKey),
        MenuEntry::new("Generate Key on USB", MenuAction::EncryptionGenerateKey),
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
        MenuEntry::new("Per-Network MAC: ???", MenuAction::TogglePerNetworkMac),
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
        MenuEntry::new("Active Interface", MenuAction::Submenu("asif")),
        MenuEntry::new("Display", MenuAction::Submenu("asdp")),
        MenuEntry::new("Discord", MenuAction::Submenu("asd")),
        MenuEntry::new("Colors", MenuAction::Submenu("aea")),
        MenuEntry::new("Logs", MenuAction::Submenu("asl")),
        MenuEntry::new("Config", MenuAction::Submenu("asc")),
        MenuEntry::new("System", MenuAction::Submenu("af")),
    ]
}

fn interface_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("View Status", MenuAction::ViewInterfaceStatus),
        MenuEntry::new("Select Interface", MenuAction::SelectActiveInterface),
    ]
}

fn display_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Display Backend", MenuAction::DisplayBackendInfo),
        MenuEntry::new("Rotation", MenuAction::DisplayRotationInfo),
        MenuEntry::new("Resolution Override", MenuAction::DisplayResolutionInfo),
        MenuEntry::new("Offsets", MenuAction::DisplayOffsetInfo),
        MenuEntry::new("Run Display Discovery", MenuAction::RunDisplayDiscovery),
        MenuEntry::new("Run Display Calibration", MenuAction::RunDisplayCalibration),
        MenuEntry::new(
            "Reset Display Calibration",
            MenuAction::ResetDisplayCalibration,
        ),
        MenuEntry::new("Reset Display Cache", MenuAction::ResetDisplayCache),
        MenuEntry::new(
            "Show Display Diagnostics",
            MenuAction::ShowDisplayDiagnostics,
        ),
    ]
}

fn logs_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Logs: ???", MenuAction::ToggleLogs),
        MenuEntry::new("Export Logs to USB", MenuAction::ExportLogsToUsb),
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
    let mut entries: Vec<MenuEntry> = ColorTarget::ALL
        .iter()
        .map(|target| MenuEntry::new(target.label(), MenuAction::SetColor(*target)))
        .collect();
    entries.push(MenuEntry::new("Apply Preset", MenuAction::ApplyThemePreset));
    entries
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
        MenuEntry::new("System Update", MenuAction::SystemUpdate),
        MenuEntry::new("Secure Shutdown", MenuAction::SecureShutdown),
        MenuEntry::new("Complete Purge", MenuAction::CompletePurge),
    ]
}

fn loot_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new("Wireless Captures", MenuAction::Loot(LootSection::Wireless)),
        MenuEntry::new("Ethernet Loot", MenuAction::Loot(LootSection::Ethernet)),
        MenuEntry::new("Browse Reports", MenuAction::Loot(LootSection::Reports)),
        MenuEntry::new("Generate Report", MenuAction::BuildNetworkReport),
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
        "as" => "Settings",
        "asl" => "Logs",
        "asd" => "Discord",
        "asc" => "Config",
        "asdp" => "Display",
        "ap" => "Attack Pipelines",
        "ao" => "Obfuscation & Evasion",
        "aom" => "MAC Address",
        "aopp" => "Operating Mode",
        "aopst" => "Operations",
        "atx" => "TX Power",
        "enc" => "Encryption",
        "encusb" => "USB Settings",
        "encadv" => "Encryption: Advanced",
        _ => "Menu",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_display_menu_has_manual_rerun_actions() {
        let tree = MenuTree::new();
        let entries = tree.entries("asdp").expect("display menu entries");
        let actions: Vec<&MenuAction> = entries.iter().map(|entry| &entry.action).collect();

        assert!(actions
            .iter()
            .any(|action| matches!(action, MenuAction::RunDisplayDiscovery)));
        assert!(actions
            .iter()
            .any(|action| matches!(action, MenuAction::RunDisplayCalibration)));
        assert!(actions
            .iter()
            .any(|action| matches!(action, MenuAction::ResetDisplayCalibration)));
        assert!(actions
            .iter()
            .any(|action| matches!(action, MenuAction::ResetDisplayCache)));
    }

    #[test]
    fn colors_menu_exposes_all_theme_roles_and_preset_entry() {
        let tree = MenuTree::new();
        let entries = tree.entries("aea").expect("colors menu entries");

        for target in ColorTarget::ALL {
            assert!(entries.iter().any(|entry| {
                matches!(
                    entry.action,
                    MenuAction::SetColor(current) if current == target
                )
            }));
        }
        assert!(entries
            .iter()
            .any(|entry| matches!(entry.action, MenuAction::ApplyThemePreset)));
    }
}
