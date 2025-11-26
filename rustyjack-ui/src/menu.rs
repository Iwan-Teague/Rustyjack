use std::collections::HashMap;

use anyhow::{Result, anyhow};

#[derive(Clone)]
pub enum MenuAction {
    Submenu(&'static str),
    RefreshConfig,
    SaveConfig,
    SetColor(ColorTarget),
    RestartSystem,
    Loot(LootSection),
    DiscordUpload,
    SystemUpdate,
    ViewDashboards,
    ToggleDiscord,
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
    /// Attack pipelines - automated sequences
    AttackPipeline(PipelineType),
    /// Stealth settings submenu
    StealthSettings,
    /// Randomize MAC address
    RandomizeMac,
    /// Restore original MAC
    RestoreMac,
    /// Set TX power
    SetTxPower(TxPowerSetting),
    /// Placeholder for informational entries (no action)
    ShowInfo,
}

/// Pipeline types for automated attacks
#[derive(Clone, Copy)]
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
        nodes.insert("ae", MenuNode::Static(options_menu));
        nodes.insert("aea", MenuNode::Static(colors_menu));
        nodes.insert("af", MenuNode::Static(system_menu));
        nodes.insert("ah", MenuNode::Static(loot_menu));
        nodes.insert("aw", MenuNode::Static(wifi_menu));
        nodes.insert("as", MenuNode::Static(settings_menu));
        nodes.insert("ap", MenuNode::Static(pipeline_menu));
        nodes.insert("ast", MenuNode::Static(stealth_menu));
        nodes.insert("atx", MenuNode::Static(tx_power_menu));
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
    Border,
    Text,
    SelectedText,
    SelectedBackground,
}

#[derive(Clone, Copy)]
pub enum LootSection {
    Wireless,
}

fn main_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Hardware Detect", MenuAction::HardwareDetect),
        MenuEntry::new(" Install WiFi Drivers", MenuAction::InstallWifiDrivers),
        MenuEntry::new(" WiFi Attacks", MenuAction::Submenu("aw")),
        MenuEntry::new(" View Dashboards", MenuAction::ViewDashboards),
        MenuEntry::new(" Settings", MenuAction::Submenu("as")),
        MenuEntry::new(" Loot", MenuAction::Submenu("ah")),
    ]
}

fn wifi_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Scan Networks", MenuAction::ScanNetworks),
        MenuEntry::new(" Attack Pipelines", MenuAction::Submenu("ap")),
        MenuEntry::new(" Deauth Attack", MenuAction::DeauthAttack),
        MenuEntry::new(" Evil Twin AP", MenuAction::EvilTwinAttack),
        MenuEntry::new(" Karma Attack", MenuAction::KarmaAttack),
        MenuEntry::new(" PMKID Capture", MenuAction::PmkidCapture),
        MenuEntry::new(" Probe Sniff", MenuAction::ProbeSniff),
        MenuEntry::new(" Crack Handshake", MenuAction::CrackHandshake),
        MenuEntry::new(" Stealth Options", MenuAction::Submenu("ast")),
        MenuEntry::new(" Connect Network", MenuAction::ConnectKnownNetwork),
    ]
}

fn pipeline_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Get WiFi Password", MenuAction::AttackPipeline(PipelineType::GetPassword)),
        MenuEntry::new(" Mass Capture", MenuAction::AttackPipeline(PipelineType::MassCapture)),
        MenuEntry::new(" Stealth Recon", MenuAction::AttackPipeline(PipelineType::StealthRecon)),
        MenuEntry::new(" Harvest Creds", MenuAction::AttackPipeline(PipelineType::CredentialHarvest)),
        MenuEntry::new(" Full Pentest", MenuAction::AttackPipeline(PipelineType::FullPentest)),
    ]
}

fn stealth_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Randomize MAC", MenuAction::RandomizeMac),
        MenuEntry::new(" Restore MAC", MenuAction::RestoreMac),
        MenuEntry::new(" TX Power", MenuAction::Submenu("atx")),
    ]
}

fn tx_power_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Stealth (1 dBm)", MenuAction::SetTxPower(TxPowerSetting::Stealth)),
        MenuEntry::new(" Low (5 dBm)", MenuAction::SetTxPower(TxPowerSetting::Low)),
        MenuEntry::new(" Medium (12 dBm)", MenuAction::SetTxPower(TxPowerSetting::Medium)),
        MenuEntry::new(" High (18 dBm)", MenuAction::SetTxPower(TxPowerSetting::High)),
        MenuEntry::new(" Maximum", MenuAction::SetTxPower(TxPowerSetting::Maximum)),
    ]
}

fn settings_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Toggle Discord", MenuAction::ToggleDiscord),
        MenuEntry::new(" Upload loot Discord", MenuAction::DiscordUpload),
        MenuEntry::new(" Options", MenuAction::Submenu("ae")),
        MenuEntry::new(" System", MenuAction::Submenu("af")),
    ]
}

fn options_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Colors", MenuAction::Submenu("aea")),
        MenuEntry::new(" Refresh config", MenuAction::RefreshConfig),
        MenuEntry::new(" Save config!", MenuAction::SaveConfig),
    ]
}

fn colors_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Background", MenuAction::SetColor(ColorTarget::Background)),
        MenuEntry::new(" Text", MenuAction::SetColor(ColorTarget::Text)),
        MenuEntry::new(
            " Selected text",
            MenuAction::SetColor(ColorTarget::SelectedText),
        ),
        MenuEntry::new(
            " Selected background",
            MenuAction::SetColor(ColorTarget::SelectedBackground),
        ),
        MenuEntry::new(" Border", MenuAction::SetColor(ColorTarget::Border)),
    ]
}

fn system_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Restart", MenuAction::RestartSystem),
        MenuEntry::new(" Update from git", MenuAction::SystemUpdate),
    ]
}

fn loot_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Transfer to USB", MenuAction::TransferToUSB),
        MenuEntry::new(" Wireless Captures", MenuAction::Loot(LootSection::Wireless)),
    ]
}

pub fn menu_title(id: &str) -> &'static str {
    match id {
        "a" => "Main Menu",
        "ae" => "Options",
        "aea" => "Colors",
        "af" => "System",
        "ah" => "Loot",
        "aw" => "WiFi Attacks",
        "as" => "Settings",
        "ap" => "Attack Pipelines",
        "ast" => "Stealth Options",
        "atx" => "TX Power",
        _ => "Menu",
    }
}
