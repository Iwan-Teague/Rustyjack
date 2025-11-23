use std::collections::HashMap;

use anyhow::{Result, anyhow};

#[derive(Clone)]
pub enum MenuAction {
    Submenu(&'static str),
    Scan(&'static ScanProfile),
    ReverseDefault,
    ReverseCustom,
    ResponderOn,
    ResponderOff,
    MitmStart,
    MitmStop,
    DnsStart,
    DnsStop,
    SpoofSite(&'static str),
    ShowInfo,
    RefreshConfig,
    SaveConfig,
    SetColor(ColorTarget),
    RestartSystem,
    Loot(LootSection),
    QuickWifiToggle,
    SwitchInterfaceMenu,
    ShowInterfaceInfo,
    ShowNetworkHealth,
    ShowRoutingStatus,
    SwitchToWifi,
    SwitchToEthernet,
    WifiManager,
    BridgeStart,
    BridgeStop,
    DiscordUpload,
    SystemUpdate,
    ViewDashboards,
    AutopilotStart(AutopilotMode),
    AutopilotStop,
    AutopilotStatus,
    ToggleDiscord,
}

#[derive(Clone, Copy, Debug)]
pub enum AutopilotMode {
    Standard,
    Aggressive,
    Stealth,
    Harvest,
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
        nodes.insert("ab", MenuNode::Static(scan_menu));
        nodes.insert("ac", MenuNode::Static(reverse_menu));
        nodes.insert("ad", MenuNode::Static(responder_menu));
        nodes.insert("ai", MenuNode::Static(mitm_menu));
        nodes.insert("aj", MenuNode::Static(dns_menu));
        nodes.insert("ak", MenuNode::Static(site_menu));
        nodes.insert("ae", MenuNode::Static(options_menu));
        nodes.insert("aea", MenuNode::Static(colors_menu));
        nodes.insert("af", MenuNode::Static(system_menu));
        nodes.insert("ah", MenuNode::Static(loot_menu));
        nodes.insert("aw", MenuNode::Static(wifi_menu));
        nodes.insert("awr", MenuNode::Static(route_menu));
        nodes.insert("abg", MenuNode::Static(bridge_menu));
        nodes.insert("ap", MenuNode::Static(autopilot_menu));
        nodes.insert("as", MenuNode::Static(settings_menu));
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

#[derive(Clone)]
pub struct ScanProfile {
    pub label: &'static str,
    pub args: &'static [&'static str],
}

pub const SCAN_PROFILES: &[ScanProfile] = &[
    ScanProfile {
        label: "Quick Scan",
        args: &["-T5"],
    },
    ScanProfile {
        label: "Full Port Scan",
        args: &["-p-"],
    },
    ScanProfile {
        label: "Service Scan",
        args: &["-T5", "-sV"],
    },
    ScanProfile {
        label: "Vulnerability",
        args: &["-T5", "-sV", "--script", "vuln"],
    },
    ScanProfile {
        label: "Full Vulns",
        args: &["-p-", "-sV", "--script", "vuln"],
    },
    ScanProfile {
        label: "OS Scan",
        args: &["-T5", "-A"],
    },
    ScanProfile {
        label: "Intensive Scan",
        args: &["-O", "-p-", "--script", "vuln"],
    },
    ScanProfile {
        label: "Stealth SYN Scan",
        args: &["-sS", "-T4"],
    },
    ScanProfile {
        label: "UDP Scan",
        args: &["-sU", "-T4"],
    },
    ScanProfile {
        label: "Ping Sweep",
        args: &["-sn"],
    },
    ScanProfile {
        label: "Top100 Scan",
        args: &["--top-ports", "100", "-T4"],
    },
    ScanProfile {
        label: "HTTP Enumeration",
        args: &[
            "-p",
            "80,81,443,8080,8443",
            "-sV",
            "--script",
            "http-enum,http-title",
        ],
    },
];

const SPOOF_SITES: &[&str] = &[
    "microsoft",
    "wordpress",
    "instagram",
    "google",
    "amazon",
    "apple",
    "twitter",
    "netflix",
    "spotify",
    "paypal",
    "linkedin",
    "snapchat",
    "pinterest",
    "yahoo",
    "steam",
    "adobe",
    "badoo",
    "icloud",
    "instafollowers",
    "ldlc",
    "origin",
    "playstation",
    "protonmail",
    "shopping",
    "wifi",
    "yandex",
];

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
    Nmap,
    Responder,
    DnsSpoof,
}

fn main_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" View Dashboards", MenuAction::ViewDashboards),
        MenuEntry::new(" Autopilot", MenuAction::Submenu("ap")),
        MenuEntry::new(" Scan Nmap", MenuAction::Submenu("ab")),
        MenuEntry::new(" Reverse Shell", MenuAction::Submenu("ac")),
        MenuEntry::new(" Responder", MenuAction::Submenu("ad")),
        MenuEntry::new(" MITM & Sniff", MenuAction::Submenu("ai")),
        MenuEntry::new(" DNS Spoofing", MenuAction::Submenu("aj")),
        MenuEntry::new(" Network info", MenuAction::ShowInfo),
        MenuEntry::new(" WiFi Manager", MenuAction::Submenu("aw")),
        MenuEntry::new(" Settings", MenuAction::Submenu("as")),
        MenuEntry::new(" Loot", MenuAction::Submenu("ah")),
        MenuEntry::new(" Bridge mode", MenuAction::Submenu("abg")),
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

fn scan_menu() -> Vec<MenuEntry> {
    SCAN_PROFILES
        .iter()
        .map(|profile| MenuEntry::new(profile.label, MenuAction::Scan(profile)))
        .collect()
}

fn reverse_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Defaut Reverse", MenuAction::ReverseDefault),
        MenuEntry::new(" Remote Reverse", MenuAction::ReverseCustom),
    ]
}

fn responder_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Responder ON", MenuAction::ResponderOn),
        MenuEntry::new(" Responder OFF", MenuAction::ResponderOff),
    ]
}

fn mitm_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Start MITM & Sniff", MenuAction::MitmStart),
        MenuEntry::new(" Stop MITM & Sniff", MenuAction::MitmStop),
    ]
}

fn dns_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Start DNSSpoofing", MenuAction::DnsStart),
        MenuEntry::new(" Select site", MenuAction::Submenu("ak")),
        MenuEntry::new(" Stop DNS&PHP", MenuAction::DnsStop),
    ]
}

fn site_menu() -> Vec<MenuEntry> {
    SPOOF_SITES
        .iter()
        .map(|site| MenuEntry::new(site, MenuAction::SpoofSite(site)))
        .collect()
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
        MenuEntry::new(" Nmap", MenuAction::Loot(LootSection::Nmap)),
        MenuEntry::new(" Responder", MenuAction::Loot(LootSection::Responder)),
        MenuEntry::new(" DNSSpoof", MenuAction::Loot(LootSection::DnsSpoof)),
    ]
}

fn wifi_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" FAST WiFi Switcher", MenuAction::WifiManager),
        MenuEntry::new(" INSTANT Toggle 0↔1", MenuAction::QuickWifiToggle),
        MenuEntry::new(" Switch Interface", MenuAction::SwitchInterfaceMenu),
        MenuEntry::new(" Show Interface Info", MenuAction::ShowInterfaceInfo),
        MenuEntry::new(" Network Health", MenuAction::ShowNetworkHealth),
        MenuEntry::new(" Route Control", MenuAction::Submenu("awr")),
    ]
}

fn route_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Show Routing Status", MenuAction::ShowRoutingStatus),
        MenuEntry::new(" Switch to WiFi", MenuAction::SwitchToWifi),
        MenuEntry::new(" Switch to Ethernet", MenuAction::SwitchToEthernet),
    ]
}

fn bridge_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Start transparent bridge", MenuAction::BridgeStart),
        MenuEntry::new(" Stop transparent bridge", MenuAction::BridgeStop),
    ]
}

fn autopilot_menu() -> Vec<MenuEntry> {
    vec![
        MenuEntry::new(" Standard Mode", MenuAction::AutopilotStart(AutopilotMode::Standard)),
        MenuEntry::new(" Aggressive Mode", MenuAction::AutopilotStart(AutopilotMode::Aggressive)),
        MenuEntry::new(" Stealth Mode", MenuAction::AutopilotStart(AutopilotMode::Stealth)),
        MenuEntry::new(" Harvest Mode", MenuAction::AutopilotStart(AutopilotMode::Harvest)),
        MenuEntry::new(" Stop Autopilot", MenuAction::AutopilotStop),
        MenuEntry::new(" View Status", MenuAction::AutopilotStatus),
    ]
}

pub fn menu_title(id: &str) -> &'static str {
    match id {
        "a" => "Main Menu",
        "ab" => "Nmap Profiles",
        "ac" => "Reverse Shell",
        "ad" => "Responder",
        "ai" => "MITM",
        "aj" => "DNS Spoofing",
        "ak" => "Spoof Site",
        "ae" => "Options",
        "aea" => "Colors",
        "af" => "System",
        "ah" => "Loot",
        "aw" => "Wi-Fi",
        "awr" => "Routing",
        "abg" => "Bridge",
        "ap" => "Autopilot",
        "as" => "Settings",
        _ => "Menu",
    }
}
