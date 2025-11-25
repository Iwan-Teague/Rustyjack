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
    AutopilotStart(AutopilotMode),
    AutopilotStop,
    AutopilotStatus,
    ToggleDiscord,
    TransferToUSB,
    HardwareDetect,
    CrackPasswords,
    DeauthAttack,
    ConnectKnownNetwork,
    /// Placeholder for informational entries (no action)
    ShowInfo,
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
        nodes.insert("ae", MenuNode::Static(options_menu));
        nodes.insert("aea", MenuNode::Static(colors_menu));
        nodes.insert("af", MenuNode::Static(system_menu));
        nodes.insert("ah", MenuNode::Static(loot_menu));
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
        MenuEntry::new(" Crack Passwords", MenuAction::CrackPasswords),
        MenuEntry::new(" View Dashboards", MenuAction::ViewDashboards),
        MenuEntry::new(" Autopilot", MenuAction::Submenu("ap")),
        MenuEntry::new(" Settings", MenuAction::Submenu("as")),
        MenuEntry::new(" Loot", MenuAction::Submenu("ah")),
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
        "ae" => "Options",
        "aea" => "Colors",
        "af" => "System",
        "ah" => "Loot",
        "ap" => "Autopilot",
        "as" => "Settings",
        _ => "Menu",
    }
}
