use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlacklistedDevice {
    pub mac: String,
    pub name: String,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    #[serde(default)]
    pub pins: PinConfig,
    #[serde(default)]
    pub colors: ColorScheme,
    #[serde(default)]
    pub paths: PathConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            pins: PinConfig::default(),
            colors: ColorScheme::default(),
            paths: PathConfig::default(),
            settings: SettingsConfig::default(),
        }
    }
}

impl GuiConfig {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("gui_conf.json");
        if !path.exists() {
            let default = GuiConfig::default();
            default.save(&path)?;
            return Ok(default);
        }

        let contents =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: GuiConfig = serde_json::from_str(&contents)
            .with_context(|| format!("parsing {}", path.display()))?;
        config.paths.apply_defaults();
        if config.settings.normalize_active_interface() {
            config.save(&path)?;
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("writing {}", path.display()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinConfig {
    #[serde(default = "PinConfig::default_key_up")]
    pub key_up_pin: u32,
    #[serde(default = "PinConfig::default_key_down")]
    pub key_down_pin: u32,
    #[serde(default = "PinConfig::default_key_left")]
    pub key_left_pin: u32,
    #[serde(default = "PinConfig::default_key_right")]
    pub key_right_pin: u32,
    #[serde(default = "PinConfig::default_key_press")]
    pub key_press_pin: u32,
    #[serde(default = "PinConfig::default_key1")]
    pub key1_pin: u32,
    #[serde(default = "PinConfig::default_key2")]
    pub key2_pin: u32,
    #[serde(default = "PinConfig::default_key3")]
    pub key3_pin: u32,
}

impl Default for PinConfig {
    fn default() -> Self {
        Self {
            key_up_pin: Self::default_key_up(),
            key_down_pin: Self::default_key_down(),
            key_left_pin: Self::default_key_left(),
            key_right_pin: Self::default_key_right(),
            key_press_pin: Self::default_key_press(),
            key1_pin: Self::default_key1(),
            key2_pin: Self::default_key2(),
            key3_pin: Self::default_key3(),
        }
    }
}

impl PinConfig {
    const fn default_key_up() -> u32 {
        6
    }
    const fn default_key_down() -> u32 {
        19
    }
    const fn default_key_left() -> u32 {
        5
    }
    const fn default_key_right() -> u32 {
        26
    }
    const fn default_key_press() -> u32 {
        13
    }
    const fn default_key1() -> u32 {
        21
    }
    const fn default_key2() -> u32 {
        20
    }
    const fn default_key3() -> u32 {
        16
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    #[serde(default = "ColorScheme::default_background")]
    pub background: String,
    #[serde(default = "ColorScheme::default_border")]
    pub border: String,
    #[serde(default = "ColorScheme::default_text")]
    pub text: String,
    #[serde(default = "ColorScheme::default_selected_text")]
    pub selected_text: String,
    #[serde(default = "ColorScheme::default_selected_background")]
    pub selected_background: String,
    #[serde(default = "ColorScheme::default_gamepad")]
    pub gamepad: String,
    #[serde(default = "ColorScheme::default_gamepad_fill")]
    pub gamepad_fill: String,
    #[serde(default = "ColorScheme::default_toolbar")]
    pub toolbar: String,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            background: "#000000".into(),
            border: "#8800AA".into(),
            text: "#AA00FF".into(),
            selected_text: "#CC44FF".into(),
            selected_background: "#330055".into(),
            gamepad: "#440066".into(),
            gamepad_fill: "#AA00FF".into(),
            toolbar: "#141414".into(),
        }
    }
}

impl ColorScheme {
    fn default_background() -> String {
        "#000000".to_string()
    }
    fn default_border() -> String {
        "#8800AA".to_string()
    }
    fn default_text() -> String {
        "#AA00FF".to_string()
    }
    fn default_selected_text() -> String {
        "#CC44FF".to_string()
    }
    fn default_selected_background() -> String {
        "#330055".to_string()
    }
    fn default_gamepad() -> String {
        "#440066".to_string()
    }
    fn default_gamepad_fill() -> String {
        "#AA00FF".to_string()
    }
    fn default_toolbar() -> String {
        "#141414".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    #[serde(default = "PathConfig::default_image_path")]
    pub imagebrowser_start: PathBuf,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            imagebrowser_start: PathConfig::default_image_path(),
        }
    }
}

impl PathConfig {
    fn default_image_path() -> PathBuf {
        PathBuf::from("/root")
    }

    fn apply_defaults(&mut self) {
        if self.imagebrowser_start.as_os_str().is_empty() {
            self.imagebrowser_start = Self::default_image_path();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsConfig {
    #[serde(default = "SettingsConfig::default_discord_enabled")]
    pub discord_enabled: bool,
    #[serde(default = "SettingsConfig::default_active_interface")]
    pub active_network_interface: String,
    #[serde(default = "SettingsConfig::default_target_network")]
    pub target_network: String,
    #[serde(default = "SettingsConfig::default_logs_enabled")]
    pub logs_enabled: bool,
    #[serde(default)]
    pub target_bssid: String,
    #[serde(default)]
    pub target_channel: u8,
    /// Master encryption toggle
    #[serde(default)]
    pub encryption_enabled: bool,
    /// Encrypt discord webhook file
    #[serde(default)]
    pub encrypt_discord_webhook: bool,
    /// Encrypt loot files
    #[serde(default)]
    pub encrypt_loot: bool,
    /// Encrypt saved Wi-Fi profiles
    #[serde(default)]
    pub encrypt_wifi_profiles: bool,
    /// Default path to encryption key file (for USB lookup)
    #[serde(default)]
    pub encryption_key_path: String,
    /// Auto-randomize MAC before attacks
    #[serde(default)]
    pub mac_randomization_enabled: bool,
    /// Use a stable randomized MAC per network
    #[serde(default)]
    pub per_network_mac_enabled: bool,
    /// SSIDs or interfaces that should never be randomized
    #[serde(default)]
    pub mac_randomization_exceptions: Vec<String>,
    /// Lifetime in seconds for stable MAC rotation (0 = no rotation)
    #[serde(default)]
    pub mac_randomization_lifetime_secs: Option<u64>,
    /// Stored per-network MACs (interface -> SSID -> MAC)
    #[serde(default)]
    pub per_network_macs: HashMap<String, HashMap<String, String>>,
    /// Per-interface original MAC addresses (saved when randomized)
    #[serde(default)]
    pub original_macs: HashMap<String, String>,
    /// Per-interface current MAC addresses
    #[serde(default)]
    pub current_macs: HashMap<String, String>,
    /// Auto-randomize hostname before attacks
    #[serde(default)]
    pub hostname_randomization_enabled: bool,
    /// Current operation mode: stealth/default/aggressive/custom
    #[serde(default = "SettingsConfig::default_operation_mode")]
    pub operation_mode: String,
    /// TX power level setting (stealth/low/medium/high/max)
    #[serde(default = "SettingsConfig::default_tx_power")]
    pub tx_power_level: String,
    /// Passive mode - no transmissions during recon
    #[serde(default)]
    pub passive_mode_enabled: bool,
    /// Hotspot SSID
    #[serde(default = "SettingsConfig::default_hotspot_ssid")]
    pub hotspot_ssid: String,
    /// Hotspot password
    #[serde(default = "SettingsConfig::default_hotspot_password")]
    pub hotspot_password: String,
    /// Hotspot device blacklist (MAC addresses with metadata)
    #[serde(default)]
    pub hotspot_blacklist: Vec<BlacklistedDevice>,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            discord_enabled: Self::default_discord_enabled(),
            active_network_interface: Self::default_active_interface(),
            target_network: Self::default_target_network(),
            logs_enabled: Self::default_logs_enabled(),
            target_bssid: String::new(),
            target_channel: 0,
            encryption_enabled: false,
            encrypt_discord_webhook: false,
            encrypt_loot: false,
            encrypt_wifi_profiles: false,
            encryption_key_path: String::new(),
            mac_randomization_enabled: false,
            per_network_mac_enabled: false,
            mac_randomization_exceptions: Vec::new(),
            mac_randomization_lifetime_secs: None,
            per_network_macs: HashMap::new(),
            original_macs: HashMap::new(),
            current_macs: HashMap::new(),
            hostname_randomization_enabled: false,
            operation_mode: Self::default_operation_mode(),
            tx_power_level: Self::default_tx_power(),
            passive_mode_enabled: false,
            hotspot_ssid: Self::default_hotspot_ssid(),
            hotspot_password: Self::default_hotspot_password(),
            hotspot_blacklist: Vec::new(),
        }
    }
}

impl BlacklistedDevice {
    pub fn new(mac: String, name: String, ip: String) -> Self {
        Self { mac, name, ip }
    }
}

impl SettingsConfig {
    fn default_discord_enabled() -> bool {
        true
    }

    fn default_active_interface() -> String {
        "wlan0".to_string()
    }

    fn default_target_network() -> String {
        String::new()
    }

    fn default_logs_enabled() -> bool {
        true
    }

    fn default_operation_mode() -> String {
        "default".to_string()
    }

    fn default_tx_power() -> String {
        "high".to_string()
    }

    fn default_hotspot_ssid() -> String {
        "rustyjack".to_string()
    }

    fn default_hotspot_password() -> String {
        "rustyjack".to_string()
    }
}

impl SettingsConfig {
    fn normalize_active_interface(&mut self) -> bool {
        let iface = self.active_network_interface.trim();
        let needs_default =
            iface.is_empty() || iface.eq_ignore_ascii_case("auto") || !interface_exists(iface);
        if needs_default {
            let preferred = if interface_exists("wlan0") {
                "wlan0".to_string()
            } else if interface_exists("wlan1") {
                "wlan1".to_string()
            } else if interface_exists("eth0") {
                "eth0".to_string()
            } else {
                first_non_loopback_interface().unwrap_or_else(|| self.active_network_interface.clone())
            };
            if preferred != self.active_network_interface {
                self.active_network_interface = preferred;
                return true;
            }
        }
        false
    }
}

fn interface_exists(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    Path::new("/sys/class/net").join(name).exists()
}

fn first_non_loopback_interface() -> Option<String> {
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "lo" {
            return Some(name);
        }
    }
    None
}
