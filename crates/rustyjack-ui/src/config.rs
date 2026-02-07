use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
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
    pub display: DisplayConfig,
    #[serde(default)]
    pub paths: PathConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
    #[serde(skip)]
    pub theme_config_repaired: bool,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            pins: PinConfig::default(),
            colors: ColorScheme::default(),
            display: DisplayConfig::default(),
            paths: PathConfig::default(),
            settings: SettingsConfig::default(),
            theme_config_repaired: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThemeMutationResult {
    pub changed: bool,
    pub normalized: bool,
    pub saved: bool,
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
        let mut config_changed = false;
        if config.settings.normalize_active_interface() {
            config_changed = true;
        }
        if config.display.normalize() {
            config_changed = true;
        }

        let theme_result = config.mutate_theme_and_persist(&path, |_| {})?;
        config.theme_config_repaired = theme_result.normalized;

        if config_changed && !theme_result.saved {
            config.save(&path)?;
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating config directory {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        let mut tmp = path.to_path_buf();
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("gui_conf.json");
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_nanos())
            .unwrap_or(0);
        tmp.set_file_name(format!(".{filename}.tmp.{}.{}", process::id(), now_ns));

        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("creating temp config {}", tmp.display()))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("writing temp config {}", tmp.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("writing newline to temp config {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temp config {}", tmp.display()))?;
        drop(file);

        fs::rename(&tmp, path).with_context(|| {
            format!(
                "renaming temp config {} -> {}",
                tmp.display(),
                path.display()
            )
        })?;
        if let Some(parent) = path.parent() {
            if let Ok(dir_handle) = fs::File::open(parent) {
                let _ = dir_handle.sync_all();
            }
        }
        Ok(())
    }

    pub fn mutate_theme_and_persist<F>(
        &mut self,
        path: &Path,
        mutate: F,
    ) -> Result<ThemeMutationResult>
    where
        F: FnOnce(&mut ColorScheme),
    {
        let before = self.colors.clone();
        mutate(&mut self.colors);
        let normalized = self.colors.normalize();
        let changed = normalized || self.colors != before;
        if changed {
            self.save(path)?;
        }
        Ok(ThemeMutationResult {
            changed,
            normalized,
            saved: changed,
        })
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
    #[serde(default = "PinConfig::default_status_led")]
    pub status_led_pin: u32,
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
            status_led_pin: Self::default_status_led(),
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
    const fn default_status_led() -> u32 {
        23
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            toolbar: "#141414".into(),
        }
    }
}

impl ColorScheme {
    pub const DEFAULT_BACKGROUND: &'static str = "#000000";
    pub const DEFAULT_BORDER: &'static str = "#8800AA";
    pub const DEFAULT_TEXT: &'static str = "#AA00FF";
    pub const DEFAULT_SELECTED_TEXT: &'static str = "#CC44FF";
    pub const DEFAULT_SELECTED_BACKGROUND: &'static str = "#330055";
    pub const DEFAULT_TOOLBAR: &'static str = "#141414";

    fn default_background() -> String {
        Self::DEFAULT_BACKGROUND.to_string()
    }
    fn default_border() -> String {
        Self::DEFAULT_BORDER.to_string()
    }
    fn default_text() -> String {
        Self::DEFAULT_TEXT.to_string()
    }
    fn default_selected_text() -> String {
        Self::DEFAULT_SELECTED_TEXT.to_string()
    }
    fn default_selected_background() -> String {
        Self::DEFAULT_SELECTED_BACKGROUND.to_string()
    }
    fn default_toolbar() -> String {
        Self::DEFAULT_TOOLBAR.to_string()
    }

    pub fn normalize(&mut self) -> bool {
        let mut changed = false;
        changed |= normalize_hex_field(&mut self.background, Self::DEFAULT_BACKGROUND);
        changed |= normalize_hex_field(&mut self.border, Self::DEFAULT_BORDER);
        changed |= normalize_hex_field(&mut self.text, Self::DEFAULT_TEXT);
        changed |= normalize_hex_field(&mut self.selected_text, Self::DEFAULT_SELECTED_TEXT);
        changed |= normalize_hex_field(
            &mut self.selected_background,
            Self::DEFAULT_SELECTED_BACKGROUND,
        );
        changed |= normalize_hex_field(&mut self.toolbar, Self::DEFAULT_TOOLBAR);
        changed
    }

    pub fn contrast_warnings(&self, min_ratio: f32) -> Vec<String> {
        let checks = [
            (
                "Text/Background",
                self.text.as_str(),
                self.background.as_str(),
            ),
            ("Text/Toolbar", self.text.as_str(), self.toolbar.as_str()),
            (
                "Selected Text/BG",
                self.selected_text.as_str(),
                self.selected_background.as_str(),
            ),
        ];

        let mut warnings = Vec::new();
        for (label, fg, bg) in checks {
            if let Some(ratio) = contrast_ratio_hex(fg, bg) {
                if ratio < min_ratio {
                    warnings.push(format!("{label}: {ratio:.2}:1"));
                }
            }
        }
        warnings
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemePreset {
    DarkPurple,
    Light,
    HighContrast,
}

impl ThemePreset {
    pub const ALL: [Self; 3] = [Self::DarkPurple, Self::Light, Self::HighContrast];

    pub fn label(self) -> &'static str {
        match self {
            Self::DarkPurple => "Dark Purple",
            Self::Light => "Light",
            Self::HighContrast => "High Contrast",
        }
    }

    pub fn apply(self, colors: &mut ColorScheme) {
        match self {
            Self::DarkPurple => {
                colors.background = "#000000".to_string();
                colors.border = "#8800AA".to_string();
                colors.text = "#AA00FF".to_string();
                colors.selected_text = "#CC44FF".to_string();
                colors.selected_background = "#330055".to_string();
                colors.toolbar = "#141414".to_string();
            }
            Self::Light => {
                colors.background = "#F2F2F2".to_string();
                colors.border = "#2B2B2B".to_string();
                colors.text = "#111111".to_string();
                colors.selected_text = "#FFFFFF".to_string();
                colors.selected_background = "#005A9C".to_string();
                colors.toolbar = "#DADADA".to_string();
            }
            Self::HighContrast => {
                colors.background = "#000000".to_string();
                colors.border = "#FFFFFF".to_string();
                colors.text = "#FFFFFF".to_string();
                colors.selected_text = "#000000".to_string();
                colors.selected_background = "#FFFF00".to_string();
                colors.toolbar = "#000000".to_string();
            }
        }
    }
}

pub fn contrast_ratio_hex(fg_hex: &str, bg_hex: &str) -> Option<f32> {
    let (fr, fg, fb) = parse_hex_rgb(fg_hex)?;
    let (br, bg, bb) = parse_hex_rgb(bg_hex)?;
    let fg_l = relative_luminance(fr, fg, fb);
    let bg_l = relative_luminance(br, bg, bb);
    let (lighter, darker) = if fg_l >= bg_l {
        (fg_l, bg_l)
    } else {
        (bg_l, fg_l)
    };
    Some((lighter + 0.05) / (darker + 0.05))
}

pub fn parse_hex_rgb(input: &str) -> Option<(u8, u8, u8)> {
    let normalized = normalize_hex(input)?;
    let hex = normalized.trim_start_matches('#');
    let value = u32::from_str_radix(hex, 16).ok()?;
    let r = ((value >> 16) & 0xFF) as u8;
    let g = ((value >> 8) & 0xFF) as u8;
    let b = (value & 0xFF) as u8;
    Some((r, g, b))
}

fn relative_luminance(r: u8, g: u8, b: u8) -> f32 {
    let rr = linearized(r);
    let gg = linearized(g);
    let bb = linearized(b);
    0.2126 * rr + 0.7152 * gg + 0.0722 * bb
}

fn linearized(v: u8) -> f32 {
    let s = (v as f32) / 255.0;
    if s <= 0.03928 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

fn normalize_hex_field(field: &mut String, fallback: &str) -> bool {
    let normalized = normalize_hex(field).unwrap_or_else(|| fallback.to_string());
    if *field != normalized {
        *field = normalized;
        true
    } else {
        false
    }
}

fn normalize_hex(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let hex = trimmed.strip_prefix('#').unwrap_or(trimmed);
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("#{}", hex.to_ascii_uppercase()))
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
        PathBuf::from("/var/lib/rustyjack")
    }

    fn apply_defaults(&mut self) {
        if self.imagebrowser_start.as_os_str().is_empty() {
            self.imagebrowser_start = Self::default_image_path();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplayBackend {
    St7735,
    Framebuffer,
    Drm,
}

impl DisplayBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::St7735 => "st7735",
            Self::Framebuffer => "framebuffer",
            Self::Drm => "drm",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplayRotation {
    Landscape,
    Portrait,
}

impl DisplayRotation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Landscape => "landscape",
            Self::Portrait => "portrait",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplayGeometrySource {
    Override,
    Detected,
    Calibrated,
    Profile,
    Cached,
}

impl DisplayGeometrySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Detected => "detected",
            Self::Calibrated => "calibrated",
            Self::Profile => "profile",
            Self::Cached => "cached",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayConfig {
    #[serde(default)]
    pub backend_preference: Option<DisplayBackend>,
    #[serde(default)]
    pub rotation: Option<DisplayRotation>,
    #[serde(default)]
    pub width_override: Option<u32>,
    #[serde(default)]
    pub height_override: Option<u32>,
    #[serde(default)]
    pub offset_x: Option<i32>,
    #[serde(default)]
    pub offset_y: Option<i32>,
    #[serde(default = "DisplayConfig::default_safe_padding")]
    pub safe_padding_px: u32,

    #[serde(default)]
    pub calibrated_left: Option<i32>,
    #[serde(default)]
    pub calibrated_top: Option<i32>,
    #[serde(default)]
    pub calibrated_right: Option<i32>,
    #[serde(default)]
    pub calibrated_bottom: Option<i32>,
    #[serde(default = "DisplayConfig::default_calibration_version")]
    pub calibration_version: u32,
    #[serde(default)]
    pub last_calibrated_at: Option<String>,

    #[serde(default)]
    pub display_probe_completed: bool,
    #[serde(default)]
    pub display_calibration_completed: bool,
    #[serde(default)]
    pub display_geometry_source: Option<DisplayGeometrySource>,
    #[serde(default)]
    pub effective_width: Option<u32>,
    #[serde(default)]
    pub effective_height: Option<u32>,
    #[serde(default)]
    pub effective_offset_x: Option<i32>,
    #[serde(default)]
    pub effective_offset_y: Option<i32>,
    #[serde(default)]
    pub effective_backend: Option<DisplayBackend>,
    #[serde(default)]
    pub effective_rotation: Option<DisplayRotation>,
    #[serde(default)]
    pub display_profile_fingerprint: Option<String>,
    #[serde(default = "DisplayConfig::default_tests_version")]
    pub display_tests_version: u32,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            backend_preference: None,
            rotation: None,
            width_override: None,
            height_override: None,
            offset_x: None,
            offset_y: None,
            safe_padding_px: Self::default_safe_padding(),
            calibrated_left: None,
            calibrated_top: None,
            calibrated_right: None,
            calibrated_bottom: None,
            calibration_version: Self::default_calibration_version(),
            last_calibrated_at: None,
            display_probe_completed: false,
            display_calibration_completed: false,
            display_geometry_source: None,
            effective_width: None,
            effective_height: None,
            effective_offset_x: None,
            effective_offset_y: None,
            effective_backend: None,
            effective_rotation: None,
            display_profile_fingerprint: None,
            display_tests_version: Self::default_tests_version(),
        }
    }
}

impl DisplayConfig {
    const fn default_safe_padding() -> u32 {
        0
    }

    const fn default_calibration_version() -> u32 {
        1
    }

    const fn default_tests_version() -> u32 {
        1
    }

    pub fn normalize(&mut self) -> bool {
        let mut changed = false;

        if self.safe_padding_px > 32 {
            self.safe_padding_px = 32;
            changed = true;
        }

        if self.width_override == Some(0) {
            self.width_override = None;
            changed = true;
        }
        if self.height_override == Some(0) {
            self.height_override = None;
            changed = true;
        }

        if self.display_tests_version == 0 {
            self.display_tests_version = Self::default_tests_version();
            changed = true;
        }
        if self.calibration_version == 0 {
            self.calibration_version = Self::default_calibration_version();
            changed = true;
        }

        if self.has_calibration_edges() && !self.display_calibration_completed {
            self.display_calibration_completed = true;
            changed = true;
        }

        changed
    }

    pub fn has_calibration_edges(&self) -> bool {
        self.calibrated_left.is_some()
            && self.calibrated_top.is_some()
            && self.calibrated_right.is_some()
            && self.calibrated_bottom.is_some()
    }

    pub fn clear_calibration(&mut self) {
        self.calibrated_left = None;
        self.calibrated_top = None;
        self.calibrated_right = None;
        self.calibrated_bottom = None;
        self.last_calibrated_at = None;
        self.display_calibration_completed = false;
        self.display_geometry_source = None;
    }

    pub fn clear_cache(&mut self) {
        self.display_probe_completed = false;
        self.display_calibration_completed = false;
        self.display_geometry_source = None;
        self.effective_width = None;
        self.effective_height = None;
        self.effective_offset_x = None;
        self.effective_offset_y = None;
        self.effective_backend = None;
        self.effective_rotation = None;
        self.display_profile_fingerprint = None;
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
    /// Hotspot channel (2.4 GHz)
    #[serde(default = "SettingsConfig::default_hotspot_channel")]
    pub hotspot_channel: u8,
    /// Restore NetworkManager management on hotspot stop
    #[serde(default)]
    pub hotspot_restore_nm: bool,
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
            hotspot_channel: Self::default_hotspot_channel(),
            hotspot_restore_nm: false,
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
        "eth0".to_string()
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

    fn default_hotspot_channel() -> u8 {
        6
    }
}

impl SettingsConfig {
    fn normalize_active_interface(&mut self) -> bool {
        let iface = self.active_network_interface.trim();
        let needs_default =
            iface.is_empty() || iface.eq_ignore_ascii_case("auto") || !interface_exists(iface);
        if needs_default {
            let preferred = if interface_exists("eth0") {
                "eth0".to_string()
            } else if interface_exists("wlan0") {
                "wlan0".to_string()
            } else if interface_exists("wlan1") {
                "wlan1".to_string()
            } else {
                first_non_loopback_interface()
                    .unwrap_or_else(|| self.active_network_interface.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn display_config_clear_calibration_resets_edges() {
        let mut cfg = DisplayConfig {
            calibrated_left: Some(1),
            calibrated_top: Some(2),
            calibrated_right: Some(120),
            calibrated_bottom: Some(121),
            display_calibration_completed: true,
            ..DisplayConfig::default()
        };
        cfg.clear_calibration();
        assert!(!cfg.has_calibration_edges());
        assert!(!cfg.display_calibration_completed);
    }

    #[test]
    fn display_config_clear_cache_resets_effective_geometry() {
        let mut cfg = DisplayConfig {
            display_probe_completed: true,
            display_calibration_completed: true,
            effective_width: Some(128),
            effective_height: Some(128),
            effective_offset_x: Some(2),
            effective_offset_y: Some(1),
            display_profile_fingerprint: Some("fp".to_string()),
            ..DisplayConfig::default()
        };
        cfg.clear_cache();
        assert!(!cfg.display_probe_completed);
        assert_eq!(cfg.effective_width, None);
        assert_eq!(cfg.effective_height, None);
        assert_eq!(cfg.display_profile_fingerprint, None);
    }

    #[test]
    fn display_config_round_trip_persists_fields() {
        let mut gui = GuiConfig::default();
        gui.display.display_probe_completed = true;
        gui.display.display_calibration_completed = true;
        gui.display.calibrated_left = Some(0);
        gui.display.calibrated_top = Some(0);
        gui.display.calibrated_right = Some(127);
        gui.display.calibrated_bottom = Some(127);
        gui.display.effective_width = Some(128);
        gui.display.effective_height = Some(128);
        gui.display.display_profile_fingerprint = Some("st7735:128x128:test".to_string());

        let json = serde_json::to_string(&gui).expect("serialize gui config");
        let decoded: GuiConfig = serde_json::from_str(&json).expect("deserialize gui config");
        assert!(decoded.display.display_probe_completed);
        assert!(decoded.display.display_calibration_completed);
        assert_eq!(decoded.display.effective_width, Some(128));
        assert_eq!(decoded.display.calibrated_right, Some(127));
    }

    #[test]
    fn color_scheme_normalize_repairs_invalid_values() {
        let mut scheme = ColorScheme {
            background: " 112233 ".to_string(),
            border: "#12".to_string(),
            text: "gggggg".to_string(),
            selected_text: "#abcdef".to_string(),
            selected_background: "#12345g".to_string(),
            toolbar: "445566".to_string(),
        };

        assert!(scheme.normalize());
        assert_eq!(scheme.background, "#112233");
        assert_eq!(scheme.border, ColorScheme::DEFAULT_BORDER);
        assert_eq!(scheme.text, ColorScheme::DEFAULT_TEXT);
        assert_eq!(scheme.selected_text, "#ABCDEF");
        assert_eq!(
            scheme.selected_background,
            ColorScheme::DEFAULT_SELECTED_BACKGROUND
        );
        assert_eq!(scheme.toolbar, "#445566");
    }

    #[test]
    fn contrast_ratio_hex_reports_expected_ordering() {
        let high = contrast_ratio_hex("#FFFFFF", "#000000").expect("valid contrast");
        let low = contrast_ratio_hex("#222222", "#111111").expect("valid contrast");
        assert!(high > 10.0);
        assert!(low < 2.0);
    }

    #[test]
    fn mutate_theme_and_persist_saves_normalized_colors() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "rustyjack-ui-theme-save-test-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temp root");
        let config_path = root.join("gui_conf.json");

        let mut config = GuiConfig::default();
        let result = config
            .mutate_theme_and_persist(&config_path, |colors| {
                colors.background = " aa00ff ".to_string();
            })
            .expect("theme mutate + persist");
        assert!(result.changed);
        assert!(result.normalized);
        assert!(result.saved);
        assert_eq!(config.colors.background, "#AA00FF");

        let saved = fs::read_to_string(&config_path).expect("read saved config");
        assert!(saved.contains("\"background\": \"#AA00FF\""));

        let _ = fs::remove_file(&config_path);
        let _ = fs::remove_dir_all(&root);
    }
}
