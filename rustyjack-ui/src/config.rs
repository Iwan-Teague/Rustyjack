use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            background: "#000000".into(),
            border: "#00AA00".into(),
            text: "#00CC00".into(),
            selected_text: "#00DD33".into(),
            selected_background: "#1A0AAA".into(),
            gamepad: "#0A0A66".into(),
            gamepad_fill: "#AAAAAA".into(),
        }
    }
}

impl ColorScheme {
    fn default_background() -> String {
        "#000000".to_string()
    }
    fn default_border() -> String {
        "#00AA00".to_string()
    }
    fn default_text() -> String {
        "#00CC00".to_string()
    }
    fn default_selected_text() -> String {
        "#00DD33".to_string()
    }
    fn default_selected_background() -> String {
        "#1A0AAA".to_string()
    }
    fn default_gamepad() -> String {
        "#0A0A66".to_string()
    }
    fn default_gamepad_fill() -> String {
        "#AAAAAA".to_string()
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
    #[serde(default)]
    pub target_bssid: String,
    #[serde(default)]
    pub target_channel: u8,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            discord_enabled: Self::default_discord_enabled(),
            active_network_interface: Self::default_active_interface(),
            target_network: Self::default_target_network(),
            target_bssid: String::new(),
            target_channel: 0,
        }
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
}
