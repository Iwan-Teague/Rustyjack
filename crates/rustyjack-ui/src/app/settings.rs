use std::{env, fs};

use anyhow::{bail, Context, Result};

use rustyjack_commands::{Commands, DiscordCommand, DiscordSendArgs, NotifyCommand};
use rustyjack_encryption::clear_encryption_key;
use zeroize::Zeroize;

use crate::{
    config::{GuiConfig, ThemePreset},
    display::CalibrationEdge,
    input::Button,
    menu::{ColorTarget, TxPowerSetting},
    util::shorten_for_display,
};

use super::state::App;

const THEME_MIN_CONTRAST_RATIO: f32 = 4.5;
const COLOR_CHOICES: [(&str, &str); 10] = [
    ("White", "#FFFFFF"),
    ("Black", "#000000"),
    ("Green", "#00FF00"),
    ("Red", "#FF0000"),
    ("Blue", "#0000FF"),
    ("Navy", "#000080"),
    ("Purple", "#AA00FF"),
    ("Amber", "#FFBF00"),
    ("Cyan", "#00FFFF"),
    ("Gray", "#808080"),
];

struct ThemeUpdateStatus {
    normalized: bool,
    save_error: Option<String>,
    contrast_warnings: Vec<String>,
}

impl App {
    pub(crate) fn reload_config(&mut self) -> Result<()> {
        self.config = GuiConfig::load(&self.root)?;
        self.display.update_palette(&self.config.colors);
        if self.config.theme_config_repaired {
            self.show_message("Config", ["Reloaded", "Theme config repaired"])
        } else {
            self.show_message("Config", ["Reloaded"])
        }
    }

    pub(crate) fn save_config(&mut self) -> Result<()> {
        self.config.save(&self.root.join("gui_conf.json"))?;
        self.show_message("Config", ["Saved"])
    }

    pub(crate) fn pick_color(&mut self, target: ColorTarget) -> Result<()> {
        let labels: Vec<String> = COLOR_CHOICES
            .iter()
            .map(|(name, hex)| format!("{name} ({hex})"))
            .collect();
        if let Some(idx) = self.choose_from_menu("Pick Color", &labels)? {
            let (_name, hex) = COLOR_CHOICES[idx];
            let status = self.mutate_theme_config_and_refresh(|colors| target.set(colors, hex));
            self.show_theme_update_result(
                "Colors",
                vec![
                    format!(
                        "{} set to {}",
                        target.label(),
                        target.get(&self.config.colors)
                    ),
                    "Updated".to_string(),
                ],
                status,
            )
        } else {
            Ok(())
        }
    }

    pub(crate) fn apply_theme_preset(&mut self) -> Result<()> {
        let labels: Vec<String> = ThemePreset::ALL
            .iter()
            .map(|preset| preset.label().to_string())
            .collect();
        let Some(idx) = self.choose_from_menu("Theme Preset", &labels)? else {
            return Ok(());
        };
        let preset = ThemePreset::ALL[idx];
        let status = self.mutate_theme_config_and_refresh(|colors| preset.apply(colors));
        self.show_theme_update_result(
            "Colors",
            vec![format!("Preset: {}", preset.label()), "Updated".to_string()],
            status,
        )
    }

    fn mutate_theme_config_and_refresh<F>(&mut self, mutate: F) -> ThemeUpdateStatus
    where
        F: FnOnce(&mut crate::config::ColorScheme),
    {
        let path = self.root.join("gui_conf.json");
        let mut normalized = false;
        let mut save_error = None;
        match self.config.mutate_theme_and_persist(&path, mutate) {
            Ok(result) => {
                normalized = result.normalized;
            }
            Err(err) => {
                save_error = Some(shorten_for_display(&err.to_string(), 90));
            }
        }
        self.display.update_palette(&self.config.colors);

        ThemeUpdateStatus {
            normalized,
            save_error,
            contrast_warnings: self
                .config
                .colors
                .contrast_warnings(THEME_MIN_CONTRAST_RATIO),
        }
    }

    fn show_theme_update_result(
        &mut self,
        title: &str,
        mut lines: Vec<String>,
        status: ThemeUpdateStatus,
    ) -> Result<()> {
        if status.normalized {
            lines.push("Normalized invalid values".to_string());
        }
        if let Some(err) = status.save_error {
            lines.push("Save failed".to_string());
            lines.push(err);
        } else {
            lines.push("Saved".to_string());
        }
        if !status.contrast_warnings.is_empty() {
            lines.push("Contrast warning".to_string());
            for warning in status.contrast_warnings.iter().take(3) {
                lines.push(warning.clone());
            }
        }
        self.show_message(title, lines)
    }

    pub(crate) fn apply_log_setting(&mut self) -> Result<()> {
        let enabled = self.config.settings.logs_enabled;
        let response = self.core.logging_config_set(enabled, None)?;
        self.config.settings.logs_enabled = response.enabled;
        self.sync_log_env(response.enabled);
        Ok(())
    }

    pub(crate) fn sync_log_env(&self, enabled: bool) {
        if enabled {
            env::remove_var("RUSTYJACK_LOGS_DISABLED");
        } else {
            env::set_var("RUSTYJACK_LOGS_DISABLED", "1");
        }
    }

    pub(crate) fn toggle_logs(&mut self) -> Result<()> {
        self.config.settings.logs_enabled = !self.config.settings.logs_enabled;
        self.apply_log_setting()?;
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;
        let state = if self.config.settings.logs_enabled {
            "ON"
        } else {
            "OFF"
        };
        self.show_message("Logs", [format!("Logging {}", state)])
    }

    pub(crate) fn show_display_backend_info(&mut self) -> Result<()> {
        let configured = self
            .config
            .display
            .backend_preference
            .as_ref()
            .map(|b| b.as_str())
            .unwrap_or("auto");
        let effective = self.display.capabilities().backend.as_str();
        self.show_message(
            "Display Backend",
            [
                format!("Configured: {configured}"),
                format!("Effective: {effective}"),
                "Use env: RUSTYJACK_DISPLAY_BACKEND".to_string(),
            ],
        )
    }

    pub(crate) fn show_display_rotation_info(&mut self) -> Result<()> {
        let configured = self
            .config
            .display
            .rotation
            .as_ref()
            .map(|r| r.as_str())
            .unwrap_or("auto");
        let effective = self.display.capabilities().orientation.as_str();
        self.show_message(
            "Display Rotation",
            [
                format!("Configured: {configured}"),
                format!("Effective: {effective}"),
                "Use env: RUSTYJACK_DISPLAY_ROTATION".to_string(),
            ],
        )
    }

    pub(crate) fn show_display_resolution_info(&mut self) -> Result<()> {
        let override_width = self
            .config
            .display
            .width_override
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let override_height = self
            .config
            .display
            .height_override
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let diag = self.display.diagnostics();
        self.show_message(
            "Display Resolution",
            [
                format!("Override: {}x{}", override_width, override_height),
                format!(
                    "Detected: {}x{}",
                    diag.detected_width_px, diag.detected_height_px
                ),
                format!(
                    "Effective: {}x{}",
                    diag.effective_width_px, diag.effective_height_px
                ),
                format!("Source: {}", diag.geometry_source.as_str()),
            ],
        )
    }

    pub(crate) fn show_display_offset_info(&mut self) -> Result<()> {
        let offset_x = self
            .config
            .display
            .offset_x
            .map(|v| v.to_string())
            .unwrap_or_else(|| "auto".to_string());
        let offset_y = self
            .config
            .display
            .offset_y
            .map(|v| v.to_string())
            .unwrap_or_else(|| "auto".to_string());
        let diag = self.display.diagnostics();
        self.show_message(
            "Display Offsets",
            [
                format!("Configured: x={offset_x} y={offset_y}"),
                format!(
                    "Effective: x={} y={}",
                    diag.effective_offset_x, diag.effective_offset_y
                ),
            ],
        )
    }

    pub(crate) fn run_display_discovery_action(&mut self) -> Result<()> {
        self.display
            .run_display_discovery(&mut self.config.display)?;
        let path = self.root.join("gui_conf.json");
        self.save_config_file(&path)?;
        self.display.reset_probe_dirty();

        if self.display.needs_startup_calibration() {
            self.show_message(
                "Display Discovery",
                [
                    "Discovery complete",
                    "Geometry is unverified",
                    "Run Display Calibration",
                ],
            )
        } else {
            self.show_message("Display Discovery", ["Discovery complete"])
        }
    }

    pub(crate) fn run_display_calibration_flow(&mut self, manual: bool) -> Result<()> {
        if manual
            && !self.confirm_yes_no_bool(
                "Display Calibration",
                [
                    "Calibrate visible edges?",
                    "LEFT/RIGHT for vertical",
                    "UP/DOWN for horizontal",
                    "SELECT confirms each edge",
                ],
            )?
        {
            return Ok(());
        }

        let (default_left, default_top, default_right, default_bottom) =
            self.display.default_calibration_edges();

        // Keep calibration in hardware pixel coordinates so the guide line
        // always maps to a drawable position on screen.
        let min_edge = default_left;
        let max_right = default_right;
        let max_bottom = default_bottom;

        let mut left = self.config.display.calibrated_left.unwrap_or(default_left);
        let mut top = self.config.display.calibrated_top.unwrap_or(default_top);
        let mut right = self
            .config
            .display
            .calibrated_right
            .unwrap_or(default_right);
        let mut bottom = self
            .config
            .display
            .calibrated_bottom
            .unwrap_or(default_bottom);
        left = left.clamp(min_edge, max_right.saturating_sub(1));
        right = right.clamp(left.saturating_add(1), max_right);
        top = top.clamp(min_edge, max_bottom.saturating_sub(1));
        bottom = bottom.clamp(top.saturating_add(1), max_bottom);

        for edge in CalibrationEdge::ALL {
            let default_value = match edge {
                CalibrationEdge::Left => default_left,
                CalibrationEdge::Top => default_top,
                CalibrationEdge::Right => default_right,
                CalibrationEdge::Bottom => default_bottom,
            };
            loop {
                let candidate = match edge {
                    CalibrationEdge::Left => left,
                    CalibrationEdge::Top => top,
                    CalibrationEdge::Right => right,
                    CalibrationEdge::Bottom => bottom,
                };
                let overlay = self.stats.snapshot();
                self.display
                    .draw_calibration_step(edge, candidate, default_value, &overlay)?;

                let button = self.buttons.wait_for_press()?;
                match (edge, button) {
                    (_, Button::Key2) => {
                        self.show_message("Display Calibration", ["Cancelled"])?;
                        return Ok(());
                    }
                    (_, Button::Key1) => match edge {
                        CalibrationEdge::Left => left = default_value,
                        CalibrationEdge::Top => top = default_value,
                        CalibrationEdge::Right => right = default_value,
                        CalibrationEdge::Bottom => bottom = default_value,
                    },
                    (CalibrationEdge::Left, Button::Left) => {
                        left = (left - 1).max(min_edge).min(right - 1);
                    }
                    (CalibrationEdge::Left, Button::Right) => {
                        left = (left + 1).min(right - 1);
                    }
                    (CalibrationEdge::Right, Button::Left) => {
                        right = (right - 1).max(left + 1);
                    }
                    (CalibrationEdge::Right, Button::Right) => {
                        right = (right + 1).min(max_right);
                    }
                    (CalibrationEdge::Top, Button::Up) => {
                        top = (top - 1).max(min_edge).min(bottom - 1);
                    }
                    (CalibrationEdge::Top, Button::Down) => {
                        top = (top + 1).min(bottom - 1);
                    }
                    (CalibrationEdge::Bottom, Button::Up) => {
                        bottom = (bottom - 1).max(top + 1);
                    }
                    (CalibrationEdge::Bottom, Button::Down) => {
                        bottom = (bottom + 1).min(max_bottom);
                    }
                    (_, Button::Select) => break,
                    (_, Button::Left)
                        if !matches!(edge, CalibrationEdge::Left | CalibrationEdge::Right) => {}
                    (_, Button::Right)
                        if !matches!(edge, CalibrationEdge::Left | CalibrationEdge::Right) => {}
                    _ => {}
                }
            }
        }

        if let Err(err) = self.display.validate_calibration(left, top, right, bottom) {
            self.show_message(
                "Display Calibration",
                [
                    "Invalid calibration".to_string(),
                    shorten_for_display(&err.to_string(), self.display.chars_per_line()),
                ],
            )?;
            return Ok(());
        }

        if manual
            && !self.confirm_yes_no_bool(
                "Apply Calibration?",
                [
                    format!("L:{left} T:{top}"),
                    format!("R:{right} B:{bottom}"),
                    "Select Yes to save".to_string(),
                ],
            )?
        {
            self.show_message("Display Calibration", ["Not saved"])?;
            return Ok(());
        }

        self.display
            .apply_calibration(&mut self.config.display, left, top, right, bottom)?;
        let path = self.root.join("gui_conf.json");
        // Stage calibration as incomplete and fsync it first. If the UI crashes
        // before finalize, startup will resume the wizard instead of skipping it.
        self.save_config_file(&path)?;
        if let Err(err) = self.display.finalize_calibration(&mut self.config.display) {
            self.config.display.display_wizard_incomplete = true;
            self.config.display.display_calibration_completed = false;
            return Err(err).context("failed to finalize display calibration");
        }
        self.save_config_file(&path)?;
        self.display.reset_probe_dirty();

        if manual {
            self.show_message("Display Calibration", ["Calibration saved"])?;
        }
        Ok(())
    }

    pub(crate) fn reset_display_calibration_action(&mut self) -> Result<()> {
        if !self.confirm_yes_no_bool(
            "Reset Calibration",
            ["Clear saved edges?", "You can recalibrate any time"],
        )? {
            return Ok(());
        }
        self.display.reset_calibration(&mut self.config.display)?;
        let path = self.root.join("gui_conf.json");
        self.save_config_file(&path)?;
        self.display.reset_probe_dirty();
        self.show_message("Display Calibration", ["Calibration reset"])
    }

    pub(crate) fn reset_display_cache_action(&mut self) -> Result<()> {
        if !self.confirm_yes_no_bool(
            "Reset Display Cache",
            ["Clear discovery cache?", "Use Discovery to repopulate"],
        )? {
            return Ok(());
        }
        self.display.reset_cache(&mut self.config.display)?;
        let path = self.root.join("gui_conf.json");
        self.save_config_file(&path)?;
        self.display.reset_probe_dirty();
        self.show_message("Display Cache", ["Cache reset"])
    }

    pub(crate) fn show_display_diagnostics(&mut self) -> Result<()> {
        let diag = self.display.diagnostics();
        let mut lines = vec![
            format!("Backend: {}", diag.backend.as_str()),
            format!(
                "Detected: {}x{}",
                diag.detected_width_px, diag.detected_height_px
            ),
            format!(
                "Effective: {}x{}",
                diag.effective_width_px, diag.effective_height_px
            ),
            format!(
                "Offset: {},{}",
                diag.effective_offset_x, diag.effective_offset_y
            ),
            format!("Source: {}", diag.geometry_source.as_str()),
            format!("Probe done: {}", diag.probe_completed),
            format!("Cal done: {}", diag.calibration_completed),
            format!(
                "Fingerprint: {}",
                shorten_for_display(&diag.profile_fingerprint, self.display.chars_per_line())
            ),
        ];
        for warning in &diag.warnings {
            lines.push(format!("Warn: {}", warning.code()));
        }
        self.show_message("Display Diagnostics", lines)
    }

    pub(crate) fn tx_power_label(level: TxPowerSetting) -> (&'static str, &'static str) {
        match level {
            TxPowerSetting::Stealth => ("Stealth (1dBm)", "stealth"),
            TxPowerSetting::Low => ("Low (5dBm)", "low"),
            TxPowerSetting::Medium => ("Medium (12dBm)", "medium"),
            TxPowerSetting::High => ("High (18dBm)", "high"),
            TxPowerSetting::Maximum => ("Maximum", "maximum"),
        }
    }

    pub(crate) fn read_webhook_url(&mut self) -> Result<Option<String>> {
        let enc_active = self.webhook_encryption_active();
        let enc_path = self.root.join("discord_webhook.txt.enc");
        let plain_path = self.root.join("discord_webhook.txt");

        if enc_active {
            self.ensure_saved_key_loaded();
            if !rustyjack_encryption::encryption_enabled() {
                bail!("Encryption enabled but key not loaded");
            }
            if enc_path.exists() {
                let mut bytes = rustyjack_encryption::decrypt_file(&enc_path)?;
                let mut content = String::from_utf8(bytes.clone())?.trim().to_string();
                if content.starts_with("https://discord.com/api/webhooks/") && !content.is_empty() {
                    // zeroize buffers before returning copy
                    bytes.zeroize();
                    let out = content.clone();
                    content.zeroize();
                    clear_encryption_key();
                    return Ok(Some(out));
                }
                bytes.zeroize();
                content.zeroize();
                clear_encryption_key();
            }
        }

        if plain_path.exists() {
            let mut content = fs::read_to_string(&plain_path)?.trim().to_string();
            if content.starts_with("https://discord.com/api/webhooks/") && !content.is_empty() {
                let out = content.clone();
                content.zeroize();
                return Ok(Some(out));
            }
            content.zeroize();
        }

        Ok(None)
    }

    pub(crate) fn webhook_encryption_active(&self) -> bool {
        self.config.settings.encryption_enabled && self.config.settings.encrypt_discord_webhook
    }

    pub(crate) fn loot_encryption_active(&self) -> bool {
        self.config.settings.encryption_enabled && self.config.settings.encrypt_loot
    }

    pub(crate) fn wifi_encryption_active(&self) -> bool {
        self.config.settings.encryption_enabled && self.config.settings.encrypt_wifi_profiles
    }

    pub(crate) fn discord_upload(&mut self) -> Result<()> {
        self.ensure_saved_key_loaded();
        // Check if webhook is configured first
        let mut webhook = match self.read_webhook_url() {
            Ok(Some(url)) => url,
            Ok(None) => {
                return self.show_message(
                    "Discord Error",
                    [
                        "No webhook configured",
                        "",
                        "Create file:",
                        "discord_webhook.txt",
                        "with your webhook URL",
                    ],
                );
            }
            Err(e) => {
                return self.show_message(
                    "Discord Error",
                    [
                        "Failed to read webhook",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };

        let (temp_path, archive_path) = self.build_loot_archive()?;
        let args = DiscordSendArgs {
            title: "Rustyjack Loot".to_string(),
            message: Some("Complete loot archive".to_string()),
            file: vec![archive_path.clone()],
            target: Some(webhook.clone()),
            interface: None,
        };
        let result = self.core.dispatch(Commands::Notify(NotifyCommand::Discord(
            DiscordCommand::Send(args),
        )));
        drop(temp_path);
        // Best-effort scrub
        webhook.zeroize();
        clear_encryption_key();
        match result {
            Ok(_) => self.show_message("Discord", ["Loot uploaded"])?,
            Err(err) => {
                let msg = err.to_string();
                self.show_message("Discord", [msg.as_str()])?;
            }
        }
        Ok(())
    }

    pub(crate) fn import_webhook_from_usb(&mut self) -> Result<()> {
        let Some(file_path) = self.browse_usb_for_file("Webhook from USB", Some(&["txt"]))? else {
            return Ok(());
        };

        let mut content = match fs::read_to_string(&file_path) {
            Ok(c) => c.trim().to_string(),
            Err(e) => {
                return self.show_message(
                    "Discord",
                    [
                        "Failed to read file",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };

        if content.is_empty() {
            return self.show_message("Discord", ["Webhook file is empty"]);
        }
        if !content.starts_with("https://discord.com/api/webhooks/") {
            return self.show_message(
                "Discord",
                ["Invalid webhook", "Expected a Discord webhook URL"],
            );
        }

        let enc = self.webhook_encryption_active();
        let dest_plain = self.root.join("discord_webhook.txt");
        let dest_enc = self.root.join("discord_webhook.txt.enc");
        if dest_plain.exists() {
            if let Err(err) = fs::remove_file(&dest_plain) {
                tracing::warn!("Failed to remove {}: {:#}", dest_plain.display(), err);
            }
        }
        if dest_enc.exists() {
            if let Err(err) = fs::remove_file(&dest_enc) {
                tracing::warn!("Failed to remove {}: {:#}", dest_enc.display(), err);
            }
        }

        if enc {
            self.ensure_saved_key_loaded();
            if !rustyjack_encryption::encryption_enabled() {
                return self.show_message(
                    "Discord",
                    ["Encryption enabled", "Load key before importing"],
                );
            }
            if let Err(e) = rustyjack_encryption::encrypt_to_file(&dest_enc, content.as_bytes()) {
                return self.show_message(
                    "Discord",
                    [
                        "Failed to encrypt webhook",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
            let res = self.show_message(
                "Discord",
                [
                    "Webhook imported (enc)",
                    &shorten_for_display(dest_enc.to_string_lossy().as_ref(), 18),
                ],
            );
            content.zeroize();
            clear_encryption_key();
            res
        } else {
            if let Err(e) = fs::write(&dest_plain, &content) {
                return self.show_message(
                    "Discord",
                    [
                        "Failed to save webhook",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
            let res = self.show_message(
                "Discord",
                [
                    "Webhook imported",
                    &shorten_for_display(dest_plain.to_string_lossy().as_ref(), 18),
                ],
            );
            content.zeroize();
            res
        }
    }

    pub(crate) fn toggle_discord(&mut self) -> Result<()> {
        self.config.settings.discord_enabled = !self.config.settings.discord_enabled;
        self.save_config()?;
        // No message needed as the menu label will update immediately
        Ok(())
    }

    pub(crate) fn show_hardware_detect(&mut self) -> Result<()> {
        self.select_active_interface()
    }
}
