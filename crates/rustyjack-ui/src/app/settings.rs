use std::{env, fs};

use anyhow::{bail, Result};

use rustyjack_commands::{
    Commands, DiscordCommand, DiscordSendArgs, HardwareCommand, NotifyCommand,
};
use rustyjack_encryption::clear_encryption_key;
use zeroize::Zeroize;

use crate::{
    config::GuiConfig,
    display::DIALOG_VISIBLE_LINES,
    menu::{ColorTarget, TxPowerSetting},
    util::shorten_for_display,
};

use super::state::App;

impl App {
    pub(crate) fn reload_config(&mut self) -> Result<()> {
        self.config = GuiConfig::load(&self.root)?;
        self.display.update_palette(&self.config.colors);
        self.show_message("Config", ["Reloaded"])
    }

    pub(crate) fn save_config(&mut self) -> Result<()> {
        self.config.save(&self.root.join("gui_conf.json"))?;
        self.show_message("Config", ["Saved"])
    }

    pub(crate) fn pick_color(&mut self, target: ColorTarget) -> Result<()> {
        // List-based selection to keep navigation consistent
        let choices = [
            ("White", "#FFFFFF"),
            ("Black", "#000000"),
            ("Green", "#00FF00"),
            ("Red", "#FF0000"),
            ("Blue", "#0000FF"),
            ("Navy", "#000080"),
            ("Purple", "#AA00FF"),
        ];
        let labels: Vec<String> = choices.iter().map(|(name, _)| name.to_string()).collect();

        if let Some(idx) = self.choose_from_menu("Pick Color", &labels)? {
            let (_name, hex) = choices[idx];
            self.apply_color(target, hex);
            self.show_message("Colors", ["Updated"])
        } else {
            Ok(())
        }
    }

    pub(crate) fn apply_color(&mut self, target: ColorTarget, value: &str) {
        match target {
            ColorTarget::Background => self.config.colors.background = value.to_string(),
            ColorTarget::Border => self.config.colors.border = value.to_string(),
            ColorTarget::Text => self.config.colors.text = value.to_string(),
            ColorTarget::SelectedText => self.config.colors.selected_text = value.to_string(),
            ColorTarget::SelectedBackground => {
                self.config.colors.selected_background = value.to_string()
            }
            ColorTarget::Toolbar => self.config.colors.toolbar = value.to_string(),
        }
        self.display.update_palette(&self.config.colors);
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
            file: Some(archive_path.clone()),
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
        self.show_progress(
            "Hardware Sanity Check",
            ["Detecting interfaces...", "Please wait"],
        )?;

        match self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))
        {
            Ok((_, data)) => {
                let eth_count = data
                    .get("ethernet_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let wifi_count = data.get("wifi_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let other_count = data
                    .get("other_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let sanity_overall = data
                    .get("sanity")
                    .and_then(|v| v.get("overall"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                let ethernet_ports = data
                    .get("ethernet_ports")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let wifi_modules = data
                    .get("wifi_modules")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Build list of detected interfaces (clickable)
                let mut all_interfaces = Vec::new();
                let mut labels = Vec::new();

                let active_interface = self.config.settings.active_network_interface.clone();

                for port in &ethernet_ports {
                    if let Some(name) = port.get("name").and_then(|v| v.as_str()) {
                        let label = if name == active_interface {
                            format!("* {}", name)
                        } else {
                            name.to_string()
                        };
                        labels.push(label);
                        all_interfaces.push(port.clone());
                    }
                }
                for module in &wifi_modules {
                    if let Some(name) = module.get("name").and_then(|v| v.as_str()) {
                        let label = if name == active_interface {
                            format!("* {}", name)
                        } else {
                            name.to_string()
                        };
                        labels.push(label);
                        all_interfaces.push(module.clone());
                    }
                }

                // If nothing to show, just present summary
                if labels.is_empty() {
                    return self.show_message(
                        "Hardware Sanity Check",
                        [
                            format!("Ethernet: {}", eth_count),
                            format!("WiFi: {}", wifi_count),
                            format!("Other: {}", other_count),
                            "".to_string(),
                            "No interfaces detected".to_string(),
                        ],
                    );
                }

                // Add summary at top
                let mut summary_lines = vec![
                    format!("Sanity: {}", sanity_overall),
                    format!("Ethernet: {}", eth_count),
                    format!("WiFi: {}", wifi_count),
                    format!("Other: {}", other_count),
                ];
                summary_lines.push("".to_string());
                summary_lines.push("Select to set active".to_string());

                self.show_message(
                    "Hardware Sanity Check",
                    summary_lines.iter().map(|s| s.as_str()),
                )?;

                if sanity_overall != "OK" {
                    let mut issue_lines = vec!["Hardware Sanity".to_string()];
                    if let Some(checks) = data
                        .get("sanity")
                        .and_then(|v| v.get("checks"))
                        .and_then(|v| v.as_array())
                    {
                        for check in checks {
                            let status = check
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("UNKNOWN");
                            if status == "OK" {
                                continue;
                            }
                            let name = check
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("check");
                            issue_lines.push(format!(
                                "{}: {}",
                                status,
                                shorten_for_display(name, 16)
                            ));
                            if let Some(path) = check
                                .get("missing_paths")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|v| v.as_str())
                            {
                                issue_lines.push(shorten_for_display(path, 18));
                            }
                            if issue_lines.len() >= (DIALOG_VISIBLE_LINES as usize - 1) {
                                issue_lines.push("More...".to_string());
                                break;
                            }
                        }
                    }
                    self.show_message("Hardware Sanity", issue_lines.iter().map(|s| s.as_str()))?;
                }

                // Let user select interface
                if let Some(idx) = self.choose_from_menu("Set Active Interface", &labels)? {
                    if let Some(selected) = all_interfaces.get(idx) {
                        if let Some(name) = selected.get("name").and_then(|v| v.as_str()) {
                            self.config.settings.active_network_interface = name.to_string();
                            self.save_config()?;
                            return self
                                .show_message("Active Interface", [format!("Set to: {}", name)]);
                        }
                    }
                }

                Ok(())
            }
            Err(e) => self.show_message("Hardware Sanity Check", [format!("Error: {}", e)]),
        }
    }
}
