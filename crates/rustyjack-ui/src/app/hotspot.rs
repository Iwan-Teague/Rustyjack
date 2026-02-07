use std::{
    collections::HashSet,
    fs,
    io::Write,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use chrono::Local;
use rustyjack_commands::{
    Commands, HardwareCommand, HotspotBlacklistArgs, HotspotCommand, HotspotDisconnectArgs,
    HotspotStartArgs,
};

use crate::{
    config::BlacklistedDevice,
    types::InterfaceSummary,
    util::{random_hotspot_password, random_hotspot_ssid, shorten_for_display},
};

use super::{
    error::{classify_start_ap_error, format_bytes_per_sec},
    state::{App, ButtonAction},
};

impl App {
    pub(crate) fn manage_hotspot(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message(
                "Hotspot",
                ["Hotspot control is available", "on Linux targets only."],
            );
        }

        #[cfg(target_os = "linux")]
        {
            loop {
                let status = self
                    .core
                    .dispatch(Commands::Hotspot(HotspotCommand::Status))?;
                let data = status.1;

                if let Ok(warnings) = self.core.hotspot_warnings() {
                    if let Some(err) = warnings.last_ap_error.as_deref() {
                        self.show_message(
                            "Hotspot error",
                            [
                                "Hotspot encountered an error:",
                                &shorten_for_display(err, 90),
                            ],
                        )?;
                    }
                    if let Some(warn) = warnings.last_warning.as_deref() {
                        self.show_message(
                            "Hotspot warning",
                            [
                                "Hotspot reported a warning:",
                                &shorten_for_display(warn, 90),
                            ],
                        )?;
                    }
                }

                let running = data
                    .get("running")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let ap_iface = data
                    .get("ap_interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let upstream_iface = data
                    .get("upstream_interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let upstream_ready = data
                    .get("upstream_ready")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let current_ssid = data
                    .get("ssid")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.config.settings.hotspot_ssid)
                    .to_string();
                let current_password = data
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.config.settings.hotspot_password)
                    .to_string();
                let current_channel = data
                    .get("channel")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u8)
                    .unwrap_or(self.config.settings.hotspot_channel);
                let nm_error = data
                    .get("nm_error")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let restore_nm_on_stop = data
                    .get("restore_nm_on_stop")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(self.config.settings.hotspot_restore_nm);

                // Note: Interface isolation is handled by the core operations when starting/stopping
                // the hotspot. We don't need to apply it in the status loop as it causes race conditions.

                let mut lines = vec![
                    format!("SSID: {}", current_ssid),
                    format!("Password: {}", current_password),
                    format!("Channel: {}", current_channel),
                    "".to_string(),
                    format!("Status: {}", if running { "ON" } else { "OFF" }),
                ];
                if running {
                    lines.push(format!("AP: {}", ap_iface));
                    let upstream_line = if upstream_iface.is_empty() {
                        "Upstream: none (offline)".to_string()
                    } else if upstream_ready {
                        format!("Upstream: {} (internet)", upstream_iface)
                    } else {
                        format!("Upstream: {} (offline/no IP)", upstream_iface)
                    };
                    lines.push(upstream_line);
                }
                if let Some(err) = nm_error {
                    lines.push(format!("NM warn: {}", shorten_for_display(&err, 24)));
                }

                let options = if running {
                    vec![
                        "Network Info".to_string(),
                        "Connected Devices".to_string(),
                        "Device Blacklist".to_string(),
                        "Network Speed".to_string(),
                        "Diagnostics".to_string(),
                        "Turn off hotspot".to_string(),
                    ]
                } else {
                    vec![
                        "Start hotspot".to_string(),
                        format!("Channel: {}", self.config.settings.hotspot_channel),
                        format!(
                            "Restore NM on stop: {}",
                            if restore_nm_on_stop { "On" } else { "Off" }
                        ),
                        "Randomize name".to_string(),
                        "Randomize password".to_string(),
                        "Diagnostics".to_string(),
                        "Back".to_string(),
                    ]
                };

                let choice = self.choose_from_list("Hotspot", &options)?;
                match (running, choice) {
                    (true, Some(0)) => {
                        // Network Info
                        self.show_hotspot_network_info(
                            &current_ssid,
                            &current_password,
                            &ap_iface,
                            &upstream_iface,
                        )?;
                    }
                    (true, Some(1)) => {
                        // Connected Devices
                        self.show_hotspot_connected_devices(&ap_iface)?;
                    }
                    (true, Some(2)) => {
                        // Device Blacklist
                        self.manage_hotspot_blacklist()?;
                    }
                    (true, Some(3)) => {
                        // Network Speed
                        self.show_hotspot_network_speed(&upstream_iface)?;
                    }
                    (true, Some(4)) => {
                        // Diagnostics
                        self.show_hotspot_diagnostics(&ap_iface)?;
                    }
                    (true, Some(5)) => {
                        // Turn off hotspot
                        if let Err(err) =
                            self.core.dispatch(Commands::Hotspot(HotspotCommand::Stop))
                        {
                            self.show_error_dialog("Hotspot Stop Failed", &err)?;
                        }
                    }
                    (true, None) => {
                        // User is trying to exit while hotspot is running - confirm
                        let confirm_options =
                            vec!["Turn off & exit".to_string(), "Keep running".to_string()];
                        let confirm = self.choose_from_list("Hotspot Active", &confirm_options)?;

                        match confirm {
                            Some(0) => {
                                // Turn off hotspot and exit
                                if let Err(err) =
                                    self.core.dispatch(Commands::Hotspot(HotspotCommand::Stop))
                                {
                                    self.show_error_dialog("Hotspot Stop Failed", &err)?;
                                }
                                return Ok(());
                            }
                            _ => {
                                // Keep running, stay in menu
                                continue;
                            }
                        }
                    }
                    (false, Some(0)) => {
                        // Select interfaces using hardware detect
                        let (_msg, detect) = self
                            .core
                            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;

                        let mut ethernet = Vec::new();
                        if let Some(arr) = detect.get("ethernet_ports").and_then(|v| v.as_array()) {
                            for item in arr {
                                if let Ok(info) =
                                    serde_json::from_value::<InterfaceSummary>(item.clone())
                                {
                                    ethernet.push(info.name);
                                }
                            }
                        }

                        let mut wifi = Vec::new();
                        if let Some(arr) = detect.get("wifi_modules").and_then(|v| v.as_array()) {
                            for item in arr {
                                if let Ok(info) =
                                    serde_json::from_value::<InterfaceSummary>(item.clone())
                                {
                                    wifi.push(info.name);
                                }
                            }
                        }

                        if wifi.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No WiFi interface found",
                                    "",
                                    "Plug in or enable a",
                                    "WiFi adapter to host",
                                    "the hotspot.",
                                ],
                            );
                        }

                        let upstream_pref = if ethernet.contains(&"eth0".to_string()) {
                            "eth0".to_string()
                        } else {
                            ethernet
                                .first()
                                .cloned()
                                .or_else(|| wifi.first().cloned())
                                .unwrap_or_default()
                        };

                        let mut upstream_options = Vec::new();
                        upstream_options.push("None (offline)".to_string());
                        upstream_options.extend(ethernet.clone());
                        upstream_options.extend(wifi.clone());

                        if upstream_options.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No interfaces detected",
                                    "",
                                    "Run Hardware Sanity Check and",
                                    "ensure adapters are up.",
                                ],
                            );
                        }

                        let upstream_choice =
                            self.choose_from_menu("Internet (upstream)", &upstream_options)?;
                        let upstream_iface = match upstream_choice {
                            Some(0) => "".to_string(),
                            Some(idx) => upstream_options
                                .get(idx)
                                .cloned()
                                .unwrap_or_else(|| upstream_pref.clone()),
                            None => upstream_pref.clone(),
                        };
                        let mut upstream_note = String::new();
                        if upstream_choice == Some(0) {
                            upstream_note =
                                "No upstream selected; hotspot will have no internet.".to_string();
                        } else if !upstream_iface.is_empty()
                            && !self.interface_has_ip(&upstream_iface)
                        {
                            upstream_note = format!(
                                "{} has no IP; hotspot will be local-only until it connects.",
                                upstream_iface
                            );
                        }

                        // Build AP list (WiFi only, excluding upstream if same)
                        let ap_choices: Vec<String> = wifi
                            .iter()
                            .filter(|name| **name != upstream_iface)
                            .cloned()
                            .collect();

                        if ap_choices.is_empty() {
                            return self.show_message(
                                "Hotspot",
                                [
                                    "No WiFi interface left",
                                    "",
                                    "Select a different",
                                    "upstream interface.",
                                ],
                            );
                        }

                        let ap_iface = self
                            .choose_interface_name("Hotspot WiFi (AP)", &ap_choices)?
                            .unwrap_or_else(|| {
                                ap_choices
                                    .first()
                                    .cloned()
                                    .unwrap_or_else(|| "wlan0".to_string())
                            });

                        if let Some(error) = self.preflight_hotspot(&ap_iface, &upstream_iface)? {
                            return self.show_preflight_error("Preflight Failed", &error);
                        }

                        let args = HotspotStartArgs {
                            ap_interface: ap_iface.clone(),
                            upstream_interface: upstream_iface.clone(),
                            ssid: self.config.settings.hotspot_ssid.clone(),
                            password: self.config.settings.hotspot_password.clone(),
                            channel: self.config.settings.hotspot_channel,
                            restore_nm_on_stop: self.config.settings.hotspot_restore_nm,
                        };
                        match self
                            .core
                            .dispatch(Commands::Hotspot(HotspotCommand::Start(args)))
                        {
                            Ok((msg, data)) => {
                                let ssid = data
                                    .get("ssid")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&self.config.settings.hotspot_ssid)
                                    .to_string();
                                let password = data
                                    .get("password")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&self.config.settings.hotspot_password)
                                    .to_string();
                                self.config.settings.hotspot_ssid = ssid.clone();
                                self.config.settings.hotspot_password = password.clone();
                                let config_path = self.root.join("gui_conf.json");
                                self.save_config_file(&config_path)?;

                                // Note: Interface isolation is handled by core operations during hotspot start.
                                // We don't apply it here to avoid race conditions.

                                let upstream_line = if upstream_iface.is_empty() {
                                    "Upstream: none (offline)".to_string()
                                } else if data
                                    .get("upstream_ready")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(true)
                                {
                                    format!("Upstream: {} (internet)", upstream_iface)
                                } else {
                                    format!("Upstream: {} (offline/no IP)", upstream_iface)
                                };

                                self.show_message(
                                    "Hotspot started",
                                    [
                                        msg,
                                        format!("SSID: {}", ssid),
                                        format!("Password: {}", password),
                                        format!("AP: {}", ap_iface),
                                        upstream_line,
                                        if upstream_note.is_empty() {
                                            "".to_string()
                                        } else {
                                            upstream_note.clone()
                                        },
                                        "".to_string(),
                                        "Turn off to exit this view".to_string(),
                                    ],
                                )?;
                            }
                            Err(e) => {
                                let err = e.to_string();
                                let mut lines = vec![
                                    "Failed to start hotspot".to_string(),
                                    shorten_for_display(&err, 90),
                                ];
                                #[cfg(target_os = "linux")]
                                {
                                    if let Ok(warnings) = self.core.hotspot_warnings() {
                                        if let Some(start_err) =
                                            warnings.last_start_error.as_deref()
                                        {
                                            lines.push(shorten_for_display(
                                                &format!("START_AP: {}", start_err),
                                                90,
                                            ));
                                            if let Some(hint) = classify_start_ap_error(start_err) {
                                                lines.push(format!("Cause: {}", hint.category));
                                                lines.push(format!("Hint: {}", hint.hint));
                                            }
                                        } else if let Some(hint) = classify_start_ap_error(&err) {
                                            lines.push(format!("Cause: {}", hint.category));
                                            lines.push(format!("Hint: {}", hint.hint));
                                        }
                                        if let Some(ap_err) = warnings.last_ap_error.as_deref() {
                                            lines.push(shorten_for_display(
                                                &format!("AP detail: {}", ap_err),
                                                90,
                                            ));
                                        }
                                    } else if let Some(hint) = classify_start_ap_error(&err) {
                                        lines.push(format!("Cause: {}", hint.category));
                                        lines.push(format!("Hint: {}", hint.hint));
                                    }
                                }
                                lines.push(
                                    "See journalctl -u rustyjack-ui.service for full logs."
                                        .to_string(),
                                );
                                self.show_message("Hotspot error", lines)?;
                            }
                        }
                    }
                    (false, Some(1)) => {
                        #[cfg(target_os = "linux")]
                        {
                            if let Some(channel) = self.select_hotspot_channel(None)? {
                                self.config.settings.hotspot_channel = channel;
                                let config_path = self.root.join("gui_conf.json");
                                self.save_config_file(&config_path)?;
                                self.show_message(
                                    "Hotspot",
                                    [format!("Channel set to {}", channel)],
                                )?;
                            }
                        }
                    }
                    (false, Some(2)) => {
                        #[cfg(target_os = "linux")]
                        {
                            self.config.settings.hotspot_restore_nm =
                                !self.config.settings.hotspot_restore_nm;
                            let config_path = self.root.join("gui_conf.json");
                            self.save_config_file(&config_path)?;
                            self.show_message(
                                "Hotspot",
                                [format!(
                                    "Restore NM: {}",
                                    if self.config.settings.hotspot_restore_nm {
                                        "On"
                                    } else {
                                        "Off"
                                    }
                                )],
                            )?;
                        }
                    }
                    (false, Some(3)) => {
                        #[cfg(target_os = "linux")]
                        {
                            let ssid = random_hotspot_ssid();
                            self.config.settings.hotspot_ssid = ssid.clone();
                            let config_path = self.root.join("gui_conf.json");
                            self.save_config_file(&config_path)?;
                            self.show_message("Hotspot", ["SSID updated", &ssid])?;
                        }
                    }
                    (false, Some(4)) => {
                        #[cfg(target_os = "linux")]
                        {
                            let pw = random_hotspot_password();
                            self.config.settings.hotspot_password = pw.clone();
                            let config_path = self.root.join("gui_conf.json");
                            self.save_config_file(&config_path)?;
                            self.show_message("Hotspot", ["Password updated", &pw])?;
                        }
                    }
                    (false, Some(5)) => {
                        // Diagnostics
                        self.show_hotspot_diagnostics("")?;
                    }
                    (false, Some(6)) | (false, None) => return Ok(()),
                    _ => return Ok(()),
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn list_wifi_interfaces(&mut self) -> Result<Vec<String>> {
        let (_msg, detect) = self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;
        let mut wifi = Vec::new();
        if let Some(arr) = detect.get("wifi_modules").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    wifi.push(info.name);
                }
            }
        }
        Ok(wifi)
    }

    pub(crate) fn interface_has_ip(&self, _interface: &str) -> bool {
        // TODO: Implement once daemon provides interface details with IP info
        // For now, assume interfaces might have IPs
        true
    }

    pub(crate) fn monitor_mode_supported(&self, interface: &str) -> bool {
        if interface.trim().is_empty() {
            return false;
        }
        match self.core.wifi_capabilities(interface) {
            Ok(caps) => caps.supports_monitor_mode,
            Err(err) => {
                tracing::warn!("Failed to read capabilities for {}: {}", interface, err);
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn resolve_hotspot_interface(
        &mut self,
        ap_iface_hint: &str,
    ) -> Result<Option<String>> {
        if !ap_iface_hint.is_empty() {
            return Ok(Some(ap_iface_hint.to_string()));
        }

        let wifi = self.list_wifi_interfaces()?;
        if wifi.is_empty() {
            self.show_message(
                "Hotspot",
                [
                    "No WiFi interface found",
                    "",
                    "Plug in or enable a",
                    "WiFi adapter to host",
                    "the hotspot.",
                ],
            )?;
            return Ok(None);
        }

        self.choose_interface_name("Hotspot WiFi (AP)", &wifi)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn select_hotspot_channel(
        &mut self,
        ap_iface_hint: Option<&str>,
    ) -> Result<Option<u8>> {
        let ap_iface = match self.resolve_hotspot_interface(ap_iface_hint.unwrap_or(""))? {
            Some(iface) => iface,
            None => return Ok(None),
        };

        let mut channels = match self.core.hotspot_diagnostics(&ap_iface) {
            Ok(diag) => diag.allowed_channels,
            Err(err) => {
                self.show_message(
                    "Hotspot",
                    [
                        "Channel list unavailable",
                        &shorten_for_display(&err.to_string(), 90),
                    ],
                )?;
                Vec::new()
            }
        };

        if channels.is_empty() {
            channels = (1u8..=11u8).collect();
        }

        channels.sort_unstable();
        channels.dedup();

        let current = self.config.settings.hotspot_channel;
        if !channels.contains(&current) {
            channels.insert(0, current);
        }

        let labels: Vec<String> = channels
            .iter()
            .map(|ch| {
                if *ch == current {
                    format!("Channel {} (current)", ch)
                } else {
                    format!("Channel {}", ch)
                }
            })
            .collect();

        let choice = self.choose_from_menu("Hotspot channel", &labels)?;
        Ok(choice.map(|idx| channels[idx]))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn show_hotspot_diagnostics(&mut self, ap_iface_hint: &str) -> Result<()> {
        let ap_iface = match self.resolve_hotspot_interface(ap_iface_hint)? {
            Some(iface) => iface,
            None => return Ok(()),
        };

        let diag = match self.core.hotspot_diagnostics(&ap_iface) {
            Ok(diag) => diag,
            Err(err) => {
                return self.show_message(
                    "Hotspot diag",
                    [
                        "Diagnostics unavailable",
                        &shorten_for_display(&err.to_string(), 90),
                    ],
                );
            }
        };

        let mut lines = Vec::new();
        lines.push(format!("Interface: {}", ap_iface));

        match diag.regdom_raw.as_deref() {
            Some(raw) if diag.regdom_valid => {
                lines.push(format!("Regdom: {}", raw));
            }
            Some(raw) => {
                lines.push(format!("Regdom: {} (unset)", raw));
                lines.push("Set country/regdom for channels".to_string());
            }
            None => {
                lines.push("Regdom: unknown".to_string());
                lines.push("Set country/regdom for channels".to_string());
            }
        }

        if diag.rfkill.is_empty() {
            lines.push("RF-kill: none".to_string());
        } else {
            lines.push("RF-kill:".to_string());
            for dev in diag.rfkill.iter() {
                lines.push(format!(
                    "rfkill{}: {} {}",
                    dev.idx, dev.type_name, dev.state
                ));
            }
        }

        if let Some(caps) = diag.ap_support.as_ref() {
            lines.push(format!(
                "AP support: {}",
                if caps.supports_ap { "yes" } else { "no" }
            ));
            if !caps.supported_modes.is_empty() {
                lines.push(format!("Modes: {}", caps.supported_modes.join(", ")));
            }
            if !caps.supported_bands.is_empty() {
                lines.push(format!("Bands: {}", caps.supported_bands.join(", ")));
            }
        } else {
            lines.push("AP support: unknown".to_string());
        }

        if !diag.allowed_channels.is_empty() {
            let list = diag
                .allowed_channels
                .iter()
                .map(|ch| ch.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("Channels: {}", list));
        } else {
            lines.push("Channels: none".to_string());
        }

        if let Some(err) = diag.last_start_error.as_deref() {
            lines.push(shorten_for_display(&format!("Last START_AP: {}", err), 90));
            if let Some(hint) = classify_start_ap_error(err) {
                lines.push(format!("Cause: {}", hint.category));
                lines.push(format!("Hint: {}", hint.hint));
            }
        } else {
            lines.push("Last START_AP: none".to_string());
        }

        self.show_message("Hotspot diag", lines.iter().map(|s| s.as_str()))
    }

    pub(crate) fn show_hotspot_network_info(
        &mut self,
        ssid: &str,
        password: &str,
        ap_iface: &str,
        upstream_iface: &str,
    ) -> Result<()> {
        let mut lines = vec![
            format!("SSID: {}", ssid),
            format!("Password: {}", password),
            "".to_string(),
            format!("AP Interface: {}", ap_iface),
        ];

        if upstream_iface.is_empty() {
            lines.push("Upstream: None (offline)".to_string());
        } else {
            lines.push(format!("Upstream: {}", upstream_iface));

            // Check if upstream has IP/internet
            if self.interface_has_ip(upstream_iface) {
                lines.push("Status: Online".to_string());
            } else {
                lines.push("Status: No IP".to_string());
            }
        }

        // Add Rustyjack IP for SSH access
        lines.push("".to_string());
        lines.push("Rustyjack IP: 10.20.30.1".to_string());
        lines.push("SSH: ssh user@10.20.30.1".to_string());

        self.show_message("Network Info", lines.iter().map(|s| s.as_str()))
    }

    pub(crate) fn show_hotspot_connected_devices(&mut self, ap_iface: &str) -> Result<()> {
        // Get currently connected clients by checking ARP table for active devices
        let mut clients = Vec::new();
        let mut active_macs = HashSet::new();

        // Query ARP table to find currently connected devices
        // ARP entries for devices on our AP subnet (10.20.30.x)
        if let Ok(contents) = fs::read_to_string("/proc/net/arp") {
            for (idx, line) in contents.lines().enumerate() {
                if idx == 0 {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }
                let iface = parts[5];
                if iface != ap_iface {
                    continue;
                }
                let flags = parts[2];
                let mac = parts[3].to_lowercase();
                if flags != "0x0" && mac != "00:00:00:00:00:00" {
                    active_macs.insert(mac);
                }
            }
        }

        // Read lease file for device info and record all devices to history
        let loot_hotspot_dir = self.root.join("loot").join("Hotspot");
        fs::create_dir_all(&loot_hotspot_dir).ok();
        let history_path = loot_hotspot_dir.join("device_history.txt");

        // Read existing history to avoid duplicate logging
        let mut logged_devices = HashSet::new();
        if let Ok(history_content) = fs::read_to_string(&history_path) {
            for line in history_content.lines() {
                // Extract MAC from history line format: "timestamp | MAC: xx:xx:xx:xx:xx:xx | ..."
                if let Some(mac_part) = line.split(" | MAC: ").nth(1) {
                    if let Some(mac) = mac_part.split(" | ").next() {
                        logged_devices.insert(mac.to_lowercase());
                    }
                }
            }
        }

        let leases = match self.core.hotspot_clients() {
            Ok(list) => list,
            Err(err) => {
                return self.show_message(
                    "Connected Devices",
                    [
                        "Failed to read hotspot leases",
                        &shorten_for_display(&err.to_string(), 90),
                    ],
                );
            }
        };
        for lease in leases {
            let mac = lease.mac.to_lowercase();
            let ip = lease.ip;
            let mut hostname = lease.hostname.unwrap_or_else(|| "Unknown".to_string());
            if hostname.is_empty() {
                hostname = "Unknown".to_string();
            }
            let lease_timestamp = if lease.lease_start > 0 {
                let ts = UNIX_EPOCH + Duration::from_secs(lease.lease_start);
                let dt: chrono::DateTime<Local> = ts.into();
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                "Unknown".to_string()
            };

            // Log to history file only if this MAC hasn't been logged before
            if !logged_devices.contains(&mac) {
                let now = Local::now().format("%Y-%m-%d %H:%M:%S");
                let history_entry = format!(
                    "{} | MAC: {} | IP: {} | Hostname: {} | Lease Timestamp: {}\n",
                    now, mac, ip, hostname, lease_timestamp
                );
                if let Ok(mut file) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&history_path)
                {
                    if let Err(err) = file.write_all(history_entry.as_bytes()) {
                        tracing::warn!("Failed to write hotspot history: {:#}", err);
                    }
                }
                logged_devices.insert(mac.clone());
            }

            // Skip blacklisted devices
            if self
                .config
                .settings
                .hotspot_blacklist
                .iter()
                .any(|d| d.mac.to_lowercase() == mac)
            {
                continue;
            }

            // Only add to display list if currently active
            if active_macs.contains(&mac) {
                clients.push((mac.to_string(), ip.to_string(), hostname.to_string()));
            }
        }

        if clients.is_empty() {
            return self.show_message("Connected Devices", ["No devices currently connected"]);
        }

        // Create list of device summaries
        let device_labels: Vec<String> = clients
            .iter()
            .map(|(mac, ip, hostname)| {
                if hostname == "Unknown" {
                    format!("{} - {}", ip, mac)
                } else {
                    format!("{} - {}", hostname, ip)
                }
            })
            .collect();

        // Let user select a device to see details
        let choice = self.choose_from_list("Connected Devices", &device_labels)?;

        if let Some(idx) = choice {
            if let Some((mac, ip, hostname)) = clients.get(idx) {
                // Show device details first
                let mut details = vec![
                    format!("Device: {}", hostname),
                    format!("MAC: {}", mac),
                    format!("IP: {}", ip),
                    "".to_string(),
                ];

                // Try to get vendor from MAC OUI
                if mac.len() >= 17 {
                    let oui_parts: Vec<&str> = mac.split(':').take(3).collect();
                    if oui_parts.len() == 3 {
                        if let (Ok(b0), Ok(b1), Ok(b2)) = (
                            u8::from_str_radix(oui_parts[0], 16),
                            u8::from_str_radix(oui_parts[1], 16),
                            u8::from_str_radix(oui_parts[2], 16),
                        ) {
                            if let Some(vendor_oui) =
                                rustyjack_evasion::VendorOui::from_oui([b0, b1, b2])
                            {
                                details.push(format!("Vendor: {}", vendor_oui.name));
                            }
                        }
                    }
                }

                self.show_message("Device Details", details.iter().map(|s| s.as_str()))?;

                // Offer options to disconnect or blacklist
                let options = vec![
                    "Add to Blacklist".to_string(),
                    "Disconnect Device".to_string(),
                    "Back".to_string(),
                ];

                let action_choice = self.choose_from_list("Device Actions", &options)?;

                match action_choice {
                    Some(0) => {
                        // Add to blacklist
                        self.add_to_hotspot_blacklist(mac, hostname, ip)?;
                    }
                    Some(1) => {
                        // Disconnect device
                        self.disconnect_hotspot_client(mac, ip)?;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub(crate) fn show_hotspot_network_speed(&mut self, upstream_iface: &str) -> Result<()> {
        if upstream_iface.is_empty() {
            return self.show_message(
                "Network Speed",
                ["No upstream configured", "Hotspot is offline"],
            );
        }

        use std::fs;
        use std::time::{Duration, Instant};

        let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", upstream_iface);
        let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", upstream_iface);

        // Read initial values
        let mut rx_start = fs::read_to_string(&rx_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let mut tx_start = fs::read_to_string(&tx_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let mut last_update = Instant::now();
        let update_interval = Duration::from_secs(2);

        loop {
            // Check for button press first (non-blocking)
            if let Ok(Some(button)) = self.buttons.try_read() {
                match self.map_button(button) {
                    ButtonAction::Select | ButtonAction::Back => break,
                    ButtonAction::Cancel => {}
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                    }
                    _ => {}
                }
            }

            // Update stats if enough time has passed
            if last_update.elapsed() >= update_interval {
                // Read current values
                let rx_end = fs::read_to_string(&rx_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                let tx_end = fs::read_to_string(&tx_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0);

                // Calculate speeds (bytes per second)
                let elapsed_secs = last_update.elapsed().as_secs().max(1);
                let rx_speed = (rx_end.saturating_sub(rx_start)) / elapsed_secs;
                let tx_speed = (tx_end.saturating_sub(tx_start)) / elapsed_secs;

                // Convert to human-readable format
                let rx_display = format_bytes_per_sec(rx_speed);
                let tx_display = format_bytes_per_sec(tx_speed);

                let lines = vec![
                    format!("Interface: {}", upstream_iface),
                    "".to_string(),
                    format!("Download: {}", rx_display),
                    format!("Upload: {}", tx_display),
                    "".to_string(),
                    "Updates every 2 seconds".to_string(),
                    "Press SELECT or LEFT".to_string(),
                ];

                // Draw dialog without blocking
                let status = self.stats.snapshot();
                self.display.draw_dialog(&lines, &status)?;

                // Update for next iteration
                rx_start = rx_end;
                tx_start = tx_end;
                last_update = Instant::now();
            }

            // Small sleep to avoid busy waiting
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    pub(crate) fn manage_hotspot_blacklist(&mut self) -> Result<()> {
        let blacklist = self.config.settings.hotspot_blacklist.clone();

        if blacklist.is_empty() {
            return self.show_message("Device Blacklist", ["No devices blacklisted"]);
        }

        // Create list of blacklisted devices showing name and MAC
        let device_labels: Vec<String> = blacklist
            .iter()
            .map(|device| {
                if device.name == "Unknown" || device.name.is_empty() {
                    device.mac.clone()
                } else {
                    format!("{} - {}", device.name, device.mac)
                }
            })
            .collect();

        let choice = self.choose_from_list("Blacklisted Devices", &device_labels)?;

        if let Some(idx) = choice {
            if let Some(device) = blacklist.get(idx) {
                let details = vec![
                    format!("Device: {}", device.name),
                    format!("MAC: {}", device.mac),
                    format!("IP: {}", device.ip),
                    "".to_string(),
                    "This device is blocked".to_string(),
                    "from connecting to".to_string(),
                    "the hotspot.".to_string(),
                ];

                self.show_message("Blacklisted Device", details.iter().map(|s| s.as_str()))?;

                // Offer to remove from blacklist
                let options = vec!["Remove from Blacklist".to_string(), "Back".to_string()];

                let action = self.choose_from_list("Actions", &options)?;

                if action == Some(0) {
                    self.remove_from_hotspot_blacklist(&device.mac)?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn add_to_hotspot_blacklist(
        &mut self,
        mac: &str,
        hostname: &str,
        ip: &str,
    ) -> Result<()> {
        if self
            .config
            .settings
            .hotspot_blacklist
            .iter()
            .any(|d| d.mac == mac)
        {
            return self.show_message("Blacklist", ["Device already", "in blacklist"]);
        }

        let device = BlacklistedDevice::new(mac.to_string(), hostname.to_string(), ip.to_string());

        self.config.settings.hotspot_blacklist.push(device);
        let config_path = self.root.join("gui_conf.json");
        self.config.save(&config_path)?;

        // Update hotspot blacklist in Rust DHCP server
        self.apply_hotspot_blacklist()?;

        // Disconnect the device immediately
        self.disconnect_hotspot_client(mac, ip)?;

        let msg = if hostname == "Unknown" || hostname.is_empty() {
            let mac_msg = format!("MAC: {}", mac);
            vec![
                "Device added to".to_string(),
                "blacklist and".to_string(),
                "disconnected.".to_string(),
                "".to_string(),
                mac_msg,
            ]
        } else {
            let host_msg = format!("{} added to", hostname);
            let mac_msg = format!("MAC: {}", mac);
            vec![
                host_msg,
                "blacklist and".to_string(),
                "disconnected.".to_string(),
                "".to_string(),
                mac_msg,
            ]
        };

        self.show_message("Blacklist Updated", msg.iter().map(|s| s.as_str()))
    }

    pub(crate) fn remove_from_hotspot_blacklist(&mut self, mac: &str) -> Result<()> {
        self.config
            .settings
            .hotspot_blacklist
            .retain(|d| d.mac != mac);
        let config_path = self.root.join("gui_conf.json");
        self.config.save(&config_path)?;

        // Update hotspot blacklist in Rust DHCP server
        self.apply_hotspot_blacklist()?;

        self.show_message(
            "Blacklist Updated",
            [
                "Device removed from",
                "blacklist.",
                "",
                "It can now connect",
                "to the hotspot.",
            ],
        )
    }

    pub(crate) fn disconnect_hotspot_client(&mut self, mac: &str, _ip: &str) -> Result<()> {
        let args = HotspotDisconnectArgs {
            mac: mac.to_string(),
        };
        if let Err(err) = self
            .core
            .dispatch(Commands::Hotspot(HotspotCommand::DisconnectClient(args)))
        {
            tracing::warn!("Hotspot disconnect failed for {}: {}", mac, err);
            return self.show_message(
                "Disconnect Failed",
                ["Could not disconnect", "device. Check logs."],
            );
        }

        self.show_message(
            "Device Disconnected",
            ["Client has been", "disconnected from", "the hotspot."],
        )
    }

    pub(crate) fn apply_hotspot_blacklist(&mut self) -> Result<()> {
        let macs: Vec<String> = self
            .config
            .settings
            .hotspot_blacklist
            .iter()
            .map(|d| d.mac.clone())
            .collect();

        let args = HotspotBlacklistArgs { macs };
        self.core
            .dispatch(Commands::Hotspot(HotspotCommand::SetBlacklist(args)))
            .context("applying hotspot blacklist")?;

        Ok(())
    }
}
