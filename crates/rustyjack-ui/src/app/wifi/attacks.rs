use std::path::Path;

use anyhow::Result;
use rustyjack_commands::{Commands, SystemCommand, WifiCommand, WifiDeauthArgs};

use crate::util::shorten_for_display;

use super::super::state::{App, INDEFINITE_SECS};

impl App {
    pub(crate) fn scan_wifi_networks(&mut self) -> Result<()> {
        if !self.mode_allows_active("Wi-Fi scanning disabled in Stealth")? {
            return Ok(());
        }
        
        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message(
                "WiFi Scan",
                ["No active interface", "", "Run Hardware Detect first"],
            );
        }
        
        if let Some(error) = self.preflight_wireless_scan(&active_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }
        
        self.show_progress("WiFi Scan", ["Scanning for networks...", "Please wait"])?;

        let scan_result = self.fetch_wifi_scan();

        match scan_result {
            Ok(response) => {
                if response.networks.is_empty() {
                    return self.show_message("WiFi Scan", ["No networks found"]);
                }

                let networks = response.networks;

                loop {
                    // Build labels each loop so target marker updates after set
                    let mut labels = Vec::new();
                    for net in &networks {
                        let ssid = net.ssid.as_deref().unwrap_or("<hidden>");
                        let ssid_display = if ssid.len() > 10 {
                            format!("{}...", &ssid[..10])
                        } else {
                            ssid.to_string()
                        };
                        let signal = net
                            .signal_dbm
                            .map(|s| format!("{}dB", s))
                            .unwrap_or_default();
                        let ch = net.channel.map(|c| format!("c{}", c)).unwrap_or_default();
                        let bssid = net.bssid.as_deref().unwrap_or("");
                        let cur_target_bssid = self.config.settings.target_bssid.as_str();
                        let is_target = (!cur_target_bssid.is_empty() && cur_target_bssid == bssid)
                            || (!self.config.settings.target_network.is_empty()
                                && self.config.settings.target_network == ssid);
                        let target_marker = if is_target { "*" } else { " " };
                        labels.push(format!(
                            "{} {} {} {}",
                            target_marker, ssid_display, signal, ch
                        ));
                    }

                    let choice = self.choose_from_menu("Select Network", &labels)?;
                    let Some(idx) = choice else {
                        break;
                    };
                    let Some(network) = networks.get(idx) else {
                        continue;
                    };
                    if let Some(ssid) = network.ssid.as_deref().filter(|s| !s.is_empty()) {
                        let mut info = vec![format!("SSID: {}", ssid)];
                        if let Some(bssid) = network.bssid.as_deref() {
                            info.push(format!("BSSID: {}", bssid));
                        }
                        if let Some(ch) = network.channel {
                            info.push(format!("Channel: {}", ch));
                        }
                        if let Some(sig) = network.signal_dbm {
                            info.push(format!("Signal: {} dBm", sig));
                        }
                        info.push("".to_string());
                        info.push("Set this as target?".to_string());
                        self.show_message("Network", info.iter().map(|s| s.as_str()))?;

                        let confirm = self.choose_from_list(
                            "Set Target",
                            &["Yes".to_string(), "No".to_string()],
                        )?;
                        if confirm == Some(0) {
                            self.config.settings.target_network = ssid.to_string();
                            self.config.settings.target_bssid =
                                network.bssid.clone().unwrap_or_default();
                            self.config.settings.target_channel =
                                network.channel.unwrap_or(0) as u8;
                            let config_path = self.root.join("gui_conf.json");
                            self.save_config_file(&config_path)?;
                            let mut result_lines = vec![
                                format!("SSID: {}", ssid),
                                format!("Channel: {}", self.config.settings.target_channel),
                            ];
                            if self.config.settings.target_bssid.is_empty() {
                                result_lines.push("BSSID: (none)".to_string());
                                result_lines.push("Note: deauth needs BSSID".to_string());
                            } else {
                                result_lines
                                    .push(format!("BSSID: {}", self.config.settings.target_bssid));
                            }
                            self.show_message(
                                "Target Set",
                                result_lines.iter().map(|s| s.as_str()),
                            )?;
                        }
                    } else {
                        self.show_message("Wi-Fi", ["Hidden SSID - configure via CLI"])?;
                    }
                }
            }
            Err(e) => {
                self.show_message("WiFi Scan Error", [format!("{}", e)])?;
            }
        }

        Ok(())
    }

    pub(crate) fn launch_deauth_attack(&mut self) -> Result<()> {
        if !self.mode_allows_active("Deauth attack blocked in Stealth mode")? {
            return Ok(());
        }
        let active_interface = self.config.settings.active_network_interface.clone();
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;

        if active_interface.is_empty() {
            return self.show_message(
                "Deauth Attack",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if let Some(error) = self.preflight_deauth_attack(&active_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }

        if target_channel == 0 {
            return self.show_message(
                "Deauth Attack",
                [
                    "No target channel set",
                    "Scan networks first",
                    "and select a target",
                ],
            );
        }

        // Duration selection
        let durations = vec![
            "1 minute".to_string(),
            "2 minutes".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Attack Duration", &durations)?;

        let duration_secs: u64 = match dur_choice {
            Some(0) => 60,
            Some(1) => 120,
            Some(2) => 300,
            Some(3) => 600,
            _ => return Ok(()),
        };

        let summary_lines = vec![
            format!(
                "Target: {}",
                if target_network.is_empty() {
                    &target_bssid
                } else {
                    &target_network
                }
            ),
            format!("BSSID: {}", target_bssid),
            format!("Channel: {}", target_channel),
            format!("Interface: {}", active_interface),
            format!("Duration: {}s", duration_secs),
        ];

        if !self.confirm_yes_no_bool("Start Deauth?", &summary_lines)? {
            self.go_home()?;
            return Ok(());
        }

        let cmd = Commands::Wifi(WifiCommand::Deauth(WifiDeauthArgs {
            bssid: target_bssid.clone(),
            ssid: if target_network.is_empty() {
                None
            } else {
                Some(target_network.clone())
            },
            interface: active_interface.clone(),
            channel: target_channel,
            duration: duration_secs as u32,
            packets: 64,
            client: None,
            continuous: true,
            interval: 1,
        }));

        let result = self.dispatch_cancellable("Deauth", cmd, duration_secs)?;
        let Some((msg, data)) = result else {
            return Ok(());
        };

        let mut result_lines = vec![msg];

                if let Some(captured) = data.get("handshake_captured").and_then(|v| v.as_bool()) {
                    if captured {
                        result_lines.push("HANDSHAKE CAPTURED!".to_string());
                        if let Some(hf) = data.get("handshake_file").and_then(|v| v.as_str()) {
                            result_lines.push(format!(
                                "File: {}",
                                Path::new(hf)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("handshake.cap")
                            ));
                        }
                    } else {
                        result_lines.push("No handshake detected".to_string());
                    }
                }

                if let Some(packets) = data.get("total_packets_sent").and_then(|v| v.as_u64()) {
                    result_lines.push(format!("Packets: {}", packets));
                }

                if let Some(bursts) = data.get("deauth_bursts").and_then(|v| v.as_u64()) {
                    result_lines.push(format!("Bursts: {}", bursts));
                }

                if let Some(log) = data.get("log_file").and_then(|v| v.as_str()) {
                    result_lines.push(format!(
                        "Log: {}",
                        Path::new(log)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("log.txt")
                    ));
                }

                result_lines.push("Check Loot > Wireless".to_string());

        self.show_message("Deauth Complete", result_lines.iter().map(|s| s.as_str()))?;
        self.go_home()?;

        Ok(())
    }

    pub(crate) fn connect_known_network(&mut self) -> Result<()> {
        // Fetch saved WiFi profiles
        let profiles = match self.fetch_wifi_profiles() {
            Ok(p) => p,
            Err(e) => {
                return self.show_message(
                    "Connect",
                    ["Failed to load profiles", "", &format!("{}", e)],
                );
            }
        };

        if profiles.is_empty() {
            return self.show_message(
                "Connect",
                [
                    "No saved profiles",
                    "",
                    "Profiles are stored in",
                    "wifi/profiles/*.json",
                    "",
                    "Or scan networks and",
                    "save credentials",
                ],
            );
        }

        // Offer import from USB + saved profiles
        let mut options = vec!["Import from USB".to_string()];
        let profile_names: Vec<String> = profiles.iter().map(|p| p.ssid.clone()).collect();
        options.extend(profile_names.clone());

        if options.len() == 1 {
            // No profiles and user declined import
            if let Some(choice) = self.choose_from_list(
                "No profiles found",
                &["Import from USB".to_string(), "Cancel".to_string()],
            )? {
                if choice == 0 {
                    self.import_wifi_from_usb()?;
                }
            }
            return Ok(());
        }

        // Let user select a profile
        let choice = self.choose_from_list("Select Network", &options)?;

        let Some(idx) = choice else {
            return Ok(());
        };

        if idx == 0 {
            self.import_wifi_from_usb()?;
            return Ok(());
        }

        let selected = &profiles[idx - 1];
        self.connect_named_profile(&selected.ssid)?;

        Ok(())
    }

    pub(crate) fn launch_evil_twin(&mut self) -> Result<()> {
        if !self.mode_allows_active("Evil Twin blocked in Stealth mode")? {
            return Ok(());
        }
        // Check if we have a target set
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let mut attack_interface = self.config.settings.active_network_interface.clone();

        if target_network.is_empty() || target_bssid.is_empty() {
            return self.show_message(
                "Evil Twin",
                [
                    "No target network set",
                    "",
                    "First scan networks and",
                    "select 'Set as Target'",
                ],
            );
        }

        if attack_interface.is_empty() {
            // Let user pick a wireless interface if none set
            if let Some(choice) = self.choose_wifi_interface("Pick WiFi interface")? {
                attack_interface = choice;
                self.config.settings.active_network_interface = attack_interface.clone();
                let config_path = self.root.join("gui_conf.json");
                self.save_config_file(&config_path)?;
            } else {
                return Ok(());
            }
        }

        // Ensure the daemon strict-isolation preference matches the selected interface.
        self.show_progress(
            "Preparing Evil Twin",
            [
                &format!("Selecting interface: {}", attack_interface),
                "Applying strict isolation...",
                "Please wait",
            ],
        )?;
        if let Err(e) = self.core.set_active_interface(&attack_interface) {
            return self.show_preflight_error(
                "Interface Select Failed",
                &format!("Failed to set active interface in daemon: {}", e),
            );
        }

        if let Some(error) = self.preflight_evil_twin(&attack_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }

        // Duration selection
        let durations = vec![
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "15 minutes".to_string(),
            "30 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Attack Duration", &durations)?;

        let duration_secs = match dur_choice {
            Some(0) => 300,
            Some(1) => 600,
            Some(2) => 900,
            Some(3) => 1800,
            _ => return Ok(()),
        };

        // Show attack configuration
        self.show_message(
            "Evil Twin Attack",
            [
                &format!("SSID: {}", target_network),
                &format!("Ch: {} Iface: {}", target_channel, attack_interface),
                &format!("Duration: {} min", duration_secs / 60),
                "",
                "Creates fake AP with same",
                "SSID to capture client",
                "credentials.",
                "",
                "Press SELECT to start",
            ],
        )?;

        // Confirm start
        let options = vec!["Start Attack".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Confirm", &options)?;

        if choice != Some(0) {
            return Ok(());
        }

        // Execute evil twin via core with cancel support
        use rustyjack_commands::{Commands, WifiCommand, WifiEvilTwinArgs};

        let cmd = Commands::Wifi(WifiCommand::EvilTwin(WifiEvilTwinArgs {
            ssid: target_network.clone(),
            target_bssid: Some(target_bssid),
            channel: target_channel,
            interface: attack_interface.clone(),
            duration: duration_secs as u32,
            open: true,
        }));

        let result = self.dispatch_cancellable("Evil Twin", cmd, duration_secs)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = Vec::new();

        // Check status
        let status = data
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status == "completed" {
            lines.push("Attack Complete".to_string());
        } else if status == "failed" {
            lines.push("Attack Failed".to_string());
            lines.push(msg);
        } else {
            lines.push(msg);
        }

        // Show stats
        if let Some(duration) = data.get("attack_duration_secs").and_then(|v| v.as_u64()) {
            let mins = duration / 60;
            let secs = duration % 60;
            lines.push(format!("Duration: {}m {}s", mins, secs));
        }

        if let Some(clients) = data.get("clients_connected").and_then(|v| v.as_u64()) {
            lines.push(format!("Clients: {}", clients));
        }
        if let Some(hs) = data.get("handshakes_captured").and_then(|v| v.as_u64()) {
            lines.push(format!("Handshakes: {}", hs));
        }
        if let Some(creds) = data.get("credentials_captured").and_then(|v| v.as_u64()) {
            lines.push(format!("Creds: {}", creds));
        }

        // Show loot location
        if let Some(dir) = data.get("loot_directory").and_then(|v| v.as_str()) {
            let short_dir = dir.split('/').last().unwrap_or(dir);
            lines.push(format!("Loot: {}", short_dir));
        }

        self.show_message("Evil Twin", lines.iter().map(|s| s.as_str()))?;

        Ok(())
    }

    pub(crate) fn launch_probe_sniff(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Probe Sniff",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if let Some(error) = self.preflight_probe_sniff(&active_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }

        // Duration selection
        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        let dur_choice = self.choose_from_list("Sniff Duration", &durations)?;

        let duration_secs = match dur_choice {
            Some(0) => 30,
            Some(1) => 60,
            Some(2) => 300,
            Some(3) => INDEFINITE_SECS,
            _ => return Ok(()),
        };

        let duration_label = if duration_secs == INDEFINITE_SECS {
            "Indefinite".to_string()
        } else {
            format!("{}s", duration_secs)
        };
        let confirm_lines = vec![
            format!("Interface: {}", active_interface),
            format!("Duration: {}", duration_label),
            "KEY2 cancels while running".to_string(),
        ];
        if !self.confirm_yes_no_bool("Start Probe Sniff?", &confirm_lines)? {
            self.go_home()?;
            return Ok(());
        }

        use rustyjack_commands::{Commands, WifiCommand, WifiProbeSniffArgs};

        let cmd = Commands::Wifi(WifiCommand::ProbeSniff(WifiProbeSniffArgs {
            interface: active_interface,
            duration: duration_secs,
            channel: 0, // hop channels
        }));

        let result = self.dispatch_cancellable("Probe Sniff", cmd, duration_secs as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = vec![msg];

        if let Some(probes) = data.get("total_probes").and_then(|v| v.as_u64()) {
            lines.push(format!("Probes: {}", probes));
        }
        if let Some(clients) = data.get("unique_clients").and_then(|v| v.as_u64()) {
            lines.push(format!("Clients: {}", clients));
        }
        if let Some(networks) = data.get("unique_networks").and_then(|v| v.as_u64()) {
            lines.push(format!("Networks: {}", networks));
        }

        // Show top probed networks
        if let Some(top) = data.get("top_networks").and_then(|v| v.as_array()) {
            lines.push("".to_string());
            lines.push("Top Networks:".to_string());
            for net in top.iter().take(3) {
                if let Some(ssid) = net.get("ssid").and_then(|v| v.as_str()) {
                    let count = net.get("probe_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    lines.push(format!("  {} ({})", ssid, count));
                }
            }
        }

        self.show_message("Probe Sniff Done", lines.iter().map(|s| s.as_str()))?;
        self.go_home()?;

        Ok(())
    }

    pub(crate) fn launch_pmkid_capture(&mut self) -> Result<()> {
        if !self.mode_allows_active("PMKID capture blocked in Stealth mode")? {
            return Ok(());
        }
        let target_network = self.config.settings.target_network.clone();
        let target_bssid = self.config.settings.target_bssid.clone();
        let target_channel = self.config.settings.target_channel;
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "PMKID Capture",
                ["No WiFi interface set", "", "Run Hardware Detect first"],
            );
        }

        if let Some(error) = self.preflight_pmkid_capture(&active_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }

        // Option to target specific network or passive capture
        let options = vec![
            if target_network.is_empty() {
                "Passive Capture".to_string()
            } else {
                format!("Target: {}", target_network)
            },
            "Passive (any network)".to_string(),
            "Indefinite (manual stop)".to_string(),
            "Cancel".to_string(),
        ];

        let choice = self.choose_from_menu("PMKID Mode", &options)?;

        let (use_target, duration) = match choice {
            Some(0) if !target_network.is_empty() => (true, 30),
            Some(1) | Some(0) => (false, 60),
            Some(2) => (false, INDEFINITE_SECS),
            _ => return Ok(()),
        };

        let duration_label = if duration == INDEFINITE_SECS {
            "Indefinite".to_string()
        } else {
            format!("{}s", duration)
        };
        let target_label = if use_target {
            format!("Target: {}", target_network)
        } else {
            "Target: Any".to_string()
        };
        let confirm_lines = vec![
            target_label,
            format!("Interface: {}", active_interface),
            format!("Duration: {}", duration_label),
            "KEY2 cancels while running".to_string(),
        ];
        if !self.confirm_yes_no_bool("Start PMKID?", &confirm_lines)? {
            self.go_home()?;
            return Ok(());
        }

        use rustyjack_commands::{Commands, WifiCommand, WifiPmkidArgs};

        let cmd = Commands::Wifi(WifiCommand::PmkidCapture(WifiPmkidArgs {
            interface: active_interface,
            bssid: if use_target { Some(target_bssid) } else { None },
            ssid: if use_target {
                Some(target_network)
            } else {
                None
            },
            channel: if use_target { target_channel } else { 0 },
            duration,
        }));

        let result = self.dispatch_cancellable("PMKID Capture", cmd, duration as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = vec![msg];

        if let Some(count) = data.get("pmkids_captured").and_then(|v| v.as_u64()) {
            if count > 0 {
                lines.push(format!("Captured: {} PMKIDs", count));
                lines.push("".to_string());
                lines.push("Auto-cracking...".to_string());

                // If PMKID was captured, trigger auto-crack
                if let Some(_hashcat) = data.get("hashcat_format").and_then(|v| v.as_str()) {
                    lines.push("Hash saved for cracking".to_string());
                }
            } else {
                lines.push("No PMKIDs found".to_string());
                lines.push("Try different network".to_string());
            }
        }

        self.show_message("PMKID Result", lines.iter().map(|s| s.as_str()))?;
        self.go_home()?;

        Ok(())
    }

    pub(crate) fn install_wifi_drivers(&mut self) -> Result<()> {
        let script_path = self.root.join("scripts/wifi_driver_installer.sh");

        // Check if script exists
        if !script_path.exists() {
            return self.show_message(
                "Driver Install",
                [
                    "Installer script not found",
                    "",
                    "Missing:",
                    "scripts/wifi_driver_installer.sh",
                    "",
                    "Please reinstall RustyJack",
                ],
            );
        }

        // Initial screen - explain what we're doing
        self.show_message(
            "WiFi Driver Install",
            [
                "This will scan for USB WiFi",
                "adapters and install any",
                "required drivers.",
                "",
                "Internet required for",
                "driver downloads.",
                "",
                "Press SELECT to continue",
            ],
        )?;

        // Confirm
        let options = vec!["Start Scan".to_string(), "Cancel".to_string()];
        let choice = self.choose_from_list("Install Drivers?", &options)?;

        if choice != Some(0) {
            return Ok(());
        }

        self.show_progress("WiFi Driver", ["Running installer...", "Please wait"])?;

        let (msg, data) = match self
            .core
            .dispatch(Commands::System(SystemCommand::InstallWifiDrivers))
        {
            Ok(result) => result,
            Err(e) => {
                let err_text = e.to_string();
                if err_text.contains("driver install disabled")
                    || err_text.contains("external scripts removed")
                {
                    return self.show_message(
                        "Driver Install",
                        [
                            "Feature disabled",
                            "Rust-only build",
                            "",
                            "No Rust installer yet",
                        ],
                    );
                }
                return self.show_message(
                    "Driver Error",
                    ["Installer failed", "", &shorten_for_display(&err_text, 90)],
                );
            }
        };

        let status = data
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        let details = data.get("details").and_then(|v| v.as_str()).unwrap_or("");
        let interfaces = data.get("interfaces").and_then(|v| v.as_array());

        match status {
            "SUCCESS" => {
                let mut lines = vec!["Driver installed!".to_string(), "".to_string()];
                if let Some(ifaces) = interfaces {
                    lines.push("Available interfaces:".to_string());
                    for iface in ifaces {
                        if let Some(name) = iface.as_str() {
                            lines.push(format!("  - {}", name));
                        }
                    }
                }
                lines.push("".to_string());
                lines.push("Ready to use!".to_string());
                self.show_message("Driver Success", lines.iter().map(|s| s.as_str()))
            }
            "REBOOT_REQUIRED" => self.show_message(
                "Reboot Required",
                [
                    "Driver installed but",
                    "reboot is required.",
                    "",
                    "Please restart the",
                    "device to complete",
                    "installation.",
                    "",
                    "Press KEY3 to reboot",
                ],
            ),
            "NO_DEVICES" => self.show_message(
                "No Devices",
                [
                    "No USB WiFi adapters",
                    "were detected.",
                    "",
                    "Please plug in a USB",
                    "WiFi adapter and try",
                    "again.",
                ],
            ),
            "FAILED" => self.show_message(
                "Driver Failed",
                [
                    "Failed to install drivers",
                    "",
                    details,
                    "",
                    "Check internet connection",
                    "and try again.",
                    "",
                    "Some adapters may not",
                    "be supported.",
                ],
            ),
            _ => self.show_message("Driver Install", vec![msg, details.to_string()]),
        }
    }

    /// Launch Karma attack
    pub(crate) fn launch_karma_attack(&mut self) -> Result<()> {
        if !self.mode_allows_active("Karma attack blocked in Stealth mode")? {
            return Ok(());
        }
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Karma Attack",
                [
                    "No WiFi interface set",
                    "",
                    "Run Hardware Detect",
                    "to configure interface",
                ],
            );
        }

        if let Some(error) = self.preflight_karma(&active_interface)? {
            return self.show_preflight_error("Preflight Failed", &error);
        }

        // Explain what Karma does
        self.show_message(
            "Karma Attack",
            [
                "Responds to ALL probe",
                "requests from devices.",
                "",
                "Captures clients looking",
                "for known networks.",
                "",
                "Very effective against",
                "phones and laptops!",
                "",
                "Press SELECT to start",
            ],
        )?;

        // Duration selection
        let durations = vec![
            "2 minutes".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
            "Indefinite".to_string(),
        ];
        let dur_choice = self.choose_from_list("Karma Duration", &durations)?;

        let duration = match dur_choice {
            Some(0) => 120,
            Some(1) => 300,
            Some(2) => 600,
            Some(3) => INDEFINITE_SECS,
            _ => return Ok(()),
        };

        if duration == INDEFINITE_SECS {
            self.show_message(
                "Karma Attack",
                [
                    "Running indefinitely.",
                    "Press KEY2",
                    "to stop. Elapsed shown.",
                ],
            )?;
        }

        // Ask if they want to create a fake AP
        let ap_options = vec![
            "Passive (sniff only)".to_string(),
            "Active (create fake AP)".to_string(),
            "Cancel".to_string(),
        ];
        let ap_choice = self.choose_from_menu("Karma Mode", &ap_options)?;

        let with_ap = match ap_choice {
            Some(0) => false,
            Some(1) => true,
            _ => return Ok(()),
        };

        // Execute via core with cancel support
        use rustyjack_commands::{Commands, WifiCommand, WifiKarmaArgs};

        let cmd = Commands::Wifi(WifiCommand::Karma(WifiKarmaArgs {
            interface: active_interface.clone(),
            ap_interface: if with_ap {
                Some(active_interface.clone())
            } else {
                None
            },
            duration,
            channel: 0, // hop channels
            with_ap,
            ssid_whitelist: None,
            ssid_blacklist: None,
        }));

        let result = self.dispatch_cancellable("Karma Attack", cmd, duration as u64)?;

        let Some((msg, data)) = result else {
            return Ok(()); // Cancelled
        };

        let mut lines = vec![msg];

        if let Some(probes) = data.get("probes_seen").and_then(|v| v.as_u64()) {
            lines.push(format!("Probes: {}", probes));
        }
        if let Some(ssids) = data.get("unique_ssids").and_then(|v| v.as_u64()) {
            lines.push(format!("SSIDs: {}", ssids));
        }
        if let Some(clients) = data.get("unique_clients").and_then(|v| v.as_u64()) {
            lines.push(format!("Clients: {}", clients));
        }
        if let Some(victims) = data.get("victims").and_then(|v| v.as_u64()) {
            if victims > 0 {
                lines.push(format!("Victims: {}", victims));
            }
        }

        self.show_message("Karma Done", lines.iter().map(|s| s.as_str()))?;

        Ok(())
    }

}
