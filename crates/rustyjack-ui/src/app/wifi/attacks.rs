use anyhow::Result;

use super::super::state::App;

impl App {
    pub(crate) fn scan_wifi_networks(&mut self) -> Result<()> {
        if !self.mode_allows_active("Wi-Fi scanning disabled in Stealth")? {
            return Ok(());
        }

        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message(
                "WiFi Scan",
                ["No active interface", "", "Run Hardware Sanity Check first"],
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

}
