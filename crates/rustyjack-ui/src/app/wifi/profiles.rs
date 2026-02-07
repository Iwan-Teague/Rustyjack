use anyhow::{bail, Result};
use rustyjack_commands::{
    Commands, WifiCommand, WifiProfileCommand, WifiProfileConnectArgs, WifiProfileDeleteArgs,
    WifiProfileSaveArgs, WifiProfileShowArgs, WifiRouteCommand, WifiStatusArgs,
};
use rustyjack_encryption::clear_encryption_key;

use crate::{
    types::{
        InterfaceSummary, RouteSnapshot, WifiListResponse, WifiNetworkEntry, WifiProfileSummary,
        WifiProfilesResponse, WifiScanResponse, WifiStatusOverview,
    },
    util::shorten_for_display,
};

use super::super::state::App;

impl App {
    #[allow(dead_code)]
    pub(crate) fn handle_network_selection(&mut self, network: &WifiNetworkEntry) -> Result<()> {
        let Some(ssid) = network
            .ssid
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        else {
            self.show_message("Wi-Fi", ["Hidden SSID - configure via CLI"])?;
            return Ok(());
        };
        let mut details = vec![format!("SSID: {ssid}")];
        if let Some(signal) = network.signal_dbm {
            details.push(format!("Signal: {signal} dBm"));
        }
        if let Some(channel) = network.channel {
            details.push(format!("Channel: {channel}"));
        }
        if let Some(bssid) = network.bssid.as_deref() {
            details.push(format!("BSSID: {bssid}"));
        }
        details.push(if network.encrypted {
            "Encrypted: yes".to_string()
        } else {
            "Encrypted: no".to_string()
        });
        self.show_message("Network", details.iter().map(|s| s.as_str()))?;

        let actions = vec![
            "Connect".to_string(),
            "Set Target".to_string(),
            "Back".to_string(),
        ];
        if let Some(choice) = self.choose_from_list("Network action", &actions)? {
            match choice {
                0 => {
                    // Connect
                    if self.connect_profile_by_ssid(&ssid)? {
                        // message handled in helper
                    } else {
                        let msg = vec![format!("No saved profile for {ssid}")];
                        self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
                    }
                }
                1 => {
                    // Set as Target for deauth attack. We will accept a target even
                    // if the network record omits the BSSID. When BSSID is missing
                    // we store an empty string — deauth attacks require a BSSID and
                    // will error later if it's absent, so the UI warns the user.
                    self.config.settings.target_network = ssid.clone();
                    self.config.settings.target_bssid = network.bssid.clone().unwrap_or_default();
                    self.config.settings.target_channel = network.channel.unwrap_or(0) as u8;

                    // Save config
                    let config_path = self.root.join("gui_conf.json");
                    if let Err(e) = self.config.save(&config_path) {
                        self.show_message("Error", [format!("Failed to save: {}", e)])?;
                    } else {
                        // Informative feedback — highlight missing BSSID if applicable
                        if self.config.settings.target_bssid.is_empty() {
                            self.show_message(
                                "Target Set",
                                [
                                    &format!("SSID: {}", ssid),
                                    "BSSID: (none)",
                                    &format!("Channel: {}", self.config.settings.target_channel),
                                    "",
                                    "Note: target has no BSSID. Deauth requires a BSSID",
                                ],
                            )?;
                        } else {
                            self.show_message(
                                "Target Set",
                                [
                                    &format!("SSID: {}", ssid),
                                    &format!("BSSID: {}", self.config.settings.target_bssid),
                                    &format!("Channel: {}", self.config.settings.target_channel),
                                    "",
                                    "Ready for Deauth Attack",
                                ],
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn handle_profile_selection(&mut self, profile: &WifiProfileSummary) -> Result<()> {
        let actions = vec![
            "Connect".to_string(),
            "Delete".to_string(),
            "Back".to_string(),
        ];
        if let Some(choice) =
            self.choose_from_list(&format!("Profile {}", profile.ssid), &actions)?
        {
            match choice {
                0 => self.connect_named_profile(&profile.ssid)?,
                1 => self.delete_profile(&profile.ssid)?,
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn fetch_wifi_scan(&mut self) -> Result<WifiScanResponse> {
        let interface = if !self.config.settings.active_network_interface.is_empty() {
            self.config.settings.active_network_interface.clone()
        } else {
            bail!("No active interface set");
        };

        let data = self.core.wifi_scan(&interface, 30000)?;
        let mut resp: WifiScanResponse = serde_json::from_value(data)?;
        if resp.count == 0 && !resp.networks.is_empty() {
            resp.count = resp.networks.len();
        }
        Ok(resp)
    }

    pub(crate) fn fetch_wifi_profiles(&mut self) -> Result<Vec<WifiProfileSummary>> {
        let used_key = self.ensure_wifi_key_loaded();
        let result = (|| {
            if self.wifi_encryption_active() && !used_key {
                bail!("Encryption key unavailable for Wi-Fi profiles");
            }
            let (_, data) = self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::List,
            )))?;
            let resp: WifiProfilesResponse = serde_json::from_value(data)?;
            Ok(resp.profiles)
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }

    pub(crate) fn manage_saved_networks(&mut self) -> Result<()> {
        let profiles = match self.fetch_wifi_profiles() {
            Ok(p) => p,
            Err(e) => {
                return self.show_message(
                    "Saved Networks",
                    [
                        "Failed to load profiles",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };

        if profiles.is_empty() {
            return self.show_message("Saved Networks", ["No saved profiles found"]);
        }

        let names: Vec<String> = profiles.iter().map(|p| p.ssid.clone()).collect();
        let Some(choice) = self.choose_from_list("Saved Networks", &names)? else {
            return Ok(());
        };
        let profile = &profiles[choice];

        let actions = vec![
            "View Password".to_string(),
            "Attempt Connection".to_string(),
            "Delete Profile".to_string(),
            "Back".to_string(),
        ];
        if let Some(action) =
            self.choose_from_list(&format!("Profile: {}", profile.ssid), &actions)?
        {
            match action {
                0 => self.view_profile_password(&profile.ssid)?,
                1 => self.attempt_profile_connection(&profile.ssid)?,
                2 => self.delete_profile(&profile.ssid)?,
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn view_profile_password(&mut self, ssid: &str) -> Result<()> {
        let used_key = self.ensure_wifi_key_loaded();
        let result = (|| {
            if self.wifi_encryption_active() && !used_key {
                return Ok(());
            }

            let (_, data) = match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::Show(WifiProfileShowArgs {
                    ssid: ssid.to_string(),
                }),
            ))) {
                Ok(res) => res,
                Err(e) => {
                    return self.show_message(
                        "Saved Networks",
                        [
                            "Failed to load profile",
                            &shorten_for_display(&e.to_string(), 90),
                        ],
                    );
                }
            };

            let pwd = data
                .get("password")
                .and_then(|value| value.as_str())
                .unwrap_or("<no password>");

            self.show_message(
                "WiFi Password",
                [format!("SSID: {ssid}"), format!("Password: {pwd}")],
            )
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }

    pub(crate) fn ensure_wifi_key_loaded(&mut self) -> bool {
        if !self.wifi_encryption_active() {
            return false;
        }
        if !self.ensure_keyfile_available() {
            return false;
        }
        true
    }

    pub(crate) fn attempt_profile_connection(&mut self, ssid: &str) -> Result<()> {
        let used_key = self.ensure_wifi_key_loaded();
        let result = (|| {
            if self.wifi_encryption_active() && !used_key {
                return Ok(());
            }
            self.apply_identity_hardening(Some(ssid));
            // Scan to see if network is present
            let scan = self.fetch_wifi_scan().ok();
            let found = scan.as_ref().and_then(|resp| {
                resp.networks
                    .iter()
                    .find(|n| n.ssid.as_deref().map(|s| s.eq_ignore_ascii_case(ssid)) == Some(true))
            });

            // Attempt connection regardless; inform user of presence.
            let msg_presence = match found {
                Some(_) => "Network found in scan",
                None => "Network NOT seen in scan",
            };

            let interface = if !self.config.settings.active_network_interface.is_empty() {
                Some(self.config.settings.active_network_interface.clone())
            } else {
                None
            };
            let args = WifiProfileConnectArgs {
                profile: Some(ssid.to_string()),
                ssid: None,
                password: None,
                interface,
                remember: false,
            };

            match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::Connect(args),
            ))) {
                Ok(_) => self.show_message(
                    "Connect",
                    [
                        format!("Attempted connect to {ssid}"),
                        msg_presence.to_string(),
                        "Check Wi-Fi status for result".to_string(),
                    ],
                ),
                Err(e) => self.show_message(
                    "Connect",
                    [
                        format!("Failed to connect to {ssid}"),
                        msg_presence.to_string(),
                        shorten_for_display(&e.to_string(), 90),
                    ],
                ),
            }
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }

    #[allow(dead_code)]
    pub(crate) fn fetch_wifi_interfaces(&mut self) -> Result<Vec<InterfaceSummary>> {
        let (_, data) = self.core.dispatch(Commands::Wifi(WifiCommand::List))?;
        let resp: WifiListResponse = serde_json::from_value(data)?;
        Ok(resp.interfaces)
    }

    pub(crate) fn fetch_route_snapshot(&mut self) -> Result<RouteSnapshot> {
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Route(WifiRouteCommand::Status)))?;
        let resp: RouteSnapshot = serde_json::from_value(data)?;
        Ok(resp)
    }

    pub(crate) fn fetch_wifi_status(
        &mut self,
        interface: Option<String>,
    ) -> Result<WifiStatusOverview> {
        let args = WifiStatusArgs { interface };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::Status(args)))?;
        let status: WifiStatusOverview = serde_json::from_value(data)?;
        Ok(status)
    }

    #[allow(dead_code)]
    pub(crate) fn connect_profile_by_ssid(&mut self, ssid: &str) -> Result<bool> {
        let profiles = self.fetch_wifi_profiles()?;
        if !profiles.iter().any(|profile| profile.ssid == ssid) {
            return Ok(false);
        }
        self.connect_named_profile(ssid)?;
        Ok(true)
    }

    pub(crate) fn connect_named_profile(&mut self, ssid: &str) -> Result<()> {
        let used_key = self.ensure_wifi_key_loaded();
        if self.wifi_encryption_active() && !used_key {
            return Ok(());
        }
        let result = (|| {
            self.apply_identity_hardening(Some(ssid));
            self.show_progress("Wi-Fi", ["Connecting...", ssid, "Please wait"])?;

            let interface = if !self.config.settings.active_network_interface.is_empty() {
                Some(self.config.settings.active_network_interface.clone())
            } else {
                None
            };
            let args = WifiProfileConnectArgs {
                profile: Some(ssid.to_string()),
                ssid: None,
                password: None,
                interface,
                remember: false,
            };

            match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::Connect(args),
            ))) {
                Ok(_) => {
                    let msg = vec![format!("Connected to {ssid}")];
                    self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
                }
                Err(err) => {
                    let msg = vec![format!("Connection failed:"), format!("{err}")];
                    self.show_message("Wi-Fi error", msg.iter().map(|s| s.as_str()))?;
                }
            }
            Ok(())
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }

    pub(crate) fn delete_profile(&mut self, ssid: &str) -> Result<()> {
        let used_key = self.ensure_wifi_key_loaded();
        if self.wifi_encryption_active() && !used_key {
            return Ok(());
        }
        let result = (|| {
            let args = WifiProfileDeleteArgs {
                ssid: ssid.to_string(),
            };
            match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::Delete(args),
            ))) {
                Ok(_) => {
                    let msg = vec![format!("Deleted {ssid}")];
                    self.show_message("Wi-Fi", msg.iter().map(|s| s.as_str()))?;
                }
                Err(err) => {
                    let msg = vec![format!("{err}")];
                    self.show_message("Wi-Fi error", msg.iter().map(|s| s.as_str()))?;
                }
            }
            Ok(())
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }

    pub(crate) fn import_wifi_from_usb(&mut self) -> Result<()> {
        let Some(file_path) = self.browse_usb_for_file("WiFi from USB", Some(&["txt"]))? else {
            return Ok(());
        };

        let content = match std::fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                return self.show_message(
                    "Wi-Fi Import",
                    [
                        "Failed to read file",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                );
            }
        };

        let mut lines = content.lines();
        let ssid = lines.next().unwrap_or("").trim().to_string();
        let password = lines.next().unwrap_or("").trim().to_string();

        if ssid.is_empty() {
            return self.show_message("Wi-Fi Import", ["SSID missing on first line"]);
        }

        let used_key = self.ensure_wifi_key_loaded();
        if self.wifi_encryption_active() && !used_key {
            return Ok(());
        }

        let result = (|| {
            // Check if profile exists for messaging
            let profiles = self.fetch_wifi_profiles().unwrap_or_default();
            let existed = profiles.iter().any(|p| p.ssid.eq_ignore_ascii_case(&ssid));

            let args = WifiProfileSaveArgs {
                ssid: ssid.clone(),
                password: password.clone(),
                interface: "auto".to_string(),
                priority: 1,
                auto_connect: Some(true),
            };

            match self.core.dispatch(Commands::Wifi(WifiCommand::Profile(
                WifiProfileCommand::Save(args),
            ))) {
                Ok(_) => {
                    let mut msg = vec![format!(
                        "{} profile {}",
                        if existed { "Updated" } else { "Saved" },
                        ssid
                    )];
                    if password.is_empty() {
                        msg.push("No password provided (open network)".to_string());
                    }
                    msg.push("Stored under wifi/profiles".to_string());
                    self.show_message("Wi-Fi Import", msg.iter().map(|s| s.as_str()))
                }
                Err(e) => self.show_message(
                    "Wi-Fi Import",
                    [
                        "Failed to save profile",
                        &shorten_for_display(&e.to_string(), 90),
                    ],
                ),
            }
        })();
        if used_key {
            clear_encryption_key();
        }
        result
    }
}
