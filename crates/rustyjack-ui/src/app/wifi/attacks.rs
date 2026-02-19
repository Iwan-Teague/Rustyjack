use std::time::Duration;

use anyhow::Result;

use crate::input::Button;
use crate::types::WifiNetworkEntry;
use crate::util::shorten_for_display;

use super::super::state::App;

const WIFI_PASSWORD_MAX_LEN: usize = 30;
// Leading space lets Up/Down wrap across a blank quickly; keep the set short for LCD scrolling.
const WIFI_PASSWORD_CHARSET: &str = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";

impl App {
    pub(crate) fn scan_wifi_networks(&mut self) -> Result<()> {
        if !self.mode_allows_active("Wi-Fi scanning disabled in Stealth")? {
            return Ok(());
        }

        let active_interface = self.config.settings.active_network_interface.clone();
        if active_interface.is_empty() {
            return self.show_message(
                "WiFi Scan",
                ["No active interface", "", "Run Network Interfaces first"],
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
                        info.push("Choose an action".to_string());
                        self.show_message("Network", info.iter().map(|s| s.as_str()))?;

                        let actions = vec![
                            "Set as target".to_string(),
                            "Enter password & connect".to_string(),
                            "Cancel".to_string(),
                        ];
                        match self.choose_from_list("Action", &actions)? {
                            Some(0) => {
                                self.set_wifi_target(network, ssid);
                            }
                            Some(1) => {
                                self.set_wifi_target(network, ssid);
                                self.connect_wifi_with_password(
                                    ssid,
                                    network.bssid.clone(),
                                    network.channel.map(|c| c as u8),
                                )?;
                            }
                            _ => {}
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

    fn set_wifi_target(&mut self, network: &WifiNetworkEntry, ssid: &str) {
        self.config.settings.target_network = ssid.to_string();
        self.config.settings.target_bssid = network.bssid.clone().unwrap_or_default();
        self.config.settings.target_channel = network.channel.unwrap_or(0) as u8;
        let _ = self.save_config_file(&self.root.join("gui_conf.json"));

        let mut result_lines = vec![
            format!("SSID: {}", ssid),
            format!("Channel: {}", self.config.settings.target_channel),
        ];
        if self.config.settings.target_bssid.is_empty() {
            result_lines.push("BSSID: (none)".to_string());
            result_lines.push("Note: deauth needs BSSID".to_string());
        } else {
            result_lines.push(format!("BSSID: {}", self.config.settings.target_bssid));
        }
        let _ = self.show_message("Target Set", result_lines.iter().map(|s| s.as_str()));
    }

    fn connect_wifi_with_password(
        &mut self,
        ssid: &str,
        bssid: Option<String>,
        channel: Option<u8>,
    ) -> Result<()> {
        if !self.mode_allows_active("Wi-Fi connect disabled in Stealth")? {
            return Ok(());
        }

        let active_iface = if self.config.settings.active_network_interface.is_empty() {
            self.show_message(
                "Wi-Fi",
                ["No active interface", "", "Run Network Interfaces first"],
            )?;
            return Ok(());
        } else {
            self.config.settings.active_network_interface.clone()
        };

        if let Some(ch) = channel {
            self.config.settings.target_channel = ch;
        }
        if let Some(b) = bssid {
            self.config.settings.target_bssid = b;
        }

        let Some(password) = self.prompt_wifi_password(ssid)? else {
            return Ok(());
        };

        self.show_progress("Wi-Fi", ["Connecting...", ssid, "Please wait"])?;

        let args = rustyjack_commands::WifiProfileConnectArgs {
            profile: None,
            ssid: Some(ssid.to_string()),
            password: Some(password),
            interface: Some(active_iface),
            remember: true,
        };

        match self.core.dispatch(rustyjack_commands::Commands::Wifi(
            rustyjack_commands::WifiCommand::Profile(
                rustyjack_commands::WifiProfileCommand::Connect(args),
            ),
        )) {
            Ok(_) => {
                self.show_message("Wi-Fi", [format!("Connected to {}", ssid)])?;
            }
            Err(err) => {
                self.show_message(
                    "Wi-Fi error",
                    [
                        format!("Connection failed"),
                        shorten_for_display(&err.to_string(), 90),
                    ],
                )?;
            }
        }

        Ok(())
    }

    fn prompt_wifi_password(&mut self, ssid: &str) -> Result<Option<String>> {
        let mut password: Vec<char> = Vec::new();
        let mut cursor: usize = 0;
        let charset: Vec<char> = WIFI_PASSWORD_CHARSET.chars().collect();
        let charset_len = charset.len();
        let mut needs_redraw = true;

        loop {
            if needs_redraw {
                let pw_string: String = password.iter().collect();
                let caret_line = if cursor < 60 {
                    let spaces = " ".repeat(cursor.min(pw_string.len()));
                    format!("{spaces}^")
                } else {
                    "^".to_string()
                };
                let overlay = self.stats.snapshot();
                let lines = vec![
                    format!("Password ({})", ssid),
                    pw_string,
                    caret_line,
                    "Up/Down: change char".to_string(),
                    "Left/Right: move/add".to_string(),
                    "Select: connect  K1: exit".to_string(),
                    "K2: backspace  K3: space".to_string(),
                ];
                self.display.draw_dialog(&lines, &overlay)?;
                needs_redraw = false;
            }

            if let Some(button) = self.buttons.try_read_timeout(Duration::from_millis(150))? {
                match button {
                    Button::Key1 => return Ok(None), // Exit
                    Button::Select => {
                        let pw: String = password.iter().collect();
                        return Ok(Some(pw.trim_end().to_string()));
                    }
                    Button::Key2 => {
                        if !password.is_empty() {
                            if cursor > 0 {
                                password.remove(cursor - 1);
                                cursor = cursor.saturating_sub(1);
                            } else {
                                password.remove(0);
                            }
                            needs_redraw = true;
                        }
                    }
                    Button::Key3 => {
                        if password.len() < WIFI_PASSWORD_MAX_LEN {
                            if cursor == password.len() {
                                password.push(' ');
                            } else {
                                password[cursor] = ' ';
                            }
                            if cursor < password.len().saturating_sub(1) {
                                cursor += 1;
                            }
                            needs_redraw = true;
                        }
                    }
                    Button::Left => {
                        if cursor > 0 {
                            cursor -= 1;
                            needs_redraw = true;
                        }
                    }
                    Button::Right => {
                        if cursor < WIFI_PASSWORD_MAX_LEN {
                            if cursor == password.len() {
                                password.push(charset[0]);
                            }
                            cursor = (cursor + 1).min(password.len());
                            needs_redraw = true;
                        }
                    }
                    Button::Up => {
                        if password.is_empty() {
                            password.push(charset[0]);
                        } else if cursor == password.len() {
                            password.push(charset[0]);
                        }
                        let idx = cursor.min(password.len().saturating_sub(1));
                        if let Some(ch) = password.get_mut(idx) {
                            let pos = charset.iter().position(|c| c == ch).unwrap_or(0);
                            let next = (pos + 1) % charset_len;
                            *ch = charset[next];
                            needs_redraw = true;
                        }
                    }
                    Button::Down => {
                        if password.is_empty() {
                            password.push(charset[0]);
                        } else if cursor == password.len() {
                            password.push(charset[0]);
                        }
                        let idx = cursor.min(password.len().saturating_sub(1));
                        if let Some(ch) = password.get_mut(idx) {
                            let pos = charset.iter().position(|c| c == ch).unwrap_or(0);
                            let next = (pos + charset_len - 1) % charset_len;
                            *ch = charset[next];
                            needs_redraw = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
