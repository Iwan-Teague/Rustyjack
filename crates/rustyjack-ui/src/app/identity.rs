use std::collections::HashMap;

use anyhow::{Context, Result};
use rustyjack_commands::{
    Commands, SystemCommand, WifiCommand, WifiMacRandomizeArgs, WifiMacRestoreArgs, WifiMacSetArgs,
    WifiMacSetVendorArgs, WifiTxPowerArgs,
};

use crate::{
    menu::{OpsCategory, TxPowerSetting},
    util::{generate_vendor_aware_mac, shorten_for_display, write_scoped_log},
};

use super::{error::mac_error_hint, state::App};

impl App {
    /// Toggle MAC randomization auto-enable setting
    pub(crate) fn toggle_mac_randomization(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message("Stealth Mode", ["MAC setting locked while in Stealth mode"]);
        }
        self.config.settings.mac_randomization_enabled =
            !self.config.settings.mac_randomization_enabled;
        let enabled = self.config.settings.mac_randomization_enabled;
        self.bump_to_custom();

        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "MAC Randomization",
            [
                format!("Auto-randomize: {}", status),
                "".to_string(),
                if enabled {
                    "MAC will be randomized".to_string()
                } else {
                    "MAC will NOT be changed".to_string()
                },
                if enabled {
                    "before each attack.".to_string()
                } else {
                    "before attacks.".to_string()
                },
            ],
        )
    }

    pub(crate) fn toggle_per_network_mac(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message(
                "Stealth Mode",
                ["Per-network MAC locked while in Stealth mode"],
            );
        }

        self.config.settings.per_network_mac_enabled =
            !self.config.settings.per_network_mac_enabled;
        let enabled = self.config.settings.per_network_mac_enabled;
        self.bump_to_custom();

        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "Per-Network MAC",
            [
                format!("Per-network MAC: {}", status),
                "".to_string(),
                if enabled {
                    "Reuse the same MAC".to_string()
                } else {
                    "MAC will change".to_string()
                },
                if enabled {
                    "for each SSID.".to_string()
                } else {
                    "between connections.".to_string()
                },
            ],
        )
    }

    pub(crate) fn toggle_hostname_randomization(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message(
                "Stealth Mode",
                ["Hostname setting locked while in Stealth mode"],
            );
        }
        self.config.settings.hostname_randomization_enabled =
            !self.config.settings.hostname_randomization_enabled;
        let enabled = self.config.settings.hostname_randomization_enabled;
        self.bump_to_custom();

        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "Hostname Randomization",
            [
                format!("Auto hostname: {}", status),
                "".to_string(),
                if enabled {
                    "Hostname will be randomized".to_string()
                } else {
                    "Hostname will stay unchanged".to_string()
                },
                if enabled {
                    "before attacks.".to_string()
                } else {
                    "unless triggered manually.".to_string()
                },
            ],
        )
    }

    pub(crate) fn randomize_hostname_now(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Hostname", ["Linux-only operation"]);
        }

        #[cfg(target_os = "linux")]
        {
            self.show_progress("Hostname", ["Randomizing...", ""])?;
            match self
                .core
                .dispatch(Commands::System(SystemCommand::RandomizeHostname))
            {
                Ok((msg, data)) => {
                    let name = data
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    self.show_message("Hostname", [msg, format!("New: {}", name)])
                }
                Err(e) => self.show_message("Hostname Error", [format!("{e}")]),
            }
        }
    }

    pub(crate) fn select_operation_mode(&mut self, mode: &str) -> Result<()> {
        let (title, warning) = match mode {
            "stealth" => (
                "Stealth Mode",
                [
                    "RX-only mode; traceable",
                    "scans/attacks blocked.",
                    "MAC+hostname auto-rand.",
                    "TX power lowered.",
                ],
            ),
            "aggressive" => (
                "Aggressive Mode",
                [
                    "Everything enabled.",
                    "High TX power, loud ops.",
                    "Use when stealth is",
                    "not a concern.",
                ],
            ),
            "default" => (
                "Default Mode",
                [
                    "Balanced settings.",
                    "Standard scans/attacks",
                    "allowed, moderate TX.",
                    "Adjust as needed.",
                ],
            ),
            "custom" => (
                "Custom Mode",
                [
                    "Keeps current toggles.",
                    "Adjust settings freely.",
                    "Use to fine-tune",
                    "behavior.",
                ],
            ),
            _ => {
                return self.show_message("Mode", ["Unknown mode"]);
            }
        };

        let options = vec!["Apply".to_string(), "Cancel".to_string()];
        self.show_message(title, warning)?;
        let choice = self.choose_from_list("Confirm Mode", &options)?;
        if choice != Some(0) {
            return Ok(());
        }

        self.apply_operation_mode(mode, true)
    }

    pub(crate) fn apply_operation_mode(&mut self, mode: &str, notify: bool) -> Result<()> {
        let settings = &mut self.config.settings;
        match mode {
            "stealth" => {
                settings.operation_mode = "stealth".to_string();
                settings.mac_randomization_enabled = true;
                settings.hostname_randomization_enabled = true;
                settings.passive_mode_enabled = true;
                settings.tx_power_level = "stealth".to_string();
            }
            "aggressive" => {
                settings.operation_mode = "aggressive".to_string();
                settings.mac_randomization_enabled = false;
                settings.hostname_randomization_enabled = false;
                settings.passive_mode_enabled = false;
                settings.tx_power_level = "maximum".to_string();
            }
            "default" => {
                settings.operation_mode = "default".to_string();
                settings.mac_randomization_enabled = false;
                settings.hostname_randomization_enabled = false;
                settings.passive_mode_enabled = false;
                settings.tx_power_level = "medium".to_string();
            }
            "custom" => {
                settings.operation_mode = "custom".to_string();
            }
            _ => return self.show_message("Mode", ["Unknown mode"]),
        }

        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;

        if notify {
            self.show_message(
                "Mode Applied",
                [
                    format!("Set mode: {}", self.mode_display_name()),
                    "Some settings may have".to_string(),
                    "changed automatically.".to_string(),
                ],
            )?;
        }
        Ok(())
    }

    pub(crate) fn mode_display_name(&self) -> String {
        self.mode_display(&self.config.settings.operation_mode)
    }

    pub(crate) fn mode_display(&self, mode: &str) -> String {
        match mode {
            "stealth" => "Stealth".to_string(),
            "aggressive" => "Aggressive".to_string(),
            "default" => "Default".to_string(),
            "custom" => "Custom".to_string(),
            other => other.to_string(),
        }
    }

    pub(crate) fn mode_allows_active(&mut self, context: &str) -> Result<bool> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            self.show_message(
                "Stealth Mode",
                ["Active/traceable ops", "are blocked in stealth.", context],
            )?;
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn bump_to_custom(&mut self) {
        let mode = &self.config.settings.operation_mode;
        if mode.eq_ignore_ascii_case("default") || mode.eq_ignore_ascii_case("aggressive") {
            self.config.settings.operation_mode = "custom".to_string();
            let config_path = self.root.join("gui_conf.json");
            self.save_config_warn(&config_path, "Saving config after mode change");
        }
    }

    pub(crate) fn apply_identity_hardening(&mut self, ssid: Option<&str>) {
        #[cfg(target_os = "linux")]
        {
            let (active_interface, mac_randomization, per_network_mac, hostname_randomization) = {
                let settings = &self.config.settings;
                (
                    settings.active_network_interface.clone(),
                    settings.mac_randomization_enabled,
                    settings.per_network_mac_enabled,
                    settings.hostname_randomization_enabled,
                )
            };
            if hostname_randomization {
                if let Err(err) = self
                    .core
                    .dispatch(Commands::System(SystemCommand::RandomizeHostname))
                {
                    tracing::warn!("Hostname randomization failed: {:#}", err);
                }
            }
            if active_interface.is_empty() {
                return;
            }

            let ssid = ssid.unwrap_or("").trim();
            if per_network_mac && !ssid.is_empty() {
                if let Err(e) = self.apply_per_network_mac(&active_interface, ssid) {
                    tracing::warn!(
                        "[MAC] per-network MAC failed on {}: {}",
                        active_interface,
                        e
                    );
                }
                return;
            }

            if mac_randomization {
                if let Err(e) = self.core.dispatch(Commands::Wifi(WifiCommand::MacRandomize(
                    WifiMacRandomizeArgs {
                        interface: active_interface.clone(),
                    },
                ))) {
                    tracing::warn!("[MAC] randomize failed on {}: {}", active_interface, e);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn apply_per_network_mac(&mut self, interface: &str, ssid: &str) -> Result<()> {
        use rustyjack_evasion::MacAddress;

        let ssid = ssid.trim();
        if ssid.is_empty() {
            return Ok(());
        }

        let existing_mac = self
            .config
            .settings
            .per_network_macs
            .get(interface)
            .and_then(|map| map.get(ssid))
            .cloned();

        let mut vendor_reused = false;
        let target_mac = match existing_mac.as_deref() {
            Some(mac_str) => match MacAddress::parse(mac_str) {
                Ok(mac) => mac,
                Err(e) => {
                    tracing::warn!(
                        "[MAC] invalid stored per-network MAC for {} on {}: {} ({})",
                        ssid,
                        interface,
                        mac_str,
                        e
                    );
                    let (mac, reused) = generate_vendor_aware_mac(interface)?;
                    vendor_reused = reused;
                    mac
                }
            },
            None => {
                let (mac, reused) = generate_vendor_aware_mac(interface)?;
                vendor_reused = reused;
                mac
            }
        };

        let target_mac_str = target_mac.to_string();
        if let Some(current) = self
            .read_interface_mac(interface)
            .and_then(|mac| MacAddress::parse(&mac).ok())
        {
            if current == target_mac {
                let mut updated = false;
                if self
                    .config
                    .settings
                    .current_macs
                    .get(interface)
                    .map(|mac| mac.eq_ignore_ascii_case(&target_mac_str))
                    .unwrap_or(false)
                    == false
                {
                    self.config
                        .settings
                        .current_macs
                        .insert(interface.to_string(), target_mac_str.clone());
                    updated = true;
                }

                let stored_matches = self
                    .config
                    .settings
                    .per_network_macs
                    .get(interface)
                    .and_then(|map| map.get(ssid))
                    .map(|mac| mac.eq_ignore_ascii_case(&target_mac_str))
                    .unwrap_or(false);
                if !stored_matches {
                    self.config
                        .settings
                        .per_network_macs
                        .entry(interface.to_string())
                        .or_insert_with(HashMap::new)
                        .insert(ssid.to_string(), target_mac_str.clone());
                    updated = true;
                }

                if updated {
                    let config_path = self.root.join("gui_conf.json");
                    self.save_config_file(&config_path)?;
                }
                return Ok(());
            }
        }

        let args = WifiMacSetArgs {
            interface: interface.to_string(),
            mac: target_mac.to_string(),
        };
        let (_, data) = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::MacSet(args)))
            .context("setting per-network MAC")?;
        let applied_mac = data
            .get("new_mac")
            .and_then(|v| v.as_str())
            .unwrap_or(&target_mac_str)
            .to_string();
        let original_mac = data
            .get("original_mac")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original_mac_value = original_mac.clone();
        let reconnect_ok = data
            .get("reconnect_ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        self.config
            .settings
            .original_macs
            .entry(interface.to_string())
            .or_insert_with(|| original_mac_value.clone());
        self.config
            .settings
            .current_macs
            .insert(interface.to_string(), applied_mac.clone());
        self.config
            .settings
            .per_network_macs
            .entry(interface.to_string())
            .or_insert_with(HashMap::new)
            .insert(ssid.to_string(), applied_mac.clone());
        let config_path = self.root.join("gui_conf.json");
        self.save_config_file(&config_path)?;

        tracing::info!(
            "[MAC] per-network MAC set on {} for {}: {} -> {} (vendor_reused={}, reconnect_ok={})",
            interface,
            ssid,
            original_mac_value,
            applied_mac,
            vendor_reused,
            reconnect_ok
        );

        Ok(())
    }

    /// Toggle passive mode setting
    pub(crate) fn toggle_passive_mode(&mut self) -> Result<()> {
        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message(
                "Stealth Mode",
                ["Passive/active toggle locked in Stealth mode"],
            );
        }
        self.config.settings.passive_mode_enabled = !self.config.settings.passive_mode_enabled;
        let enabled = self.config.settings.passive_mode_enabled;
        self.bump_to_custom();

        // Save config
        let config_path = self.root.join("gui_conf.json");
        if let Err(e) = self.config.save(&config_path) {
            return self.show_message("Config Error", [format!("Failed to save: {}", e)]);
        }

        let status = if enabled { "ENABLED" } else { "DISABLED" };
        self.show_message(
            "Passive Mode",
            [
                format!("Passive mode: {}", status),
                "".to_string(),
                if enabled {
                    "Recon will use RX-only".to_string()
                } else {
                    "Normal TX/RX mode".to_string()
                },
                if enabled {
                    "No transmissions.".to_string()
                } else {
                    "will be used.".to_string()
                },
            ],
        )
    }

    pub(crate) fn toggle_ops(&mut self, category: OpsCategory) -> Result<()> {
        let mut ops = self.core.ops_config_get().context("fetch ops config")?;
        let current = Self::ops_enabled_in_config(&ops, category);
        let next = !current;
        let label = Self::ops_category_label(category);

        let prompt = if next {
            format!("Enable {}?", label)
        } else {
            format!("Disable {}?", label)
        };
        let options = vec!["Confirm".to_string(), "Cancel".to_string()];
        if self.choose_from_list(&prompt, &options)? != Some(0) {
            return Ok(());
        }

        Self::set_ops_config_value(&mut ops, category, next);
        match self.core.ops_config_set(ops) {
            Ok(_) => {
                let state = if next { "ON" } else { "OFF" };
                self.show_message("Ops Updated", [format!("{}: {}", label, state)])
            }
            Err(err) => {
                let msg = shorten_for_display(&err.to_string(), 90);
                self.show_message("Ops Error", [msg])
            }
        }
    }

    /// Launch passive reconnaissance mode
    pub(crate) fn launch_passive_recon(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message(
                "Passive Recon",
                [
                    "No interface selected",
                    "",
                    "Run Network Interfaces",
                    "to select an interface.",
                ],
            );
        }

        if !self.monitor_mode_supported(&active_interface) {
            return self.show_message(
                "Hardware Error",
                [
                    "Interface does not",
                    "support monitor mode.",
                    "",
                    "External adapter required",
                ],
            );
        }

        // Duration selection
        let durations = vec![
            "30 seconds".to_string(),
            "1 minute".to_string(),
            "5 minutes".to_string(),
            "10 minutes".to_string(),
        ];
        let dur_choice = self.choose_from_list("Recon Duration", &durations)?;

        let duration_secs = match dur_choice {
            Some(0) => 30,
            Some(1) => 60,
            Some(2) => 300,
            Some(3) => 600,
            _ => return Ok(()),
        };

        self.show_progress(
            "Passive Recon",
            [
                "Starting passive mode...",
                "",
                "NO transmissions!",
                "Listening only.",
            ],
        )?;

        // In real implementation, this would call rustyjack-wireless passive mode
        // For now, show what it would do
        self.show_message(
            "Passive Recon",
            [
                &format!("Interface: {}", active_interface),
                &format!("Duration: {} sec", duration_secs),
                "",
                "Passive mode captures:",
                "- Beacon frames",
                "- Probe requests",
                "- Data (handshakes)",
                "",
                "Zero transmission mode",
            ],
        )
    }

    /// Randomize MAC address immediately
    pub(crate) fn randomize_mac_now(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message("Randomize MAC", ["No interface selected"]);
        }

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Randomize MAC", ["Supported on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let mut connected_warn = false;
            if let Ok(status) = self.fetch_wifi_status(Some(active_interface.clone())) {
                if status.connected {
                    connected_warn = true;
                    if let Err(err) = self.show_message(
                        "Randomize MAC",
                        [
                            &format!(
                                "Interface {} is connected{}",
                                active_interface,
                                status
                                    .ssid
                                    .as_ref()
                                    .map(|s| format!(" ({})", s))
                                    .unwrap_or_default()
                            ),
                            "Changing MAC will force reconnect",
                            "Proceed?",
                        ],
                    ) {
                        tracing::warn!("Failed to show MAC warning: {:#}", err);
                    }
                    let opts = vec!["Proceed (reconnect)".to_string(), "Cancel".to_string()];
                    if self
                        .choose_from_list("Randomize MAC", &opts)?
                        .map(|i| i != 0)
                        .unwrap_or(true)
                    {
                        return Ok(());
                    }
                }
            }

            self.show_progress(
                "Randomize MAC",
                [
                    &format!("Interface: {}", active_interface),
                    "",
                    "Generating vendor-aware MAC...",
                ],
            )?;

            let args = WifiMacRandomizeArgs {
                interface: active_interface.clone(),
            };
            match self
                .core
                .dispatch(Commands::Wifi(WifiCommand::MacRandomize(args)))
            {
                Ok((_, data)) => {
                    let original_mac = data
                        .get("original_mac")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let new_mac = data
                        .get("new_mac")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let vendor_reused = data
                        .get("vendor_reused")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let reconnect_ok = data
                        .get("reconnect_ok")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    self.config
                        .settings
                        .original_macs
                        .entry(active_interface.clone())
                        .or_insert_with(|| original_mac.clone());
                    self.config
                        .settings
                        .current_macs
                        .insert(active_interface.clone(), new_mac.clone());
                    let config_path = self.root.join("gui_conf.json");
                    self.save_config_file(&config_path)?;

                    let mut lines = vec![
                        format!("Interface: {}", active_interface),
                        "".to_string(),
                        format!("Old -> New"),
                        format!("{original_mac} -> {new_mac}"),
                        "".to_string(),
                        format!(
                            "Vendor OUI reused: {}",
                            if vendor_reused { "yes" } else { "no" }
                        ),
                        "".to_string(),
                    ];

                    if reconnect_ok {
                        lines.push("DHCP renewed and".to_string());
                        lines.push("reconnect signaled.".to_string());
                    } else {
                        lines.push("Warning: reconnect may".to_string());
                        lines.push("have failed. Check DHCP.".to_string());
                    }

                    if connected_warn {
                        lines.push("Note: Interface was connected;".to_string());
                        lines.push("MAC change forced reconnect.".to_string());
                    }

                    let _log_path = write_scoped_log(
                        &self.root,
                        "Wireless",
                        &active_interface,
                        "Mac",
                        "mac_randomize",
                        &lines,
                    );

                    self.scrollable_text_viewer("MAC Randomized", &lines, false)
                }
                Err(e) => {
                    let err_str = format!("{}", e);
                    self.show_message(
                        "MAC Error",
                        [
                            "Failed to randomize MAC",
                            "",
                            &err_str,
                            "",
                            mac_error_hint(&err_str),
                        ],
                    )
                }
            }
        }
    }

    /// Restore original MAC address
    pub(crate) fn set_vendor_mac(&mut self) -> Result<()> {
        let interface = self.config.settings.active_network_interface.clone();
        if interface.is_empty() {
            return self.show_message("MAC Address", ["No interface selected"]);
        }

        #[cfg(target_os = "linux")]
        {
            use rustyjack_evasion::VENDOR_DATABASE;

            // Create vendor list for selection
            let mut vendors: Vec<String> = VENDOR_DATABASE
                .iter()
                .map(|v| format!("{} ({})", v.name, v.description))
                .collect();
            vendors.sort();

            let choice = self.choose_from_list("Select Vendor", &vendors)?;
            let Some(idx) = choice else {
                return Ok(());
            };

            // Find the selected vendor (since we sorted the display list, we need to find it again or sort the source)
            // Simpler: just sort the source list of references first
            let mut sorted_vendors: Vec<&rustyjack_evasion::VendorOui> =
                VENDOR_DATABASE.iter().collect();
            sorted_vendors.sort_by_key(|v| v.name);
            let selected_vendor = sorted_vendors[idx];

            self.show_progress("MAC Address", ["Setting vendor MAC...", "Please wait"])?;

            let args = WifiMacSetVendorArgs {
                interface: interface.clone(),
                vendor: selected_vendor.name.to_string(),
            };
            match self
                .core
                .dispatch(Commands::Wifi(WifiCommand::MacSetVendor(args)))
            {
                Ok((_, data)) => {
                    let new_mac = data
                        .get("new_mac")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let orig_mac = data
                        .get("original_mac")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reconnect_ok = data
                        .get("reconnect_ok")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    tracing::info!(
                        "[MAC] vendor set on {}: {} -> {} (vendor={}, reconnect_ok={})",
                        interface,
                        orig_mac,
                        new_mac,
                        selected_vendor.name,
                        reconnect_ok
                    );
                    self.config
                        .settings
                        .original_macs
                        .entry(interface.clone())
                        .or_insert_with(|| orig_mac.clone());
                    self.config
                        .settings
                        .current_macs
                        .insert(interface.clone(), new_mac.clone());
                    let config_path = self.root.join("gui_conf.json");
                    self.save_config_file(&config_path)?;

                    let mut lines = vec![
                        format!("Set to {}", selected_vendor.name),
                        format!("New: {}", new_mac),
                    ];

                    if !reconnect_ok {
                        lines.push("".to_string());
                        lines.push("Warning: reconnect may".to_string());
                        lines.push("have failed. Check DHCP.".to_string());
                    }

                    self.show_message(
                        "MAC Address",
                        lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    )?;
                }
                Err(e) => {
                    self.show_message("MAC Error", [shorten_for_display(&e.to_string(), 20)])?;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.show_message("MAC Address", ["Linux-only operation"])?;
        }
        Ok(())
    }

    pub(crate) fn restore_mac(&mut self) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if active_interface.is_empty() {
            return self.show_message("Restore MAC", ["No interface selected"]);
        }

        // Check if we have a saved original MAC
        let original_mac =
            if let Some(mac) = self.config.settings.original_macs.get(&active_interface) {
                mac.clone()
            } else {
                // Try to read the permanent hardware address
                let perm_path = format!("/sys/class/net/{}/address", active_interface);
                match std::fs::read_to_string(&perm_path) {
                    Ok(mac) => mac.trim().to_uppercase(),
                    Err(_) => {
                        return self.show_message(
                            "Restore MAC",
                            [
                                "No original MAC saved",
                                "",
                                "MAC was not changed by",
                                "RustyJack, or original",
                                "was not recorded.",
                            ],
                        );
                    }
                }
            };

        self.show_progress("Restore MAC", [&format!("Restoring: {}", original_mac)])?;

        let args = WifiMacRestoreArgs {
            interface: active_interface.clone(),
            original_mac: original_mac.clone(),
        };
        match self
            .core
            .dispatch(Commands::Wifi(WifiCommand::MacRestore(args)))
        {
            Ok((_, data)) => {
                let restored_mac = data
                    .get("restored_mac")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&original_mac)
                    .to_string();
                let reconnect_ok = data
                    .get("reconnect_ok")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                self.config.settings.current_macs.remove(&active_interface);
                self.config.settings.original_macs.remove(&active_interface);
                let config_path = self.root.join("gui_conf.json");
                self.save_config_file(&config_path)?;

                let interface_line = format!("Interface: {}", active_interface);
                let mac_line = format!("MAC: {}", restored_mac);
                let mut lines = vec![&interface_line, "", &mac_line, ""];

                if reconnect_ok {
                    lines.push("Original MAC restored.");
                } else {
                    lines.push("MAC restored.");
                    lines.push("Warning: reconnect may");
                    lines.push("have failed. Check DHCP.");
                }

                return self.show_message("MAC Restored", lines);
            }
            Err(e) => {
                return self.show_message(
                    "Restore Error",
                    [
                        "Failed to restore MAC",
                        "",
                        &shorten_for_display(&e.to_string(), 60),
                    ],
                );
            }
        }
    }

    /// Set TX power level
    pub(crate) fn set_tx_power(&mut self, level: TxPowerSetting) -> Result<()> {
        let active_interface = self.config.settings.active_network_interface.clone();

        if self
            .config
            .settings
            .operation_mode
            .eq_ignore_ascii_case("stealth")
        {
            return self.show_message("Stealth Mode", ["TX power locked in Stealth mode"]);
        }

        if active_interface.is_empty() {
            return self.show_message("TX Power", ["No interface selected"]);
        }

        let (dbm, label) = match level {
            TxPowerSetting::Stealth => (1, "Stealth (1 dBm)"),
            TxPowerSetting::Low => (5, "Low (5 dBm)"),
            TxPowerSetting::Medium => (12, "Medium (12 dBm)"),
            TxPowerSetting::High => (18, "High (18 dBm)"),
            TxPowerSetting::Maximum => (30, "Maximum"),
        };

        self.bump_to_custom();
        self.show_progress("TX Power", [&format!("Setting to: {}", label)])?;

        let args = WifiTxPowerArgs {
            interface: active_interface.clone(),
            dbm,
        };
        let success = self
            .core
            .dispatch(Commands::Wifi(WifiCommand::TxPower(args)))
            .is_ok();

        if success {
            // Save selected power level
            let (_, key) = Self::tx_power_label(level);
            self.config.settings.tx_power_level = key.to_string();
            let config_path = self.root.join("gui_conf.json");
            self.save_config_file(&config_path)?;
            self.show_message(
                "TX Power Set",
                [
                    format!("Interface: {}", active_interface),
                    format!("Power: {}", label),
                    "".to_string(),
                    match level {
                        TxPowerSetting::Stealth => "Minimal range - stealth mode".to_string(),
                        TxPowerSetting::Low => "Short range operations".to_string(),
                        TxPowerSetting::Medium => "Balanced range/stealth".to_string(),
                        TxPowerSetting::High => "Normal operation range".to_string(),
                        TxPowerSetting::Maximum => "Maximum range".to_string(),
                    },
                ],
            )
        } else {
            self.show_message(
                "TX Power Error",
                [
                    "Failed to set power.".to_string(),
                    "".to_string(),
                    "Interface may not".to_string(),
                    "support TX power control.".to_string(),
                ],
            )
        }
    }
}
