use std::time::Duration;

use anyhow::{anyhow, Result};
use rustyjack_commands::{Commands, HardwareCommand};
use rustyjack_ipc::{InterfaceSelectJobResult, JobState};

use crate::{types::InterfaceSummary, util::shorten_for_display};

use super::state::{App, ButtonAction};

impl App {
    pub(crate) fn choose_interface_name(
        &mut self,
        title: &str,
        names: &[String],
    ) -> Result<Option<String>> {
        if names.is_empty() {
            self.show_message("Interfaces", ["No interfaces detected"])?;
            return Ok(None);
        }
        let labels: Vec<String> = names.iter().map(|n| format!(" {n}")).collect();
        Ok(self
            .choose_from_list(title, &labels)?
            .map(|idx| names[idx].clone()))
    }

    #[allow(dead_code)]
    pub(crate) fn choose_interface_prompt(&mut self, title: &str) -> Result<Option<String>> {
        let (_, data) = self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;
        let mut names: Vec<String> = Vec::new();
        if let Some(arr) = data.get("ethernet_ports").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    names.push(info.name);
                }
            }
        }
        if let Some(arr) = data.get("wifi_modules").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    names.push(info.name);
                }
            }
        }
        names.sort();
        names.dedup();
        self.choose_interface_name(title, &names)
    }

    /// Choose a wireless interface (wifi_modules) with active preselection if present
    pub(crate) fn choose_wifi_interface(&mut self, title: &str) -> Result<Option<String>> {
        let (_, data) = self
            .core
            .dispatch(Commands::Hardware(HardwareCommand::Detect))?;
        let mut wifi = Vec::new();
        if let Some(arr) = data.get("wifi_modules").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(info) = serde_json::from_value::<InterfaceSummary>(item.clone()) {
                    wifi.push(info.name);
                }
            }
        }

        if wifi.is_empty() {
            self.show_message("WiFi", ["No wireless interfaces found"])?;
            return Ok(None);
        }

        wifi.sort();
        wifi.dedup();

        // Auto-select if only one
        if wifi.len() == 1 {
            return Ok(Some(wifi[0].clone()));
        }

        // Build labels with active marker
        let active = self.config.settings.active_network_interface.clone();
        let labels: Vec<String> = wifi
            .iter()
            .map(|n| {
                if !active.is_empty() && *n == active {
                    format!("* {}", n)
                } else {
                    n.clone()
                }
            })
            .collect();

        Ok(self
            .choose_from_list(title, &labels)?
            .map(|idx| wifi[idx].clone()))
    }

    pub(crate) fn run_interface_selection_job(
        &mut self,
        selected_name: &str,
        title: &str,
    ) -> Result<Option<InterfaceSelectJobResult>> {
        let job_id = self.core.start_interface_select(selected_name)?;
        let mut last_message: Option<String> = None;

        loop {
            let status = self.core.job_status(job_id)?;
            if let Some(progress) = status.progress.clone() {
                let msg = format!("{}% {}", progress.percent, progress.message);
                if last_message.as_ref() != Some(&msg) {
                    self.show_progress(
                        title,
                        [
                            &format!("Interface: {}", selected_name),
                            &msg,
                            "KEY2 = Cancel",
                        ],
                    )?;
                    last_message = Some(msg);
                }
            } else if last_message.is_none() {
                self.show_progress(
                    title,
                    [
                        &format!("Interface: {}", selected_name),
                        "Queued...",
                        "KEY2 = Cancel",
                    ],
                )?;
                last_message = Some("Queued".to_string());
            }

            match status.state {
                JobState::Queued | JobState::Running => {
                    if let Some(button) = self.buttons.try_read()? {
                        match self.map_button(button) {
                            ButtonAction::Cancel => {
                                if !self.confirm_cancel("Interface selection")? {
                                    continue;
                                }
                                self.show_progress(
                                    title,
                                    [
                                        &format!("Interface: {}", selected_name),
                                        "Cancelling...",
                                        "Please wait",
                                    ],
                                )?;
                                if let Err(err) = self.core.cancel_job(job_id) {
                                    self.show_error_dialog(
                                        "Cancel failed: Interface selection",
                                        &err,
                                    )?;
                                    return Ok(None);
                                }

                                let cancel_start = std::time::Instant::now();
                                while cancel_start.elapsed() < Duration::from_secs(3) {
                                    let st = self.core.job_status(job_id)?;
                                    if matches!(
                                        st.state,
                                        JobState::Cancelled
                                            | JobState::Failed
                                            | JobState::Completed
                                    ) {
                                        break;
                                    }
                                    std::thread::sleep(Duration::from_millis(100));
                                }

                                self.show_message(
                                    "Interface Selection",
                                    [
                                        "Cancelled",
                                        "",
                                        "Run Interface Select again",
                                        "to ensure desired state",
                                    ],
                                )?;
                                return Ok(None);
                            }
                            _ => {}
                        }
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                JobState::Completed => {
                    let value = status
                        .result
                        .ok_or_else(|| anyhow!("Interface job completed without result"))?;
                    let parsed: InterfaceSelectJobResult = serde_json::from_value(value)?;
                    return Ok(Some(parsed));
                }
                JobState::Failed | JobState::Cancelled => {
                    let mut lines = vec![format!("Interface: {}", selected_name)];
                    if let Some(err) = status.error {
                        lines.push(err.message);
                        if let Some(detail) = err.detail {
                            lines.push(shorten_for_display(&detail, 120));
                        }
                    } else {
                        lines.push("Interface selection failed".to_string());
                    }
                    self.show_message("Interface Error", lines.iter().map(|s| s.as_str()))?;
                    return Ok(None);
                }
            }
        }
    }

    pub(crate) fn render_interface_selection_success(
        &mut self,
        result: InterfaceSelectJobResult,
    ) -> Result<()> {
        self.config.settings.active_network_interface = result.interface.clone();
        let config_path = self.root.join("gui_conf.json");
        let mut lines = Vec::new();

        match self.config.save(&config_path) {
            Ok(()) => lines.push("Config saved".to_string()),
            Err(e) => lines.push(format!("Config save failed: {}", e)),
        }

        lines.push(format!("Active: {}", result.interface));
        if !result.blocked.is_empty() {
            lines.push(format!("Blocked: {}", result.blocked.join(", ")));
        }
        if let Some(carrier) = result.carrier {
            lines.push(format!(
                "Carrier: {}",
                if carrier { "present" } else { "none" }
            ));
        }
        if let Some(dhcp) = result.dhcp {
            if let Some(ip) = dhcp.ip {
                lines.push(format!("IP: {}", ip));
            }
            if let Some(gw) = dhcp.gateway {
                lines.push(format!("Gateway: {}", gw));
            }
            if !dhcp.dns_servers.is_empty() {
                lines.push(format!("DNS: {}", dhcp.dns_servers.join(", ")));
            }
        }
        for note in result.notes {
            lines.push(note);
        }

        self.show_message("Interface Set", lines.iter().map(|s| s.as_str()))
    }

    pub(crate) fn select_active_interface(&mut self) -> Result<()> {
        // List all interfaces via daemon RPC
        let data = self.core.wifi_interfaces()?;
        let ifaces: rustyjack_ipc::WifiInterfacesResponse = serde_json::from_value(data)?;

        if ifaces.interfaces.is_empty() {
            return self.show_message("Interfaces", ["No interfaces found"]);
        }

        // Build menu labels (just names since daemon doesn't provide full details yet)
        let labels = ifaces.interfaces.clone();

        // Let user select
        if let Some(idx) = self.choose_from_menu("Select Interface", &labels)? {
            let selected_name = &ifaces.interfaces[idx];

            // Confirm selection with dialog
            let overlay = self.stats.snapshot();
            let content = vec![
                format!("Interface: {}", selected_name),
                "".to_string(),
                "All other interfaces will be".to_string(),
                "brought DOWN and blocked.".to_string(),
                "".to_string(),
                "SELECT = Continue".to_string(),
                "LEFT = Back".to_string(),
                "KEY2 = Cancel".to_string(),
            ];
            self.display.draw_dialog(&content, &overlay)?;

            loop {
                let button = self.buttons.wait_for_press()?;
                match self.map_button(button) {
                    ButtonAction::Select => {
                        break;
                    }
                    ButtonAction::Back => {
                        return Ok(());
                    }
                    ButtonAction::Cancel => {
                        if self.confirm_cancel("Interface selection")? {
                            return Ok(());
                        }
                    }
                    ButtonAction::Refresh => {
                        self.display.draw_dialog(&content, &overlay)?;
                    }
                    _ => {}
                }
            }

            // Call set-active-interface RPC
            self.show_progress(
                "Setting Interface",
                &[
                    &format!("Activating {}", selected_name),
                    "Blocking others...",
                    "Please wait",
                ],
            )?;

            if let Some(result) =
                self.run_interface_selection_job(selected_name, "Setting Interface")?
            {
                self.render_interface_selection_success(result)?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    pub(crate) fn view_interface_status(&mut self) -> Result<()> {
        // Get current state - daemon only returns interface names
        let data = self.core.wifi_interfaces()?;
        let ifaces: rustyjack_ipc::WifiInterfacesResponse = serde_json::from_value(data)?;

        // Show available interfaces
        let mut status_lines = vec!["Available Interfaces:".to_string(), "".to_string()];

        for iface_name in &ifaces.interfaces {
            status_lines.push(format!("  {}", iface_name));
        }

        if ifaces.interfaces.is_empty() {
            status_lines.push("  (none found)".to_string());
        }

        status_lines.push("".to_string());
        status_lines.push("Only one interface should".to_string());
        status_lines.push("be active at a time.".to_string());

        self.show_message("Interface Status", status_lines)
    }
}
