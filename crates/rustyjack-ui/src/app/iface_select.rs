use std::time::Duration;

use anyhow::{anyhow, Result};
use rustyjack_ipc::{InterfaceSelectJobResult, InterfaceStatusResponse, JobState};

use crate::util::shorten_for_display;

use super::state::{App, ButtonAction};

impl App {
    fn format_interface_label(status: &InterfaceStatusResponse, active_interface: &str) -> String {
        let iface_type = if !status.kind.is_empty() {
            status.kind.as_str()
        } else if status.is_wireless {
            "wifi"
        } else {
            "ethernet"
        };
        let admin = if status.rfkill_blocked == Some(true) {
            "BLOCKED"
        } else if status.is_up {
            "UP"
        } else {
            "DOWN"
        };
        let carrier = match status.carrier {
            Some(true) => "car:up",
            Some(false) => "car:down",
            None => "car:?",
        };
        let ip = status.ip.as_deref().unwrap_or("-");
        let mut label = format!(
            "{} {} {} {} ip:{}",
            status.interface,
            iface_type,
            admin,
            carrier,
            shorten_for_display(ip, 14)
        );
        if status.interface == active_interface {
            label.push_str(" active");
        } else if status.eligible && !status.is_wireless && status.carrier == Some(true) {
            label.push_str(" rec");
        }
        label
    }

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

    pub(crate) fn run_interface_selection_job(
        &mut self,
        selected_name: &str,
        title: &str,
    ) -> Result<Option<InterfaceSelectJobResult>> {
        loop {
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
                                "Switching network state...",
                                &msg,
                                "Navigation locked",
                            ],
                        )?;
                        last_message = Some(msg);
                    }
                } else if last_message.is_none() {
                    self.show_progress(
                        title,
                        [
                            &format!("Interface: {}", selected_name),
                            "Switching network state...",
                            "Queued...",
                            "Navigation locked",
                        ],
                    )?;
                    last_message = Some("Queued".to_string());
                }

                match status.state {
                    JobState::Queued | JobState::Running => {
                        if let Some(button) = self.buttons.try_read()? {
                            if matches!(self.map_button(button), ButtonAction::Refresh) {
                                self.show_progress(
                                    title,
                                    [
                                        &format!("Interface: {}", selected_name),
                                        "Switching network state...",
                                        last_message.as_deref().unwrap_or("Working..."),
                                        "Navigation locked",
                                    ],
                                )?;
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
                        let mut base_lines = vec![format!("Interface: {}", selected_name)];
                        if let Some(err) = status.error {
                            base_lines.push(shorten_for_display(&err.message, 120));
                            if let Some(detail) = err.detail {
                                base_lines.push(shorten_for_display(&detail, 120));
                            }
                        } else {
                            base_lines.push("Interface switch failed".to_string());
                        }

                        loop {
                            let interfaces = self.core.interfaces_list()?.interfaces;
                            let safe_state = interfaces
                                .iter()
                                .filter(|iface| iface.eligible)
                                .all(|iface| !iface.is_up);
                            let recovered_state = Self::exclusivity_achieved(&interfaces);

                            let mut lines = base_lines.clone();
                            lines.push(String::new());
                            if recovered_state {
                                lines.push("SELECT/RIGHT: Back to menu".to_string());
                                lines.push("Recovered: previous interface active".to_string());
                            } else {
                                lines.push("SELECT/RIGHT: Retry switch".to_string());
                            }
                            lines.push("KEY3: Reboot".to_string());
                            if safe_state {
                                lines.push("LEFT: Back to list".to_string());
                            } else {
                                lines.push("LEFT locked until safe".to_string());
                            }

                            self.show_message("Interface Error", lines.iter().map(|s| s.as_str()))?;
                            let button = self.buttons.wait_for_press()?;
                            match self.map_button(button) {
                                ButtonAction::Select => {
                                    if recovered_state {
                                        return Ok(None);
                                    }
                                    break;
                                }
                                ButtonAction::Back => {
                                    if safe_state {
                                        return Ok(None);
                                    }
                                }
                                ButtonAction::Reboot => {
                                    self.restart_system()?;
                                }
                                ButtonAction::Refresh => continue,
                                _ => {}
                            }
                        }
                        break;
                    }
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
        let selected_status = self.core.interface_status(&result.interface)?;

        match self.config.save(&config_path) {
            Ok(()) => lines.push("Config saved".to_string()),
            Err(e) => lines.push(format!("Config save failed: {}", e)),
        }

        lines.push(format!("Active: {}", result.interface));
        lines.push(format!(
            "Admin state: {}",
            if selected_status.is_up { "UP" } else { "DOWN" }
        ));
        lines.push(format!("Operstate: {}", selected_status.oper_state));
        if let Some(ip) = selected_status.ip.as_deref() {
            lines.push(format!("Kernel IP: {}", ip));
        }
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
        for warning in result.warnings {
            lines.push(format!("Warning: {}", warning));
        }
        for note in result.notes {
            lines.push(note);
        }
        if let Some(rollback) = result.rollback {
            if rollback.attempted {
                lines.push(format!(
                    "Rollback: {}",
                    if rollback.restored_previous {
                        "restored previous"
                    } else {
                        "attempted with issues"
                    }
                ));
            }
        }

        if selected_status.is_up {
            self.show_message("Active interface set", lines.iter().map(|s| s.as_str()))
        } else {
            lines.push("Warning: selected interface is not admin-UP.".to_string());
            lines.push("Check cable, rfkill, or Wi-Fi association.".to_string());
            self.show_message("Interface Set (warning)", lines.iter().map(|s| s.as_str()))
        }
    }

    pub(crate) fn select_active_interface(&mut self) -> Result<()> {
        loop {
            let mut interfaces = self.core.interfaces_list()?.interfaces;
            interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));

            if interfaces.is_empty() {
                return self.show_message("Network Interfaces", ["No interfaces found"]);
            }

            let is_exclusive = Self::exclusivity_achieved(&interfaces);
            let active_interface = self.config.settings.active_network_interface.clone();
            let labels: Vec<String> = interfaces
                .iter()
                .map(|status| Self::format_interface_label(status, &active_interface))
                .collect();

            let Some(idx) = self.choose_from_menu("Network Interfaces", &labels)? else {
                if is_exclusive {
                    return Ok(());
                }
                self.show_message(
                    "Network Interfaces",
                    [
                        "Isolation is not complete.",
                        "Select an interface to",
                        "continue.",
                    ],
                )?;
                continue;
            };

            let selected_name = interfaces[idx].interface.clone();

            let overlay = self.stats.snapshot();
            let content = vec![
                "Are you sure?".to_string(),
                "".to_string(),
                format!("Switch to {}", selected_name),
                "All other interfaces will be".to_string(),
                "forced DOWN and blocked.".to_string(),
                "".to_string(),
                "SELECT = Continue".to_string(),
                "LEFT = Back".to_string(),
            ];
            self.display.draw_dialog(&content, &overlay)?;

            let mut confirmed = false;
            loop {
                let button = self.buttons.wait_for_press()?;
                match self.map_button(button) {
                    ButtonAction::Select => {
                        confirmed = true;
                        break;
                    }
                    ButtonAction::Back => {
                        break;
                    }
                    ButtonAction::Refresh => {
                        self.display.draw_dialog(&content, &overlay)?;
                    }
                    _ => {}
                }
            }
            if !confirmed {
                continue;
            }

            self.show_progress(
                "Switching Interface",
                &[
                    &format!("Switching to {}", selected_name),
                    "Processing...",
                    "Navigation locked",
                ],
            )?;

            if let Some(result) =
                self.run_interface_selection_job(&selected_name, "Switching Interface")?
            {
                self.render_interface_selection_success(result)?;
            }
            if Self::exclusivity_achieved(&self.core.interfaces_list()?.interfaces) {
                return Ok(());
            }
        }
    }

    pub(crate) fn view_interface_status(&mut self) -> Result<()> {
        let mut interfaces = self.core.interfaces_list()?.interfaces;
        interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));

        let mut status_lines = vec!["Interfaces:".to_string(), "".to_string()];

        let active_interface = self.config.settings.active_network_interface.clone();
        for iface in &interfaces {
            status_lines.push(Self::format_interface_label(iface, &active_interface));
            status_lines.push(format!(
                "  oper:{} ip:{}",
                iface.oper_state,
                iface.ip.clone().unwrap_or_else(|| "-".to_string())
            ));
        }

        if interfaces.is_empty() {
            status_lines.push("  (none found)".to_string());
        }

        status_lines.push("".to_string());
        status_lines.push("Only one interface should".to_string());
        status_lines.push("be active at a time.".to_string());

        self.show_message("Interface Status", status_lines)
    }

    fn exclusivity_achieved(interfaces: &[InterfaceStatusResponse]) -> bool {
        let eligible: Vec<&InterfaceStatusResponse> =
            interfaces.iter().filter(|iface| iface.eligible).collect();
        let up: Vec<&InterfaceStatusResponse> = eligible
            .iter()
            .copied()
            .filter(|iface| iface.is_up)
            .collect();
        if up.len() != 1 {
            return false;
        }

        let selected = up[0].interface.as_str();
        for iface in eligible {
            if iface.interface == selected {
                continue;
            }
            if iface.is_up {
                return false;
            }
            if iface.is_wireless && iface.rfkill_blocked != Some(true) {
                return false;
            }
        }

        true
    }
}
