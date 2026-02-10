use std::time::Duration;

use anyhow::{anyhow, Result};
use rustyjack_ipc::{InterfaceSelectJobResult, InterfaceStatusResponse, JobState};

use crate::util::shorten_for_display;

use super::state::{App, ButtonAction};

impl App {
    fn format_interface_label(status: &InterfaceStatusResponse) -> String {
        let admin = if status.is_up { "UP" } else { "DOWN" };
        let carrier = match status.carrier {
            Some(true) => "car:up",
            Some(false) => "car:down",
            None => "car:?",
        };
        let ip = status.ip.as_deref().unwrap_or("-");
        format!(
            "{} {} {} {}",
            status.interface,
            admin,
            carrier,
            shorten_for_display(ip, 14)
        )
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
                            "Processing...",
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
                        "Processing...",
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
                                        "Processing...",
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
                        let mut combined = err.message.clone();
                        lines.push(err.message);
                        if let Some(detail) = err.detail {
                            combined.push(' ');
                            combined.push_str(&detail);
                            lines.push(shorten_for_display(&detail, 120));
                        }
                        let combined_lower = combined.to_lowercase();
                        if combined_lower.contains("rollback restored") {
                            lines.push("Rollback restored previous uplink.".to_string());
                        } else if combined_lower.contains("rollback failed") {
                            lines.push(
                                "Rollback failed; recover with eth0 if possible.".to_string(),
                            );
                        }
                    } else {
                        lines.push("Interface selection failed".to_string());
                    }
                    lines.push("If stranded, reconnect SSH and select eth0.".to_string());
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
        let mut interfaces = self.core.interfaces_list()?.interfaces;
        interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));

        if interfaces.is_empty() {
            return self.show_message("Interfaces", ["No interfaces found"]);
        }

        let labels: Vec<String> = interfaces
            .iter()
            .map(Self::format_interface_label)
            .collect();

        if let Some(idx) = self.choose_from_menu("Switch Active Interface", &labels)? {
            let selected_name = interfaces[idx].interface.clone();

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

            self.show_progress(
                "Switching Interface",
                &[
                    &format!("Switching to {}", selected_name),
                    "Processing...",
                    "Please wait",
                ],
            )?;

            if let Some(result) =
                self.run_interface_selection_job(&selected_name, "Switching Interface")?
            {
                self.render_interface_selection_success(result)?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    pub(crate) fn view_interface_status(&mut self) -> Result<()> {
        let mut interfaces = self.core.interfaces_list()?.interfaces;
        interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));

        let mut status_lines = vec!["Interfaces:".to_string(), "".to_string()];

        for iface in &interfaces {
            status_lines.push(Self::format_interface_label(iface));
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
}
