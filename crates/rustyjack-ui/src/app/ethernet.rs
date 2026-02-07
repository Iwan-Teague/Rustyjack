use std::{fs, time::Duration};

use anyhow::Result;
use rustyjack_commands::{Commands, DnsSpoofCommand, MitmCommand};

use crate::util::{count_lines, shorten_for_display};

use super::state::{App, ButtonAction};

impl App {
    pub(crate) fn stop_ethernet_mitm(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet MITM", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if let Err(err) = self
                .core
                .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Stop))
            {
                self.show_error_dialog("DNS Spoof Stop Failed", &err)?;
            }
            match self.core.dispatch(Commands::Mitm(MitmCommand::Stop)) {
                Ok((msg, _)) => {
                    self.show_message("MITM Stopped", [msg, "IP forwarding disabled".to_string()])
                }
                Err(e) => self.show_message(
                    "MITM Stop Error",
                    ["Failed to stop MITM".to_string(), format!("{}", e)],
                ),
            }?;
            self.active_mitm = None;
            Ok(())
        }
    }

    pub(crate) fn list_dnsspoof_sites(&self) -> Vec<String> {
        let mut sites = Vec::new();
        let base = self.root.join("DNSSpoof").join("sites");
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        sites.push(name.to_string());
                    }
                }
            }
        }
        sites.sort();
        sites
    }

    pub(crate) fn show_mitm_status(&mut self) -> Result<()> {
        let session = match self.active_mitm.clone() {
            Some(s) if s.site.is_some() => s,
            _ => {
                return self.show_message(
                    "MITM Status",
                    [
                        "No active DNS spoof session.",
                        "Start MITM + DNS to track",
                        "visits and credentials.",
                    ],
                );
            }
        };

        let mut visits_prev = 0usize;
        let mut creds_prev = 0usize;

        loop {
            let elapsed_secs = session.started.elapsed().as_secs();
            let visits = session
                .visit_log
                .as_ref()
                .and_then(|p| count_lines(p).ok())
                .unwrap_or(0);
            let creds = session
                .cred_log
                .as_ref()
                .and_then(|p| count_lines(p).ok())
                .unwrap_or(0);

            let mut lines = vec![
                format!("Site: {}", session.site.clone().unwrap_or_default()),
                format!("Elapsed: {}s", elapsed_secs),
                format!("Visits: {}", visits),
                format!("Creds: {}", creds),
                "".to_string(),
                "Select=Stop".to_string(),
                "LEFT=Back  KEY2=Cancel".to_string(),
            ];

            // Highlight new events
            if visits > visits_prev {
                lines.insert(2, "[+] New visit".to_string());
            }
            if creds > creds_prev {
                lines.insert(2, "[+] New credential".to_string());
            }
            visits_prev = visits;
            creds_prev = creds;

            self.display.draw_dialog(&lines, &self.stats.snapshot())?;

            // Wait with timeout so we can refresh counts
            if let Some(button) = self.buttons.try_read_timeout(Duration::from_millis(1000))? {
                match self.map_button(button) {
                    ButtonAction::Back => return Ok(()),
                    ButtonAction::Select => {
                        self.stop_ethernet_mitm()?;
                        return Ok(());
                    }
                    ButtonAction::Cancel => {
                        if self.confirm_cancel("MITM")? {
                            self.stop_ethernet_mitm()?;
                            return Ok(());
                        }
                    }
                    ButtonAction::Reboot => {
                        self.confirm_reboot()?;
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn build_network_report(&mut self) -> Result<()> {
        let networks = self.collect_network_names();
        if networks.is_empty() {
            return self.show_message(
                "Reports",
                [
                    "No network loot found.",
                    "Run Ethernet/WiFi ops",
                    "then try again.",
                ],
            );
        }
        let Some(choice) = self.choose_from_menu("Pick Network", &networks)? else {
            return Ok(());
        };
        let network = &networks[choice];

        self.show_progress(
            "Reports",
            [
                &format!("Building report for {}", network),
                "Please wait...",
            ],
        )?;

        match self.generate_network_report(network) {
            Ok((path, preview)) => {
                self.show_message(
                    "Report Saved",
                    [
                        shorten_for_display(path.to_string_lossy().as_ref(), 18),
                        format!("Lines: {}", preview.len()),
                    ],
                )?;
                self.scrollable_text_viewer("Network Report", &preview, false)
            }
            Err(e) => {
                self.show_message("Report Error", ["Failed to build report", &format!("{e}")])
            }
        }
    }
}
