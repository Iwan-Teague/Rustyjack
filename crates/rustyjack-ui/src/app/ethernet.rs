use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Result;
use rustyjack_commands::{
    Commands, DnsSpoofCommand, DnsSpoofStartArgs, EthernetCommand, EthernetDiscoverArgs,
    EthernetInventoryArgs, EthernetPortScanArgs, EthernetSiteCredArgs, MitmCommand, MitmStartArgs,
};

use crate::util::{count_lines, shorten_for_display};

use super::state::{App, ButtonAction, MitmSession};

impl App {
    /// Launch Ethernet device discovery scan
    pub(crate) fn launch_ethernet_discovery(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Ethernet discovery blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Ethernet",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if let Some(error) = self.preflight_ethernet_operation(&active_interface, false)? {
                return self.show_preflight_error("Preflight Failed", &error);
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Ethernet",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Ethernet Discovery",
                ["ICMP sweep on wired LAN", "Press KEY2 to cancel"],
            )?;

            let args = EthernetDiscoverArgs {
                interface: Some(active_interface.clone()),
                target: None,
                timeout_ms: 500,
            };
            let cmd = Commands::Ethernet(EthernetCommand::Discover(args));

            if let Some((_, data)) = self.dispatch_cancellable("Ethernet Discovery", cmd, 30)? {
                let network = data
                    .get("network")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let interface = data
                    .get("interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("eth0");
                let hosts: Vec<String> = data
                    .get("hosts_found")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let loot_path = data
                    .get("loot_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let detail = data
                    .get("hosts_detail")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut lines = vec![
                    format!("Net: {}", network),
                    format!("Iface: {}", interface),
                    format!("Hosts: {}", hosts.len()),
                ];

                if !hosts.is_empty() {
                    let mut samples = Vec::new();
                    for host in detail.iter().take(3) {
                        if let Some(ip) = host.get("ip").and_then(|v| v.as_str()) {
                            let os = host.get("os_guess").and_then(|v| v.as_str()).unwrap_or("");
                            if os.is_empty() {
                                samples.push(ip.to_string());
                            } else {
                                samples.push(format!("{} ({})", ip, os));
                            }
                        }
                    }
                    if samples.is_empty() {
                        lines.push(format!(
                            "Sample: {}",
                            hosts.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                        ));
                    } else {
                        lines.push(format!("Sample: {}", samples.join(", ")));
                    }
                    if hosts.len() > 3 {
                        lines.push(format!("+{} more", hosts.len() - 3));
                    }
                }

                if let Some(path) = loot_path {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(&path, 18));
                }

                self.show_message("Discovery Done", lines)?;
            }
            Ok(())
        }
    }

    /// Launch Ethernet port scan
    pub(crate) fn launch_ethernet_port_scan(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Port scan blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Port Scan",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if let Some(error) = self.preflight_ethernet_operation(&active_interface, false)? {
                return self.show_preflight_error("Preflight Failed", &error);
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Port Scan",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Ethernet Port Scan",
                ["Scanning target (gateway if unset)", "Select duration next"],
            )?;

            let duration_options = vec![
                ("Quick (0.5s/port)", 500u64),
                ("Normal (1s/port)", 1_000u64),
                ("Thorough (2s/port)", 2_000u64),
                ("Deep (5s/port)", 5_000u64),
            ];
            let labels: Vec<String> = duration_options
                .iter()
                .map(|(label, _)| label.to_string())
                .collect();
            let Some(choice) = self.choose_from_menu("Port Scan", &labels)? else {
                return Ok(());
            };
            let timeout_ms = duration_options
                .get(choice)
                .map(|(_, t)| *t)
                .unwrap_or(1_000);

            let args = EthernetPortScanArgs {
                target: None, // defaults to gateway
                interface: Some(active_interface.clone()),
                ports: None, // default common ports
                timeout_ms: timeout_ms,
            };
            let cmd = Commands::Ethernet(EthernetCommand::PortScan(args));

            // rough estimate: ports count * timeout + buffer (default ports ~15)
            let estimated_secs = ((15u64 * timeout_ms) / 1000).saturating_add(10);

            if let Some((_, data)) = self.dispatch_cancellable("Port Scan", cmd, estimated_secs)? {
                let target = data
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let open_ports: Vec<u16> = data
                    .get("open_ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|p| p as u16))
                            .collect()
                    })
                    .unwrap_or_default();
                let loot_path = data
                    .get("loot_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let banners = data
                    .get("banners")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let mut lines = vec![
                    format!("Target: {}", target),
                    format!("Open: {}", open_ports.len()),
                ];

                if !open_ports.is_empty() {
                    let preview: Vec<String> =
                        open_ports.iter().take(6).map(|p| p.to_string()).collect();
                    lines.push(preview.join(", "));
                    if open_ports.len() > 6 {
                        lines.push(format!("+{} more", open_ports.len() - 6));
                    }
                } else {
                    lines.push("No open ports found".to_string());
                }

                if !banners.is_empty() {
                    let mut preview = Vec::new();
                    for b in banners.iter().take(3) {
                        let port = b.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                        let banner = b
                            .get("banner")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(40)
                            .collect::<String>();
                        preview.push(format!("{}: {}", port, banner));
                    }
                    lines.push("Banners:".to_string());
                    lines.extend(preview);
                    if banners.len() > 3 {
                        lines.push(format!("+{} more", banners.len() - 3));
                    }
                }

                if let Some(path) = loot_path {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(&path, 18));
                }

                self.show_message("Port Scan Done", lines)?;
            }
            Ok(())
        }
    }

    /// Launch Ethernet device inventory (hostnames/services/OS hints)
    pub(crate) fn launch_ethernet_inventory(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Inventory blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Inventory",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if let Some(error) = self.preflight_ethernet_operation(&active_interface, false)? {
                return self.show_preflight_error("Preflight Failed", &error);
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Inventory",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            self.show_progress(
                "Inventory",
                ["Building device list...", "mDNS/LLMNR/NetBIOS/WSD"],
            )?;

            let args = EthernetInventoryArgs {
                interface: Some(active_interface.clone()),
                target: None,
                timeout_ms: 800,
            };
            let cmd = Commands::Ethernet(EthernetCommand::Inventory(args));

            if let Some((msg, data)) = self.dispatch_cancellable("Inventory", cmd, 60)? {
                let devices = data
                    .get("devices")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let loot_path = data.get("loot_file").and_then(|v| v.as_str()).unwrap_or("");

                let mut lines = vec![msg.clone(), format!("Devices: {}", devices.len())];
                if !loot_path.is_empty() {
                    lines.push("Saved:".to_string());
                    lines.push(shorten_for_display(loot_path, 18));
                }
                self.show_message("Inventory Done", lines)?;

                if !devices.is_empty() {
                    self.browse_inventory(devices)?;
                }
            }
            Ok(())
        }
    }

    pub(crate) fn launch_ethernet_mitm(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Ethernet MITM", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("MITM/DNS spoof blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Ethernet MITM",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if let Some(error) = self.preflight_mitm(&active_interface)? {
                return self.show_preflight_error("Preflight Failed", &error);
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Ethernet MITM",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            let dns_sites = self.list_dnsspoof_sites();

            self.show_message(
                "MITM Warning",
                [
                    "Starts ARP spoof on LAN,",
                    "enables IP forwarding,",
                    "captures to PCAP under",
                    "loot/Ethernet/<target>/",
                    "",
                    "Optionally launches DNS",
                    "spoof + portal if picked.",
                    "Use only on authorized",
                    "networks.",
                ],
            )?;

            let mut options = vec!["Start MITM capture".to_string()];
            if !dns_sites.is_empty() {
                options.push("MITM + DNS spoof".to_string());
            }
            options.push("Cancel".to_string());

            let Some(choice) = self.choose_from_menu("Ethernet MITM", &options)? else {
                return Ok(());
            };

            let start_dns = choice == 1 && !dns_sites.is_empty();
            if options.len() == 2 && choice == 1 {
                // Cancel selected in two-item menu
                return Ok(());
            }
            if options.len() == 3 && choice == 2 {
                return Ok(());
            }

            let max_options = vec![
                ("Cap 8 hosts (safe)", 8usize),
                ("All hosts (no cap)", usize::MAX),
            ];
            let max_labels: Vec<String> = max_options
                .iter()
                .map(|(label, _)| label.to_string())
                .collect();
            let Some(max_choice) = self.choose_from_menu("Host Limit", &max_labels)? else {
                return Ok(());
            };
            let max_hosts = max_options.get(max_choice).map(|(_, v)| *v).unwrap_or(8);

            let loot_label = if !self.config.settings.target_network.is_empty() {
                self.config.settings.target_network.clone()
            } else {
                active_interface.clone()
            };

            let args = MitmStartArgs {
                interface: Some(active_interface.clone()),
                network: Some(loot_label.clone()),
                max_hosts,
                label: Some(loot_label.clone()),
            };
            let cmd = Commands::Mitm(MitmCommand::Start(args));

            self.show_progress(
                "Ethernet MITM",
                [
                    &format!("Iface: {}", active_interface),
                    &format!(
                        "Max hosts: {}",
                        if max_hosts == usize::MAX {
                            "all".to_string()
                        } else {
                            max_hosts.to_string()
                        }
                    ),
                ],
            )?;

            let result = self.dispatch_cancellable("Ethernet MITM", cmd, 30)?;
            let Some((msg, data)) = result else {
                if let Err(err) = self.core.dispatch(Commands::Mitm(MitmCommand::Stop)) {
                    tracing::warn!("MITM stop after cancel failed: {:#}", err);
                }
                return Ok(());
            };

            let victim_count = data
                .get("victim_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let skipped = data
                .get("victims_skipped")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let pcap_path = data
                .get("pcap_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let loot_dir = data.get("loot_dir").and_then(|v| v.as_str()).unwrap_or("");
            let loot_dir_buf = if loot_dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(loot_dir))
            };
            let gateway = data
                .get("gateway")
                .and_then(|v| v.as_str())
                .unwrap_or("gateway");

            let mut lines = vec![
                msg,
                format!("Iface: {}", active_interface),
                format!("Gateway: {}", gateway),
                format!("Victims: {}", victim_count),
            ];
            if skipped > 0 {
                lines.push(format!("Skipped: {}", skipped));
            }
            if let Some(ref dir) = loot_dir_buf {
                lines.push("Loot dir:".to_string());
                lines.push(shorten_for_display(dir.to_string_lossy().as_ref(), 18));
            }
            lines.push("PCAP:".to_string());
            lines.push(shorten_for_display(pcap_path, 18));

            self.show_message("MITM Running", lines)?;

            if start_dns {
                let site = self.choose_dnsspoof_site(&dns_sites)?;
                if let Some(site_name) = site {
                    let dns_args = DnsSpoofStartArgs {
                        site: site_name.clone(),
                        interface: Some(active_interface.clone()),
                        loot_dir: loot_dir_buf.clone(),
                    };
                    let dns_cmd = Commands::DnsSpoof(DnsSpoofCommand::Start(dns_args));
                    match self.core.dispatch(dns_cmd) {
                        Ok((dns_msg, dns_data)) => {
                            self.begin_mitm_session(Some(site_name.clone()), loot_dir_buf.clone());
                            let mut dns_lines = vec![
                                dns_msg,
                                format!("Site: {}", site_name),
                                format!("Iface: {}", active_interface),
                            ];
                            if let Some(ip) = dns_data.get("interface").and_then(|v| v.as_str()) {
                                dns_lines.push(format!("Bound: {}", ip));
                            }
                            self.show_message("DNS Spoof", dns_lines)?;
                            self.show_mitm_status()?;
                        }
                        Err(e) => {
                            self.show_message(
                                "DNS Spoof Error",
                                ["Failed to launch DNS spoof", &format!("{}", e)],
                            )?;
                        }
                    }
                }
            }
            Ok(())
        }
    }

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

    pub(crate) fn launch_ethernet_site_cred_capture(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Site Cred Capture", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.mode_allows_active("Site credential capture blocked in Stealth mode")? {
                return Ok(());
            }
            let active_interface = self.config.settings.active_network_interface.clone();
            if active_interface.is_empty() {
                return self.show_message(
                    "Site Cred Capture",
                    [
                        "No active interface set",
                        "",
                        "Set an Ethernet interface",
                        "as Active in Settings.",
                    ],
                );
            }

            if let Some(error) = self.preflight_ethernet_operation(&active_interface, true)? {
                return self.show_preflight_error("Preflight Failed", &error);
            }

            if !self.interface_has_carrier(&active_interface) {
                return self.show_message(
                    "Site Cred Capture",
                    [
                        &format!("Interface: {}", active_interface),
                        "Link is down / no cable",
                        "",
                        "Plug into a network and",
                        "try again.",
                    ],
                );
            }

            let dns_sites = self.list_dnsspoof_sites();
            if dns_sites.is_empty() {
                return self.show_message(
                    "DNS Spoof",
                    [
                        "No site templates found.",
                        "Add folders under",
                        "DNSSpoof/sites/<name>",
                        "with an index.html.",
                    ],
                );
            }

            self.show_message(
                "Site Cred Capture",
                [
                    "Pipeline: scan LAN, classify",
                    "human devices, ARP poison",
                    "them, start DNS spoof site,",
                    "and capture traffic to PCAP.",
                    "",
                    "Use only on authorized",
                    "networks.",
                ],
            )?;

            let site = match self.choose_dnsspoof_site(&dns_sites)? {
                Some(s) => s,
                None => return Ok(()),
            };

            let max_options = vec![
                ("Cap 6-8 likely humans", 8usize),
                ("All detected humans", usize::MAX),
            ];
            let max_labels: Vec<String> = max_options.iter().map(|(l, _)| l.to_string()).collect();
            let Some(max_choice) = self.choose_from_menu("Host Limit", &max_labels)? else {
                return Ok(());
            };
            let max_hosts = max_options.get(max_choice).map(|(_, v)| *v).unwrap_or(8);

            let confirm_options = vec![
                format!("Site: {}", site),
                format!("Iface: {}", active_interface),
                if max_hosts == usize::MAX {
                    "Hosts: all detected".to_string()
                } else {
                    format!("Hosts: up to {}", max_hosts)
                },
                "Start".to_string(),
                "Cancel".to_string(),
            ];
            let Some(choice) = self.choose_from_list("Start Pipeline?", &confirm_options)? else {
                return Ok(());
            };
            if choice == confirm_options.len().saturating_sub(1) {
                return Ok(());
            }
            if choice != confirm_options.len().saturating_sub(2) {
                return Ok(());
            }

            self.show_progress(
                "Site Cred Capture",
                ["Scanning + classifying...", "ARP poison + DNS spoof..."],
            )?;

            let args = EthernetSiteCredArgs {
                interface: Some(active_interface.clone()),
                target: None,
                site: site.clone(),
                max_hosts,
                timeout_ms: 800,
            };
            let cmd = Commands::Ethernet(EthernetCommand::SiteCredCapture(args));

            if let Some((msg, data)) = self.dispatch_cancellable("Site Cred Capture", cmd, 45)? {
                let victim_count = data
                    .get("victim_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let victims: Vec<String> = data
                    .get("victims")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| s.as_str().map(ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let pcap_path = data
                    .get("pcap_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let loot_dir = data.get("loot_dir").and_then(|v| v.as_str()).unwrap_or("");
                let loot_dir_buf = if loot_dir.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(loot_dir))
                };
                let skipped = data
                    .get("victims_skipped")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let mut lines = vec![
                    msg,
                    format!("Site: {}", site),
                    format!("Iface: {}", active_interface),
                    format!("Victims: {}", victim_count),
                ];
                if skipped > 0 {
                    lines.push(format!("Skipped: {}", skipped));
                }
                if !victims.is_empty() {
                    let preview: Vec<String> = victims.iter().take(3).cloned().collect();
                    lines.push(format!("Targets: {}", preview.join(", ")));
                    if victims.len() > 3 {
                        lines.push(format!("+{} more", victims.len() - 3));
                    }
                }
                if let Some(ref dir) = loot_dir_buf {
                    lines.push("Loot dir:".to_string());
                    lines.push(shorten_for_display(dir.to_string_lossy().as_ref(), 18));
                }
                lines.push("PCAP:".to_string());
                lines.push(shorten_for_display(pcap_path, 18));
                lines.push("DNS spoof enabled".to_string());

                self.show_message("Pipeline Running", lines)?;
                let dns_base = data
                    .get("dns_capture_dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .or(loot_dir_buf.clone());
                self.begin_mitm_session(Some(site), dns_base);
                self.show_mitm_status()?;
            }
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

    pub(crate) fn begin_mitm_session(&mut self, site: Option<String>, base: Option<PathBuf>) {
        let base = base.unwrap_or_else(|| self.root.join("DNSSpoof").join("captures"));
        let (visit_log, cred_log) = if let Some(ref s) = site {
            (
                Some(base.join(s).join("visits.log")),
                Some(base.join(s).join("credentials.log")),
            )
        } else {
            (None, None)
        };
        self.active_mitm = Some(MitmSession {
            started: Instant::now(),
            site,
            visit_log,
            cred_log,
        });
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
