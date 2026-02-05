use anyhow::Result;

use super::state::App;

impl App {
    pub(crate) fn preflight_wireless_scan(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not a wireless interface. Wireless scanning requires a Wi-Fi adapter.",
                iface
            )));
        }

        if !status.is_up {
            return Ok(Some(format!(
                "{} is currently DOWN. The interface must be active to scan for networks.",
                iface
            )));
        }

        Ok(None)
    }

    /// Preflight check for deauth attack
    pub(crate) fn preflight_deauth_attack(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Deauth attacks require a Wi-Fi adapter with injection support.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_monitor {
            return Ok(Some(format!(
                "{} does not support monitor mode. Deauth requires an adapter that can enter monitor mode (e.g., ath9k, rtl8812au).",
                iface
            )));
        }

        // Check TX-in-monitor capability - needed for deauth
        match caps.tx_in_monitor {
            crate::core::TxInMonitorCapability::NotSupported => {
                return Ok(Some(format!(
                    "{} cannot inject packets in monitor mode. {}. Consider using an external USB Wi-Fi adapter with injection support (e.g., AR9271, RTL8812AU).",
                    iface, caps.tx_in_monitor_reason
                )));
            }
            crate::core::TxInMonitorCapability::Unknown => {
                // Allow but warn - user can proceed at their own risk
                tracing::warn!(
                    "TX-in-monitor capability unknown for {}: {}",
                    iface, caps.tx_in_monitor_reason
                );
            }
            crate::core::TxInMonitorCapability::Supported => {
                // Good to go
            }
        }

        if self.config.settings.target_bssid.is_empty() {
            return Ok(Some(
                "No target BSSID set. Use 'Set as Target' on a network from the scan list first."
                    .to_string(),
            ));
        }

        Ok(None)
    }

    /// Preflight check for evil twin attack
    pub(crate) fn preflight_evil_twin(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Evil Twin requires a Wi-Fi adapter.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_ap {
            return Ok(Some(format!(
                "{} does not support Access Point mode. Evil Twin requires AP capability. The built-in CYW43436 supports limited AP mode on 2.4GHz only.",
                iface
            )));
        }

        let target_net = &self.config.settings.target_network;
        if !target_net.is_empty() {
            let channel_str = target_net.split('|').nth(2).unwrap_or("0");
            if let Ok(channel) = channel_str.parse::<u8>() {
                if channel > 14 && !caps.supports_5ghz {
                    return Ok(Some(format!(
                        "Target network is on 5GHz (channel {}), but {} only supports 2.4GHz. Use a dual-band adapter.",
                        channel, iface
                    )));
                }
            }
        }

        if self.config.settings.target_network.is_empty() {
            return Ok(Some(
                "No target network set. Use 'Set as Target' on a network from the scan list first."
                    .to_string(),
            ));
        }

        Ok(None)
    }

    /// Preflight check for hotspot
    pub(crate) fn preflight_hotspot(
        &mut self,
        iface: &str,
        upstream: &str,
    ) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Hotspot requires a Wi-Fi adapter.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_ap {
            return Ok(Some(format!(
                "{} does not support Access Point mode. Hotspot requires AP capability.",
                iface
            )));
        }

        if !caps.supports_2ghz {
            return Ok(Some(format!(
                "{} does not support 2.4GHz. Hotspot requires 2.4GHz band support.",
                iface
            )));
        }

        if !upstream.is_empty() {
            if upstream == iface {
                return Ok(Some(
                    "Upstream interface must be different from the AP interface.".to_string(),
                ));
            }

            let status = match self.core.interface_status(upstream) {
                Ok(s) => s,
                Err(e) => return Ok(Some(format!("Failed to check upstream status: {}", e))),
            };

            if !status.exists {
                return Ok(Some(format!(
                    "Upstream interface {} does not exist.",
                    upstream
                )));
            }

            if !status.is_up {
                return Ok(Some(format!(
                    "Upstream interface {} is DOWN. Bring it up before starting hotspot.",
                    upstream
                )));
            }

            if let Some(ip) = status.ip.as_deref() {
                if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                    let octets = addr.octets();
                    if octets[0] == 10 && octets[1] == 20 && octets[2] == 30 {
                        return Ok(Some(format!(
                            "Upstream interface {} has IP {} which conflicts with hotspot subnet 10.20.30.0/24.",
                            upstream, ip
                        )));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Preflight check for karma attack
    pub(crate) fn preflight_karma(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Karma attack requires a Wi-Fi adapter.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_ap {
            return Ok(Some(format!(
                "{} does not support AP mode. Karma requires AP capability.",
                iface
            )));
        }

        if !caps.supports_monitor {
            return Ok(Some(format!(
                "{} does not support monitor mode. Karma requires monitor mode to sniff probe requests.",
                iface
            )));
        }

        Ok(None)
    }

    /// Preflight check for handshake capture
    pub(crate) fn preflight_handshake_capture(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Handshake capture requires a Wi-Fi adapter.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_monitor {
            return Ok(Some(format!(
                "{} does not support monitor mode. Handshake capture requires monitor mode capability.",
                iface
            )));
        }

        // Check TX-in-monitor capability - needed for active handshake capture with deauth
        match caps.tx_in_monitor {
            crate::core::TxInMonitorCapability::NotSupported => {
                return Ok(Some(format!(
                    "{} cannot inject packets in monitor mode. {}. Consider using an external USB Wi-Fi adapter with injection support.",
                    iface, caps.tx_in_monitor_reason
                )));
            }
            crate::core::TxInMonitorCapability::Unknown => {
                // Allow but warn
                tracing::warn!(
                    "TX-in-monitor capability unknown for {}: {}",
                    iface, caps.tx_in_monitor_reason
                );
            }
            crate::core::TxInMonitorCapability::Supported => {
                // Good to go
            }
        }

        if self.config.settings.target_bssid.is_empty() {
            return Ok(Some(
                "No target BSSID set. Use 'Set as Target' on a network from the scan list first."
                    .to_string(),
            ));
        }

        Ok(None)
    }

    /// Preflight check for PMKID capture
    pub(crate) fn preflight_pmkid_capture(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. PMKID capture requires a Wi-Fi adapter.",
                iface
            )));
        }

        Ok(None)
    }

    /// Preflight check for probe sniffing
    pub(crate) fn preflight_probe_sniff(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Wi-Fi interface.",
                iface
            )));
        }

        if !status.is_wireless {
            return Ok(Some(format!(
                "{} is not wireless. Probe sniffing requires a Wi-Fi adapter.",
                iface
            )));
        }

        let caps = match self.core.get_interface_capabilities(iface) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Some(format!(
                    "Failed to check interface capabilities: {}",
                    e
                )))
            }
        };

        if !caps.supports_monitor {
            return Ok(Some(format!(
                "{} does not support monitor mode. Probe sniffing requires monitor mode.",
                iface
            )));
        }

        Ok(None)
    }

    /// Preflight check for ethernet operations
    pub(crate) fn preflight_ethernet_operation(
        &mut self,
        iface: &str,
        requires_ip: bool,
    ) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid Ethernet interface.",
                iface
            )));
        }

        if status.is_wireless {
            return Ok(Some(format!(
                "{} is a wireless interface. This operation requires an Ethernet adapter.",
                iface
            )));
        }

        if !status.is_up {
            return Ok(Some(format!(
                "{} is currently DOWN. The interface must be active for Ethernet operations.",
                iface
            )));
        }

        if requires_ip {
            if status.ip.is_none() {
                return Ok(Some(format!(
                    "{} has no IP address. This operation requires network connectivity. Try 'DHCP Request' first.",
                    iface
                )));
            }
        }

        Ok(None)
    }

    /// Preflight check for MITM attack
    pub(crate) fn preflight_mitm(&mut self, iface: &str) -> Result<Option<String>> {
        let status = match self.core.interface_status(iface) {
            Ok(s) => s,
            Err(e) => return Ok(Some(format!("Failed to check interface status: {}", e))),
        };

        if !status.exists {
            return Ok(Some(format!(
                "{} does not exist. Select a valid interface.",
                iface
            )));
        }

        if status.is_wireless {
            return Ok(Some(format!(
                "{} is a wireless interface. Ethernet MITM requires a wired adapter.",
                iface
            )));
        }

        if !status.is_up {
            return Ok(Some(format!(
                "{} is currently DOWN. MITM requires an active network connection.",
                iface
            )));
        }

        if status.ip.is_none() {
            return Ok(Some(format!(
                "{} has no IP address. MITM requires you to be connected to the target network.",
                iface
            )));
        }

        Ok(None)
    }

    /// Helper to show preflight error with proper text wrapping
    pub(crate) fn show_preflight_error(&mut self, title: &str, error_msg: &str) -> Result<()> {
        use crate::display::{wrap_text, DIALOG_MAX_CHARS};
        let lines = wrap_text(error_msg, DIALOG_MAX_CHARS);
        self.show_message(title, lines)?;
        self.go_home()
    }

    pub(crate) fn preflight_or_skip(&mut self, error: Option<String>) -> Result<Option<String>> {
        if let Some(msg) = error {
            self.show_preflight_error("Preflight Failed", &msg)?;
            return Ok(Some(msg));
        }
        Ok(None)
    }
}
