use anyhow::{bail, Result};
use serde_json::Value;

use crate::util::shorten_for_display;
use crate::{config::GuiConfig, core::CoreBridge};

pub fn require_not_stealth(config: &GuiConfig, context: &str) -> Result<()> {
    if config
        .settings
        .operation_mode
        .eq_ignore_ascii_case("stealth")
    {
        bail!("Active/traceable ops are blocked in stealth: {context}");
    }
    Ok(())
}

pub fn require_active_interface(config: &GuiConfig) -> Result<()> {
    if config.settings.active_network_interface.is_empty() {
        bail!("No Wi-Fi interface set. Run Network Interfaces first.");
    }
    Ok(())
}

pub fn deauth_attack(core: &CoreBridge, config: &GuiConfig, iface: &str) -> Result<()> {
    let status = core
        .interface_status(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface status: {}", e))?;

    if !status.exists {
        bail!("{} does not exist. Select a valid Wi-Fi interface.", iface);
    }

    if !status.is_wireless {
        bail!(
            "{} is not wireless. Deauth attacks require a Wi-Fi adapter with injection support.",
            iface
        );
    }

    let caps = core
        .get_interface_capabilities(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface capabilities: {}", e))?;

    if !caps.supports_monitor {
        bail!(
            "{} does not support monitor mode. Deauth requires an adapter that can enter monitor mode (e.g., ath9k, rtl8812au).",
            iface
        );
    }

    // Check TX-in-monitor capability - needed for deauth
    use crate::core::TxInMonitorCapability;
    match caps.tx_in_monitor {
        TxInMonitorCapability::NotSupported => {
            bail!(
                "{} cannot inject packets in monitor mode. {}. Consider using an external USB Wi-Fi adapter with injection support (e.g., AR9271, RTL8812AU).",
                iface, caps.tx_in_monitor_reason
            );
        }
        TxInMonitorCapability::Unknown => {
            // Allow but warn - user can proceed at their own risk
            tracing::warn!(
                "TX-in-monitor capability unknown for {}: {}",
                iface,
                caps.tx_in_monitor_reason
            );
        }
        TxInMonitorCapability::Supported => {
            // Good to go
        }
    }

    if config.settings.target_bssid.is_empty() {
        bail!("No target BSSID set. Use 'Set as Target' on a network from the scan list first.");
    }

    Ok(())
}

pub fn pmkid_capture(core: &CoreBridge, iface: &str) -> Result<()> {
    let status = core
        .interface_status(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface status: {}", e))?;

    if !status.exists {
        bail!("{} does not exist. Select a valid Wi-Fi interface.", iface);
    }

    if !status.is_wireless {
        bail!(
            "{} is not wireless. PMKID capture requires a Wi-Fi adapter.",
            iface
        );
    }

    Ok(())
}

pub fn probe_sniff(core: &CoreBridge, iface: &str) -> Result<()> {
    let status = core
        .interface_status(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface status: {}", e))?;

    if !status.exists {
        bail!("{} does not exist. Select a valid Wi-Fi interface.", iface);
    }

    if !status.is_wireless {
        bail!(
            "{} is not wireless. Probe sniffing requires a Wi-Fi adapter.",
            iface
        );
    }

    let caps = core
        .get_interface_capabilities(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface capabilities: {}", e))?;

    if !caps.supports_monitor {
        bail!(
            "{} does not support monitor mode. Probe sniffing requires monitor mode.",
            iface
        );
    }

    Ok(())
}

pub fn preflight_only_summary(data: &Value) -> Option<Vec<String>> {
    let mode = data.get("mode").and_then(|v| v.as_str())?;
    if mode != "preflight_only" {
        return None;
    }
    let status = data
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let mut lines = vec![
        format!("Preflight: {}", status),
        "Authorization required".to_string(),
    ];
    if let Some(errors) = data.get("errors").and_then(|v| v.as_array()) {
        for err in errors.iter().filter_map(|v| v.as_str()) {
            lines.push(shorten_for_display(err, 22));
            if lines.len() >= 6 {
                break;
            }
        }
    }
    if let Some(warnings) = data.get("warnings").and_then(|v| v.as_array()) {
        for warn in warnings.iter().filter_map(|v| v.as_str()) {
            lines.push(shorten_for_display(warn, 22));
            if lines.len() >= 6 {
                break;
            }
        }
    }
    Some(lines)
}
