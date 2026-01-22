use anyhow::{bail, Result};

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
        bail!("No Wi-Fi interface set. Run Hardware Detect first.");
    }
    Ok(())
}

pub fn deauth_attack(core: &CoreBridge, config: &GuiConfig, iface: &str) -> Result<()> {
    let status = core
        .interface_status(iface)
        .map_err(|e| anyhow::anyhow!("Failed to check interface status: {}", e))?;

    if !status.exists {
        bail!(
            "{} does not exist. Select a valid Wi-Fi interface.",
            iface
        );
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

    if !caps.supports_injection {
        bail!(
            "{} cannot inject packets. Deauth attacks require packet injection capability. Consider using an external USB Wi-Fi adapter.",
            iface
        );
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
        bail!(
            "{} does not exist. Select a valid Wi-Fi interface.",
            iface
        );
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
        bail!(
            "{} does not exist. Select a valid Wi-Fi interface.",
            iface
        );
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
