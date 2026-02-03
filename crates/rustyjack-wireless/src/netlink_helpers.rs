use crate::error::{Result, WirelessError};
use rustyjack_netlink::{HardwareMode, WirelessManager};
use tracing::{debug, info};

pub fn netlink_set_interface_up(interface: &str) -> Result<()> {
    info!("netlink: set interface {} up", interface);
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_up(interface)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!("Failed to set {} up: {}", interface, e))
                    })
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::set_interface_up(interface)
                        .await
                        .map_err(|e| {
                            WirelessError::System(format!("Failed to set {} up: {}", interface, e))
                        })
                })
        })
}

pub fn netlink_set_interface_down(interface: &str) -> Result<()> {
    info!("netlink: set interface {} down", interface);
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_down(interface)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!("Failed to set {} down: {}", interface, e))
                    })
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::set_interface_down(interface)
                        .await
                        .map_err(|e| {
                            WirelessError::System(format!(
                                "Failed to set {} down: {}",
                                interface, e
                            ))
                        })
                })
        })
}

pub fn netlink_flush_addresses(interface: &str) -> Result<()> {
    info!("netlink: flush addresses on {}", interface);
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::flush_addresses(interface)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!(
                            "Failed to flush addresses on {}: {}",
                            interface, e
                        ))
                    })
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::flush_addresses(interface)
                        .await
                        .map_err(|e| {
                            WirelessError::System(format!(
                                "Failed to flush addresses on {}: {}",
                                interface, e
                            ))
                        })
                })
        })
}

pub fn netlink_add_address(interface: &str, addr: std::net::IpAddr, prefix_len: u8) -> Result<()> {
    info!(
        "netlink: add address {}/{} to {}",
        addr, prefix_len, interface
    );
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::add_address(interface, addr, prefix_len)
                    .await
                    .map_err(|e| {
                        WirelessError::System(format!(
                            "Failed to add {}/{} to {}: {}",
                            addr, prefix_len, interface, e
                        ))
                    })
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::add_address(interface, addr, prefix_len)
                        .await
                        .map_err(|e| {
                            WirelessError::System(format!(
                                "Failed to add {}/{} to {}: {}",
                                addr, prefix_len, interface, e
                            ))
                        })
                })
        })
}

pub fn select_hw_mode(interface: &str, channel: u8) -> HardwareMode {
    let default_mode = if channel > 14 {
        HardwareMode::A
    } else {
        HardwareMode::G
    };

    let mut mgr = match WirelessManager::new() {
        Ok(mgr) => mgr,
        Err(err) => {
            debug!(
                "Failed to read wireless capabilities for {}: {}",
                interface, err
            );
            return default_mode;
        }
    };

    let caps = match mgr.get_phy_capabilities(interface) {
        Ok(caps) => caps,
        Err(err) => {
            debug!("Failed to read phy capabilities for {}: {}", interface, err);
            return default_mode;
        }
    };

    let freq = WirelessManager::channel_to_frequency(channel);
    let supports_ht = caps.band_info.iter().any(|band| {
        let band_match = freq
            .map(|f| band.frequencies.iter().any(|info| info.freq == f))
            .unwrap_or(false)
            || (channel <= 14 && band.name.contains("2.4"))
            || (channel > 14 && band.name.contains("5"));
        band_match
            && band.ht_capab.is_some()
            && band
                .ht_mcs_set
                .as_ref()
                .map(|mcs| mcs.len() >= 16)
                .unwrap_or(false)
    });

    if supports_ht {
        HardwareMode::N
    } else {
        default_mode
    }
}
