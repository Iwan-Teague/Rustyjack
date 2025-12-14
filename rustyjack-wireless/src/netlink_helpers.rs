use std::process::Command;
use crate::error::{Result, WirelessError};

pub fn netlink_set_interface_up(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_up(interface)
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to set {} up: {}", interface, e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::set_interface_up(interface)
                        .await
                        .map_err(|e| WirelessError::System(format!("Failed to set {} up: {}", interface, e)))
                })
        })
}

pub fn netlink_set_interface_down(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_down(interface)
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to set {} down: {}", interface, e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::set_interface_down(interface)
                        .await
                        .map_err(|e| WirelessError::System(format!("Failed to set {} down: {}", interface, e)))
                })
        })
}

pub fn netlink_flush_addresses(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::flush_addresses(interface)
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to flush addresses on {}: {}", interface, e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::flush_addresses(interface)
                        .await
                        .map_err(|e| WirelessError::System(format!("Failed to flush addresses on {}: {}", interface, e)))
                })
        })
}

pub fn netlink_add_address(interface: &str, addr: std::net::IpAddr, prefix_len: u8) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::add_address(interface, addr, prefix_len)
                    .await
                    .map_err(|e| WirelessError::System(format!("Failed to add {}/{} to {}: {}", addr, prefix_len, interface, e)))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()
                .map_err(|e| WirelessError::System(format!("Failed to create runtime: {}", e)))?
                .block_on(async {
                    rustyjack_netlink::add_address(interface, addr, prefix_len)
                        .await
                        .map_err(|e| WirelessError::System(format!("Failed to add {}/{} to {}: {}", addr, prefix_len, interface, e)))
                })
        })
}
