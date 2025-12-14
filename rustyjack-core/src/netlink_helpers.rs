use anyhow::Result;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
pub fn netlink_set_interface_up(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_up(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to set {} up: {}", interface, e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::set_interface_up(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to set {} up: {}", interface, e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn netlink_set_interface_down(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::set_interface_down(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to set {} down: {}", interface, e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::set_interface_down(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to set {} down: {}", interface, e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn netlink_flush_addresses(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::flush_addresses(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to flush addresses on {}: {}", interface, e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::flush_addresses(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to flush addresses on {}: {}", interface, e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn netlink_add_address(interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::add_address(interface, addr, prefix_len)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to add {}/{} to {}: {}", addr, prefix_len, interface, e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::add_address(interface, addr, prefix_len)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to add {}/{} to {}: {}", addr, prefix_len, interface, e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn netlink_list_interfaces() -> Result<Vec<rustyjack_netlink::InterfaceInfo>> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::list_interfaces()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to list interfaces: {}", e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::list_interfaces()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to list interfaces: {}", e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn netlink_dhcp_release(interface: &str) -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|handle| {
            handle.block_on(async {
                rustyjack_netlink::dhcp_release(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to release DHCP on {}: {}", interface, e))
            })
        })
        .unwrap_or_else(|_| {
            tokio::runtime::Runtime::new()?.block_on(async {
                rustyjack_netlink::dhcp_release(interface)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to release DHCP on {}: {}", interface, e))
            })
        })
}

#[cfg(target_os = "linux")]
pub fn rfkill_block(idx: u32) -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.block(idx)
        .map_err(|e| anyhow::anyhow!("Failed to block rfkill {}: {}", idx, e))
}

#[cfg(target_os = "linux")]
pub fn rfkill_unblock(idx: u32) -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.unblock(idx)
        .map_err(|e| anyhow::anyhow!("Failed to unblock rfkill {}: {}", idx, e))
}

#[cfg(target_os = "linux")]
pub fn rfkill_block_all() -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.block_all()
        .map_err(|e| anyhow::anyhow!("Failed to block all rfkill: {}", e))
}

#[cfg(target_os = "linux")]
pub fn rfkill_unblock_all() -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.unblock_all()
        .map_err(|e| anyhow::anyhow!("Failed to unblock all rfkill: {}", e))
}

#[cfg(target_os = "linux")]
pub fn rfkill_find_index(interface: &str) -> Result<Option<u32>> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.find_index_by_interface(interface)
        .map_err(|e| anyhow::anyhow!("Failed to find rfkill index for {}: {}", interface, e))
}

#[cfg(target_os = "linux")]
pub fn process_kill_pattern(pattern: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill(pattern)
        .map_err(|e| anyhow::anyhow!("Failed to kill processes matching '{}': {}", pattern, e))
}

#[cfg(target_os = "linux")]
pub fn process_kill_pattern_force(pattern: &str) -> Result<usize> {
    use rustyjack_netlink::process;
    process::pkill_force(pattern)
        .map_err(|e| anyhow::anyhow!("Failed to kill -9 processes matching '{}': {}", pattern, e))
}

#[cfg(target_os = "linux")]
pub fn process_find_pattern(pattern: &str) -> Result<Vec<i32>> {
    use rustyjack_netlink::process;
    process::pgrep(pattern)
        .map_err(|e| anyhow::anyhow!("Failed to find processes matching '{}': {}", pattern, e))
}

#[cfg(target_os = "linux")]
pub fn process_running(pattern: &str) -> Result<bool> {
    use rustyjack_netlink::process;
    process::process_running(pattern)
        .map_err(|e| anyhow::anyhow!("Failed to check if process '{}' is running: {}", pattern, e))
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_find_index(_interface: &str) -> Result<Option<u32>> {
    anyhow::bail!("rfkill operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn process_kill_pattern(_pattern: &str) -> Result<usize> {
    anyhow::bail!("process operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn process_kill_pattern_force(_pattern: &str) -> Result<usize> {
    anyhow::bail!("process operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn process_find_pattern(_pattern: &str) -> Result<Vec<i32>> {
    anyhow::bail!("process operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn process_running(_pattern: &str) -> Result<bool> {
    anyhow::bail!("process operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn netlink_set_interface_down(_interface: &str) -> Result<()> {
    anyhow::bail!("netlink operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn netlink_flush_addresses(_interface: &str) -> Result<()> {
    anyhow::bail!("netlink operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn netlink_add_address(_interface: &str, _addr: IpAddr, _prefix_len: u8) -> Result<()> {
    anyhow::bail!("netlink operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn netlink_dhcp_release(_interface: &str) -> Result<()> {
    anyhow::bail!("netlink operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_block(_idx: u32) -> Result<()> {
    anyhow::bail!("rfkill operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_unblock(_idx: u32) -> Result<()> {
    anyhow::bail!("rfkill operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_block_all() -> Result<()> {
    anyhow::bail!("rfkill operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_unblock_all() -> Result<()> {
    anyhow::bail!("rfkill operations only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn rfkill_find_index(_interface: &str) -> Result<Option<u32>> {
    anyhow::bail!("rfkill operations only supported on Linux")
}
