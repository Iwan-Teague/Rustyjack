use crate::error::{Result, WirelessError};

#[allow(dead_code)]
pub fn rfkill_block(idx: u32) -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.block(idx)
        .map_err(|e| WirelessError::System(format!("Failed to block rfkill {}: {}", idx, e)))
}

pub fn rfkill_unblock(idx: u32) -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.unblock(idx)
        .map_err(|e| WirelessError::System(format!("Failed to unblock rfkill {}: {}", idx, e)))
}

pub fn rfkill_unblock_all() -> Result<()> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.unblock_all()
        .map_err(|e| WirelessError::System(format!("Failed to unblock all rfkill: {}", e)))
}

pub fn rfkill_list() -> Result<Vec<rustyjack_netlink::RfkillDevice>> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.list()
        .map_err(|e| WirelessError::System(format!("Failed to list rfkill devices: {}", e)))
}

#[allow(dead_code)]
pub fn rfkill_find_index(interface: &str) -> Result<Option<u32>> {
    use rustyjack_netlink::RfkillManager;
    let mgr = RfkillManager::new();
    mgr.find_index_by_interface(interface).map_err(|e| {
        WirelessError::System(format!(
            "Failed to find rfkill index for {}: {}",
            interface, e
        ))
    })
}
