use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use nix::poll::{poll, PollFd, PollFlags};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::netlink_helpers::rfkill_find_index;
use crate::system::{
    dns::DnsManager, ops::ErrorEntry, preference::PreferenceManager, routing::RouteManager, NetOps,
    RealNetOps,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionDhcpInfo {
    pub ip: Option<std::net::Ipv4Addr>,
    pub gateway: Option<std::net::Ipv4Addr>,
    pub dns_servers: Vec<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSelectionOutcome {
    pub interface: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub dhcp: Option<SelectionDhcpInfo>,
    pub carrier: Option<bool>,
    pub notes: Vec<String>,
    pub errors: Vec<ErrorEntry>,
}

pub fn select_interface<F>(
    root: PathBuf,
    iface: &str,
    progress: Option<&mut F>,
) -> Result<InterfaceSelectionOutcome>
where
    F: FnMut(&str, u8, &str),
{
    let ops = Arc::new(RealNetOps) as Arc<dyn NetOps>;
    select_interface_with_ops(ops, root, iface, progress)
}

pub fn select_interface_with_ops<F>(
    ops: Arc<dyn NetOps>,
    root: PathBuf,
    iface: &str,
    mut progress: Option<&mut F>,
) -> Result<InterfaceSelectionOutcome>
where
    F: FnMut(&str, u8, &str),
{
    let mut outcome = InterfaceSelectionOutcome {
        interface: iface.to_string(),
        allowed: Vec::new(),
        blocked: Vec::new(),
        dhcp: None,
        carrier: None,
        notes: Vec::new(),
        errors: Vec::new(),
    };

    let prefs = PreferenceManager::new(root.clone());
    let dns = DnsManager::new(PathBuf::from("/etc/resolv.conf"));
    let routes = RouteManager::new(Arc::clone(&ops));

    emit_progress(&mut progress, "validate", 5, &format!("Validating {}", iface));

    // Step 1: validate + snapshot
    if !ops.interface_exists(iface) {
        bail!("Interface {} does not exist", iface);
    }

    let interfaces = ops
        .list_interfaces()
        .context("failed to list interfaces")?;
    let selected = interfaces
        .iter()
        .find(|intf| intf.name == iface)
        .ok_or_else(|| anyhow!("Interface {} not found in snapshot", iface))?;
    let is_wireless = selected.is_wireless;

    let other_ifaces: Vec<String> = interfaces
        .iter()
        .filter(|intf| intf.name != iface)
        .map(|intf| intf.name.clone())
        .collect();

    if is_wireless {
        // Snapshot rfkill before changes
        if let Some(state) = read_rfkill_state(iface)? {
            if state.hard.unwrap_or(false) {
                bail!("Interface {} is hard-blocked by rfkill", iface);
            }
        }
    }

    emit_progress(
        &mut progress,
        "deactivate",
        25,
        "Disabling other interfaces",
    );

    // Step 2: deactivate others
    for other in &other_ifaces {
        ops.release_dhcp(other)
            .context(format!("failed to release DHCP on {}", other))?;

        if let Err(e) = ops.flush_addresses(other) {
            warn!("Failed to flush addresses on {}: {}", other, e);
        }

        if let Err(e) = routes.delete_default_route(other) {
            debug!("No default route to delete for {}: {}", other, e);
        }

        if let Err(e) = ops.apply_nm_managed(other, false) {
            warn!("Failed to set {} unmanaged via NetworkManager: {}", other, e);
        }

        ops.bring_down(other)
            .context(format!("failed to bring {} DOWN", other))?;

        if ops.is_wireless(other) {
            if let Err(e) = ops.set_rfkill_block(other, true) {
                warn!("Failed to rfkill block {}: {}", other, e);
            }
        }

        wait_for_admin_state(&*ops, other, false, Duration::from_secs(5))
            .context(format!("timeout waiting for {} to go DOWN", other))?;

        outcome.blocked.push(other.clone());
    }

    emit_progress(
        &mut progress,
        "prepare",
        55,
        &format!("Bringing {} UP", iface),
    );

    // Step 3: prepare selected interface
    if is_wireless {
        if let Err(e) = ops.set_rfkill_block(iface, false) {
            bail!("Failed to clear rfkill for {}: {}", iface, e);
        }
        wait_for_rfkill(iface, Duration::from_secs(2))
            .context(format!("rfkill unblock did not complete for {}", iface))?;
    }

    if let Err(e) = ops.apply_nm_managed(iface, false) {
        bail!("Failed to set {} unmanaged via NetworkManager: {}", iface, e);
    }

    ops.bring_up(iface)
        .context(format!("failed to bring {} UP", iface))?;
    wait_for_admin_state(&*ops, iface, true, Duration::from_secs(10))
        .context(format!("timeout waiting for {} to become UP", iface))?;
    outcome.allowed.push(iface.to_string());

    // Step 4: wired connectivity (wireless remains passive)
    emit_progress(
        &mut progress,
        "connectivity",
        75,
        if is_wireless {
            "Wireless interface ready (no auto-connect)"
        } else {
            "Checking carrier and DHCP"
        },
    );

    if !is_wireless {
        let carrier = ops
            .has_carrier(iface)
            .context("failed to read carrier state")?
            .unwrap_or(false);
        outcome.carrier = Some(carrier);

        if !carrier {
            outcome
                .notes
                .push("No carrier detected; leaving interface UP without IP".to_string());
        } else {
            let lease = ops
                .acquire_dhcp(iface, Duration::from_secs(30))
                .context("DHCP failed")?;

            if let Some(gw) = lease.gateway {
                routes
                    .set_default_route(iface, gw, 100)
                    .context("failed to set default route")?;
            }

            if !lease.dns_servers.is_empty() {
                dns.set_dns(&lease.dns_servers)
                    .context("failed to write DNS servers")?;
            }

            outcome.dhcp = Some(SelectionDhcpInfo {
                ip: Some(lease.ip),
                gateway: lease.gateway,
                dns_servers: lease.dns_servers.clone(),
            });
        }
    }

    emit_progress(
        &mut progress,
        "verify",
        90,
        "Verifying interface invariants",
    );

    // Step 5: verify invariants
    verify_single_admin_up(&*ops, iface, &other_ifaces)?;

    if is_wireless {
        if let Some(addr) = ops
            .get_ipv4_address(iface)
            .context("failed to query IP state")?
        {
            bail!(
                "Wireless interface {} already has IP {} (auto-connect detected)",
                iface,
                addr
            );
        }
    } else if let Some(ref dhcp) = outcome.dhcp {
        let ip = ops
            .get_ipv4_address(iface)
            .context("failed to read DHCP address")?;
        if dhcp.ip.is_some() && ip.is_none() {
            bail!("DHCP reported an address but none is configured on {}", iface);
        }
    }

    emit_progress(&mut progress, "persist", 100, "Persisting preference");

    // Step 6: persist preference
    prefs.set_preferred(iface)?;
    crate::system::write_interface_preference(&root, "system_preferred", iface)
        .context("failed to write preference file")?;

    info!("Interface {} selected successfully", iface);
    Ok(outcome)
}

fn emit_progress<F>(progress: &mut Option<&mut F>, phase: &str, percent: u8, message: &str)
where
    F: FnMut(&str, u8, &str),
{
    if let Some(cb) = progress.as_deref_mut() {
        cb(phase, percent, message);
    }
}

fn verify_single_admin_up(ops: &dyn NetOps, selected: &str, others: &[String]) -> Result<()> {
    let mut up_interfaces = Vec::new();
    for name in std::iter::once(selected.to_string()).chain(others.to_owned()) {
        if ops.admin_is_up(&name)? {
            up_interfaces.push(name);
        }
    }

    if up_interfaces.len() != 1 || up_interfaces[0] != selected {
        bail!(
            "Invariant violated: expected only {} admin-UP, found {:?}",
            selected,
            up_interfaces
        );
    }
    Ok(())
}

#[derive(Debug, Default)]
struct RfkillState {
    soft: Option<bool>,
    hard: Option<bool>,
}

fn read_rfkill_state(iface: &str) -> Result<Option<RfkillState>> {
    let Some(idx) = rfkill_find_index(iface)? else {
        return Ok(None);
    };
    let soft_path = format!("/sys/class/rfkill/rfkill{}/soft", idx);
    let hard_path = format!("/sys/class/rfkill/rfkill{}/hard", idx);

    let soft = std::fs::read_to_string(&soft_path)
        .ok()
        .and_then(|c| match c.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        });
    let hard = std::fs::read_to_string(&hard_path)
        .ok()
        .and_then(|c| match c.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        });

    Ok(Some(RfkillState { soft, hard }))
}

fn wait_for_rfkill(iface: &str, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if let Some(state) = read_rfkill_state(iface)? {
            if state.hard.unwrap_or(false) {
                bail!("rfkill hard block detected on {}", iface);
            }
            if state.soft == Some(false) || state.soft.is_none() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            bail!("rfkill unblock timed out for {}", iface);
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_admin_state(
    ops: &dyn NetOps,
    iface: &str,
    desired_up: bool,
    timeout: Duration,
) -> Result<()> {
    if ops.admin_is_up(iface)? == desired_up {
        return Ok(());
    }

    let start = Instant::now();
    let mut watcher = LinkEventWatcher::new().ok();
    let mut buf = BytesMut::with_capacity(8192);
    buf.reserve(8192);

    loop {
        if ops.admin_is_up(iface)? == desired_up {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            bail!(
                "Timed out waiting for {} to become {}",
                iface,
                if desired_up { "UP" } else { "DOWN" }
            );
        }

        if let Some(w) = watcher.as_mut() {
            let remaining = timeout
                .saturating_sub(start.elapsed())
                .as_millis()
                .clamp(1, i32::MAX as u128) as i32;
            let mut fds = [PollFd::new(w.fd(), PollFlags::POLLIN)];
            match poll(&mut fds, remaining) {
                Ok(ready) if ready > 0 => {
                    let messages = w.recv(&mut buf)?;
                    for msg in messages {
                        if let Some(state) = parse_link_state(&msg, iface) {
                            if state.admin_up == desired_up {
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Link watcher poll error: {}", e);
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[derive(Debug)]
struct LinkState {
    admin_up: bool,
    carrier: Option<bool>,
}

fn parse_link_state(
    msg: &netlink_packet_core::NetlinkMessage<netlink_packet_route::RtnlMessage>,
    target_iface: &str,
) -> Option<LinkState> {
    use netlink_packet_route::link::nlas::LinkAttribute;
    use netlink_packet_route::link::state::State;
    use netlink_packet_route::RtnlMessage;
    use netlink_packet_core::NetlinkPayload;

    match &msg.payload {
        NetlinkPayload::InnerMessage(RtnlMessage::NewLink(link)) => {
            let name = link.nlas.iter().find_map(|nla| {
                if let LinkAttribute::IfName(name) = nla {
                    Some(name.clone())
                } else {
                    None
                }
            })?;

            if name != target_iface {
                return None;
            }

            let admin_up = (link.header.flags & libc::IFF_UP as u32) != 0;

            let carrier = link.nlas.iter().find_map(|nla| match nla {
                LinkAttribute::Carrier(v) => Some(*v != 0),
                LinkAttribute::OperState(state) => match state {
                    State::Up => Some(true),
                    State::Down | State::Dormant | State::NotPresent => Some(false),
                    _ => None,
                },
                _ => None,
            });

            Some(LinkState { admin_up, carrier })
        }
        _ => None,
    }
}

struct LinkEventWatcher {
    socket: netlink_sys::Socket,
}

impl LinkEventWatcher {
    fn new() -> Result<Self> {
        let mut socket =
            netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_ROUTE).context("netlink socket")?;
        let groups = libc::RTMGRP_LINK as u32;
        socket
            .bind(&netlink_sys::SocketAddr::new(0, groups))
            .context("bind netlink socket")?;
        socket
            .set_non_blocking(true)
            .context("set netlink socket non-blocking")?;
        Ok(Self { socket })
    }

    fn fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }

    fn recv(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Vec<netlink_packet_core::NetlinkMessage<netlink_packet_route::RtnlMessage>>> {
        use netlink_packet_core::NetlinkMessage;
        use netlink_packet_core::NetlinkPayload;
        use netlink_packet_core::NetlinkBuffer;
        use netlink_packet_route::RtnlMessage;

        buf.clear();
        buf.reserve(4096);
        match self.socket.recv(buf, 0) {
            Ok(size) => {
                buf.truncate(size);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(Vec::new());
                }
                return Err(anyhow!("netlink recv failed: {}", e));
            }
        }

        let mut messages = Vec::new();
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &buf[offset..];
            let header = NetlinkBuffer::new_checked(slice)
                .map_err(|e| anyhow!("failed to parse netlink buffer: {}", e))?;
            let length = header.length() as usize;
            if length == 0 || length > slice.len() {
                break;
            }
            let msg = NetlinkMessage::<RtnlMessage>::deserialize(&slice[..length])
                .map_err(|e| anyhow!("failed to deserialize netlink message: {}", e))?;

            // Skip ACK/Done messages
            if matches!(msg.payload, NetlinkPayload::Done(_)) {
                break;
            }

            messages.push(msg);

            let aligned = (length + 3) & !3;
            offset += aligned;
        }

        Ok(messages)
    }
}
