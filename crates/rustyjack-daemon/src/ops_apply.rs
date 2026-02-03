use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::config::OPS_OVERRIDE_FILENAME;
use crate::ops::OpsConfig;
use crate::state::DaemonState;
use rustyjack_ipc::JobKind;

use rustyjack_core::mount::{list_mounts_under, unmount, MountPolicy, UnmountRequest};
use rustyjack_core::netlink_helpers::{netlink_bridge_delete, netlink_set_interface_down};
use rustyjack_core::system::ops::{InterfaceSummary, NetOps, RealNetOps};
use rustyjack_core::system::PreferenceManager;
use rustyjack_core::system::{
    enable_ip_forwarding, stop_arp_spoof, stop_dns_spoof, stop_pcap_capture,
};
use rustyjack_netlink::{IptablesManager, Table};

pub async fn apply_ops_delta(
    previous: OpsConfig,
    next: OpsConfig,
    state: &DaemonState,
) -> Result<()> {
    let net_ops = RealNetOps;
    let mut errors: Vec<String> = Vec::new();

    if previous.wifi_ops && !next.wifi_ops {
        state
            .jobs
            .cancel_where(|kind| {
                matches!(kind, JobKind::WifiScan { .. } | JobKind::WifiConnect { .. })
            })
            .await;
        if let Err(err) = disable_wireless_interfaces(&net_ops) {
            errors.push(format!("disable wifi: {err}"));
        }
        if let Err(err) = clear_active_wireless(&net_ops, &state.config.root_path) {
            errors.push(format!("clear wireless preference: {err}"));
        }
    }

    if !previous.wifi_ops && next.wifi_ops {
        if let Err(err) = set_wireless_rfkill(&net_ops, false) {
            errors.push(format!("unblock wifi rfkill: {err}"));
        }
    }

    if previous.eth_ops && !next.eth_ops {
        state
            .jobs
            .cancel_where(|kind| matches!(kind, JobKind::InterfaceSelect { .. }))
            .await;
        if let Err(err) = disable_wired_interfaces(&net_ops) {
            errors.push(format!("disable ethernet: {err}"));
        }
        if let Err(err) = clear_active_interface(&state.config.root_path) {
            errors.push(format!("clear active interface: {err}"));
        }
    }

    if previous.hotspot_ops && !next.hotspot_ops {
        state
            .jobs
            .cancel_where(|kind| matches!(kind, JobKind::HotspotStart { .. }))
            .await;
        if let Err(err) = rustyjack_core::services::hotspot::stop() {
            errors.push(format!("stop hotspot: {err}"));
        }
    }

    if previous.portal_ops && !next.portal_ops {
        state
            .jobs
            .cancel_where(|kind| matches!(kind, JobKind::PortalStart { .. }))
            .await;
        if let Err(err) = rustyjack_core::services::portal::stop() {
            errors.push(format!("stop portal: {err}"));
        }
    }

    if previous.storage_ops && !next.storage_ops {
        state
            .jobs
            .cancel_where(|kind| {
                matches!(
                    kind,
                    JobKind::MountStart { .. } | JobKind::UnmountStart { .. }
                )
            })
            .await;
        if let Err(err) = unmount_all(&state.config.root_path) {
            errors.push(format!("unmount storage: {err}"));
        }
    }

    if previous.update_ops && !next.update_ops {
        state
            .jobs
            .cancel_where(|kind| matches!(kind, JobKind::SystemUpdate { .. }))
            .await;
    }

    if previous.offensive_ops && !next.offensive_ops {
        state
            .jobs
            .cancel_where(|kind| matches!(kind, JobKind::ScanRun { .. }))
            .await;
        if let Err(err) = stop_dns_spoof() {
            errors.push(format!("stop dns spoof: {err}"));
        }
        if let Err(err) = stop_arp_spoof() {
            errors.push(format!("stop arp spoof: {err}"));
        }
        if let Err(err) = stop_pcap_capture() {
            errors.push(format!("stop pcap capture: {err}"));
        }
        if let Err(err) = enable_ip_forwarding(false) {
            errors.push(format!("disable ip forwarding: {err}"));
        }
        if let Err(err) = cleanup_bridge() {
            errors.push(format!("cleanup bridge: {err}"));
        }
    }

    if (previous.hotspot_ops && !next.hotspot_ops)
        || (previous.portal_ops && !next.portal_ops)
        || (previous.offensive_ops && !next.offensive_ops)
    {
        if let Err(err) = flush_nf_tables() {
            errors.push(format!("flush nf_tables: {err}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}

pub fn write_ops_override(root: &Path, ops: OpsConfig) -> Result<PathBuf> {
    let path = root.join(OPS_OVERRIDE_FILENAME);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(&ops).context("serialize ops override")?;
    atomic_write(&path, &payload)?;
    Ok(path)
}

fn disable_wireless_interfaces(ops: &RealNetOps) -> Result<()> {
    disable_interfaces(ops, |iface| iface.is_wireless, Some(true))
}

fn disable_wired_interfaces(ops: &RealNetOps) -> Result<()> {
    disable_interfaces(ops, |iface| !iface.is_wireless, None)
}

fn disable_interfaces<F>(ops: &RealNetOps, filter: F, rfkill_block: Option<bool>) -> Result<()>
where
    F: Fn(&InterfaceSummary) -> bool,
{
    let mut errors = Vec::new();
    let interfaces = ops.list_interfaces().context("list interfaces")?;
    for iface in interfaces {
        if !filter(&iface) {
            continue;
        }
        if let Err(err) = ops.release_dhcp(&iface.name) {
            errors.push(format!("release dhcp {}: {err}", iface.name));
        }
        if let Err(err) = ops.flush_addresses(&iface.name) {
            errors.push(format!("flush addresses {}: {err}", iface.name));
        }
        if let Err(err) = ops.bring_down(&iface.name) {
            errors.push(format!("bring down {}: {err}", iface.name));
        }
        if let Some(blocked) = rfkill_block {
            if let Err(err) = ops.set_rfkill_block(&iface.name, blocked) {
                errors.push(format!("rfkill {} {}: {err}", iface.name, blocked));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}

fn set_wireless_rfkill(ops: &RealNetOps, blocked: bool) -> Result<()> {
    let mut errors = Vec::new();
    let interfaces = ops.list_interfaces().context("list interfaces")?;
    for iface in interfaces {
        if !iface.is_wireless {
            continue;
        }
        if let Err(err) = ops.set_rfkill_block(&iface.name, blocked) {
            errors.push(format!("rfkill {} {}: {err}", iface.name, blocked));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}

fn clear_active_interface(root: &Path) -> Result<()> {
    let prefs = PreferenceManager::new(root.to_path_buf());
    prefs.clear_preferred()
}

fn clear_active_wireless(ops: &RealNetOps, root: &Path) -> Result<()> {
    let prefs = PreferenceManager::new(root.to_path_buf());
    if let Some(iface) = prefs.get_preferred()? {
        if ops.is_wireless(&iface) {
            prefs.clear_preferred()?;
        }
    }
    Ok(())
}

fn unmount_all(root: &Path) -> Result<()> {
    let policy = MountPolicy::for_root(root);
    let mut mounts = list_mounts_under(&policy)?;
    mounts.sort_by_key(|entry| std::cmp::Reverse(entry.mountpoint.as_os_str().len()));
    for mount in mounts {
        let mountpoint = mount.mountpoint;
        let display = mountpoint.display().to_string();
        let req = UnmountRequest {
            mountpoint,
            detach: false,
        };
        unmount(&policy, req).with_context(|| format!("unmount {}", display))?;
    }
    Ok(())
}

fn cleanup_bridge() -> Result<()> {
    let br_path = Path::new("/sys/class/net/br0");
    if !br_path.exists() {
        return Ok(());
    }
    let _ = netlink_set_interface_down("br0");
    let _ = netlink_bridge_delete("br0");

    let entries = fs::read_dir("/sys/class/net").context("read interfaces")?;
    for entry in entries {
        let entry = entry.context("read interface entry")?;
        let name = entry.file_name().to_string_lossy().to_string();
        let master = entry.path().join("master");
        if let Ok(target) = fs::read_link(&master) {
            if target.file_name().and_then(|n| n.to_str()) == Some("br0") {
                let _ = netlink_set_interface_down(&name);
            }
        }
    }

    Ok(())
}

fn flush_nf_tables() -> Result<()> {
    let ipt = IptablesManager::new().context("init nf_tables manager")?;
    let _ = ipt.flush_table(Table::Nat);
    let _ = ipt.flush_table(Table::Filter);
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing parent dir for {}", path.display()))?;
    let tmp = temp_path(path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .with_context(|| format!("open {}", tmp.display()))?;
    file.write_all(data)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    fsync_parent(parent)?;
    Ok(())
}

fn fsync_parent(parent: &Path) -> Result<()> {
    let dir = File::open(parent).with_context(|| format!("open {}", parent.display()))?;
    dir.sync_all()
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

fn temp_path(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ops_override");
    let tmp_name = format!("{}.new", file_name);
    dest.with_file_name(tmp_name)
}
