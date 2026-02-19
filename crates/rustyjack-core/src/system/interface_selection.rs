use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use nix::poll::{poll, PollFd, PollFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{debug, info, warn};

use crate::cancel::{check_cancel, CancelFlag};
use crate::netlink_helpers::rfkill_find_index;
use crate::system::wifi_backend_from_env;
use crate::system::{
    dns::DnsManager, ops::ErrorEntry, preference::PreferenceManager, routing::RouteManager, NetOps,
    RealNetOps,
};
use rustyjack_netlink::{station_disconnect_with_backend, StationBackendKind};

static INTERFACE_SWITCH_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionDhcpInfo {
    pub ip: Option<std::net::Ipv4Addr>,
    pub gateway: Option<std::net::Ipv4Addr>,
    pub dns_servers: Vec<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionInterfaceStatus {
    pub interface: String,
    pub is_up: bool,
    pub oper_state: String,
    pub carrier: Option<bool>,
    pub ip: Option<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRollbackInfo {
    pub attempted: bool,
    pub restored_previous: bool,
    pub previous_interface: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSelectionOutcome {
    pub interface: String,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub dhcp: Option<SelectionDhcpInfo>,
    pub carrier: Option<bool>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<ErrorEntry>,
    pub previous_interface: Option<String>,
    pub selected_status: Option<SelectionInterfaceStatus>,
    pub rollback: SelectionRollbackInfo,
}

pub fn select_interface<F>(
    root: PathBuf,
    iface: &str,
    progress: Option<&mut F>,
    cancel: Option<&CancelFlag>,
) -> Result<InterfaceSelectionOutcome>
where
    F: FnMut(&str, u8, &str),
{
    let ops = Arc::new(RealNetOps) as Arc<dyn NetOps>;
    select_interface_with_ops(ops, root, iface, progress, cancel)
}

#[tracing::instrument(target = "net", skip(ops, root, progress))]
pub fn select_interface_with_ops<F>(
    ops: Arc<dyn NetOps>,
    root: PathBuf,
    iface: &str,
    mut progress: Option<&mut F>,
    cancel: Option<&CancelFlag>,
) -> Result<InterfaceSelectionOutcome>
where
    F: FnMut(&str, u8, &str),
{
    let lock = INTERFACE_SWITCH_LOCK.get_or_init(|| StdMutex::new(()));
    let _switch_guard = lock.lock().unwrap_or_else(|e| e.into_inner());

    check_cancel(cancel)?;

    let prefs = PreferenceManager::new(root.clone());
    let dns = DnsManager::new(root.join("resolv.conf"));
    let routes = RouteManager::new(Arc::clone(&ops));

    let previous_preference = prefs.get_preferred().ok().flatten();
    let previous_system_preference =
        crate::system::read_interface_preference(&root, "system_preferred")
            .ok()
            .flatten();

    let mut outcome = InterfaceSelectionOutcome {
        interface: iface.to_string(),
        allowed: Vec::new(),
        blocked: Vec::new(),
        dhcp: None,
        carrier: None,
        notes: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
        previous_interface: None,
        selected_status: None,
        rollback: SelectionRollbackInfo {
            attempted: false,
            restored_previous: false,
            previous_interface: None,
            message: None,
        },
    };

    emit_progress(
        &mut progress,
        "phase_a",
        5,
        &format!("Phase A: validating {}", iface),
    );
    check_cancel(cancel)?;

    let uplinks = list_uplink_interfaces(&*ops)?;
    if uplinks.is_empty() {
        bail!("No physical uplink interfaces are available");
    }

    let selected = uplinks
        .iter()
        .find(|intf| intf.name == iface)
        .ok_or_else(|| anyhow!("Interface {} not found in physical uplink list", iface))?;

    if let Some(caps) = selected.capabilities.as_ref() {
        if !caps.is_physical {
            bail!("Interface {} is not a physical uplink", iface);
        }
    }

    let is_wireless = selected.is_wireless;
    let other_ifaces: Vec<String> = uplinks
        .iter()
        .filter(|intf| intf.name != iface)
        .map(|intf| intf.name.clone())
        .collect();

    let previous_active = determine_previous_active_interface(
        &*ops,
        &routes,
        &uplinks,
        previous_preference.as_deref(),
    )?;
    outcome.previous_interface = previous_active.clone();
    outcome.rollback.previous_interface = previous_active.clone();

    emit_progress(
        &mut progress,
        "phase_a",
        20,
        "Phase A: preflighting target interface",
    );
    check_cancel(cancel)?;

    if is_wireless {
        preflight_wireless_target(&*ops, iface, cancel, &mut outcome)?;
    }

    emit_progress(
        &mut progress,
        "phase_a",
        38,
        "Phase A: bringing target admin-UP",
    );
    check_cancel(cancel)?;

    prepare_target_interface(&*ops, &routes, iface, cancel, &mut outcome)?;
    outcome.allowed = vec![iface.to_string()];

    emit_progress(
        &mut progress,
        "phase_b",
        55,
        "Phase B: isolating non-target uplinks",
    );

    let commit_result = (|| -> Result<()> {
        deactivate_non_target_uplinks(&*ops, &routes, &other_ifaces, cancel, &mut outcome)?;

        emit_progress(
            &mut progress,
            "phase_b",
            72,
            "Phase B: configuring target connectivity",
        );
        check_cancel(cancel)?;

        configure_target_connectivity(
            &*ops,
            &routes,
            &dns,
            iface,
            is_wireless,
            cancel,
            &mut outcome,
        )?;

        emit_progress(
            &mut progress,
            "verify",
            86,
            "Verifying exclusive network state",
        );
        check_cancel(cancel)?;

        verify_exclusive_network_state(&*ops, iface, &other_ifaces)?;
        outcome.blocked = other_ifaces.clone();

        emit_progress(
            &mut progress,
            "persist",
            94,
            "Persisting interface preference",
        );
        check_cancel(cancel)?;

        prefs
            .set_preferred(iface)
            .context("failed to persist preferred interface")?;
        crate::system::write_interface_preference(&root, "system_preferred", iface)
            .context("failed to write preference file")?;

        outcome.selected_status = Some(snapshot_interface_status(&*ops, iface)?);
        Ok(())
    })();

    if let Err(err) = commit_result {
        let err_text = err.to_string();
        let verification_failed = err_text
            .to_ascii_lowercase()
            .contains("verification failed");

        let rollback = if verification_failed {
            emit_progress(
                &mut progress,
                "rollback",
                92,
                "Rollback: forcing safe all-down state",
            );
            rollback_to_safe_all_down(&ops, &uplinks, cancel, &mut outcome)
        } else {
            emit_progress(
                &mut progress,
                "rollback",
                92,
                "Rollback: restoring previous interface",
            );
            rollback_after_commit_failure(
                &ops,
                &prefs,
                &routes,
                &dns,
                &root,
                iface,
                previous_active.as_deref(),
                previous_preference.as_deref(),
                previous_system_preference.as_deref(),
                cancel,
                &mut outcome,
            )
        };
        outcome.rollback = rollback.clone();

        let mut message = if verification_failed {
            format!("Interface switch verification failed: {}", err)
        } else {
            format!("Interface switch failed after isolation: {}", err)
        };
        if rollback.restored_previous {
            if let Some(previous) = rollback.previous_interface.as_deref() {
                message.push_str(&format!(
                    "; rollback restored previous interface {}",
                    previous
                ));
            } else {
                message.push_str("; rollback restored previous interface");
            }
        } else if verification_failed {
            message.push_str("; rollback moved system to safe all-down state");
        } else if rollback.attempted {
            let reason = rollback
                .message
                .clone()
                .unwrap_or_else(|| "unknown rollback failure".to_string());
            message.push_str(&format!("; rollback failed: {}", reason));
        }

        return Err(anyhow!(message));
    }

    emit_progress(&mut progress, "verify", 100, "Switch complete");

    info!(target: "net", iface = %iface, "interface_selected");
    Ok(outcome)
}

fn list_uplink_interfaces(ops: &dyn NetOps) -> Result<Vec<crate::system::ops::InterfaceSummary>> {
    let interfaces = ops.list_interfaces().context("failed to list interfaces")?;
    Ok(interfaces
        .into_iter()
        .filter(|iface| iface.name != "lo")
        .filter(|iface| {
            iface
                .capabilities
                .as_ref()
                .map(|caps| caps.is_physical)
                .unwrap_or(true)
        })
        .collect())
}

fn determine_previous_active_interface(
    ops: &dyn NetOps,
    routes: &RouteManager,
    uplinks: &[crate::system::ops::InterfaceSummary],
    preferred: Option<&str>,
) -> Result<Option<String>> {
    if let Some(pref) = preferred {
        if uplinks.iter().any(|iface| iface.name == pref) {
            return Ok(Some(pref.to_string()));
        }
    }

    if let Ok(Some(route)) = routes.get_default_route() {
        if uplinks.iter().any(|iface| iface.name == route.interface) {
            return Ok(Some(route.interface));
        }
    }

    for iface in uplinks {
        if ops.admin_is_up(&iface.name).unwrap_or(false) {
            return Ok(Some(iface.name.clone()));
        }
    }

    Ok(None)
}

fn preflight_wireless_target(
    ops: &dyn NetOps,
    iface: &str,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    if let Some(state) = read_rfkill_state(iface)? {
        if state.hard.unwrap_or(false) {
            bail!("{}", rfkill_hard_block_error(iface, &state));
        }
    }

    match ops.set_rfkill_block(iface, false) {
        Ok(()) => {
            if let Err(err) = wait_for_rfkill(iface, Duration::from_secs(5), cancel) {
                let msg = err.to_string();
                if msg.to_lowercase().contains("hard-blocked") {
                    bail!("{}", msg);
                }
                push_warning(
                    outcome,
                    format!(
                        "could not fully clear rfkill for {} (continuing): {}",
                        iface, msg
                    ),
                );
            }
        }
        Err(err) => {
            push_warning(
                outcome,
                format!("could not clear rfkill for {} (continuing): {}", iface, err),
            );
        }
    }

    Ok(())
}

fn prepare_target_interface(
    ops: &dyn NetOps,
    routes: &RouteManager,
    iface: &str,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    check_cancel(cancel)?;

    if let Err(err) = ops.release_dhcp(iface) {
        push_warning(
            outcome,
            format!("DHCP release failed for {} (continuing): {}", iface, err),
        );
    }

    if let Err(err) = ops.flush_addresses(iface) {
        push_warning(
            outcome,
            format!("address flush failed for {} (continuing): {}", iface, err),
        );
    }

    if let Err(err) = routes.delete_default_route(iface) {
        debug!(target: "net", iface = %iface, error = %err, "default_route_delete_skipped");
    }

    // Keep target down until all non-target uplinks are isolated.
    if let Err(err) = ops.bring_down(iface) {
        push_warning(
            outcome,
            format!(
                "failed to bring {} DOWN during pre-isolation (continuing): {}",
                iface, err
            ),
        );
    } else if let Err(err) = wait_for_admin_state(ops, iface, false, Duration::from_secs(5), cancel)
    {
        push_warning(
            outcome,
            format!(
                "timeout waiting for {} to become DOWN during pre-isolation: {}",
                iface, err
            ),
        );
    }

    Ok(())
}

fn deactivate_non_target_uplinks(
    ops: &dyn NetOps,
    routes: &RouteManager,
    other_ifaces: &[String],
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    let mut hard_failures = 0usize;

    for other in other_ifaces {
        check_cancel(cancel)?;

        if ops.is_wireless(other) {
            if let Err(err) = stop_wpa_service(other) {
                push_warning(
                    outcome,
                    format!(
                        "failed to stop wpa_supplicant for {} (continuing): {}",
                        other, err
                    ),
                );
            }
            if let Err(err) = disconnect_station_backend(other) {
                push_warning(
                    outcome,
                    format!("disconnect failed for {} (continuing): {}", other, err),
                );
            }
        }

        if let Err(err) = ops.release_dhcp(other) {
            push_warning(
                outcome,
                format!("DHCP release failed for {} (continuing): {}", other, err),
            );
        }

        if let Err(err) = ops.flush_addresses(other) {
            push_warning(
                outcome,
                format!("address flush failed for {} (continuing): {}", other, err),
            );
        }

        if let Err(err) = routes.delete_default_route(other) {
            debug!(target: "net", iface = %other, error = %err, "default_route_delete_skipped");
        }

        if let Err(err) = ops.bring_down(other) {
            push_error(
                outcome,
                other,
                format!("failed to bring DOWN during isolation: {}", err),
            );
            hard_failures += 1;
            continue;
        }

        if let Err(err) = wait_for_admin_state(ops, other, false, Duration::from_secs(5), cancel) {
            push_error(
                outcome,
                other,
                format!("timeout waiting for DOWN state: {}", err),
            );
            hard_failures += 1;
        }

        if ops.is_wireless(other) {
            if let Err(err) = ops.set_rfkill_block(other, true) {
                push_warning(
                    outcome,
                    format!("rfkill block failed for {} (continuing): {}", other, err),
                );
            }
        }
    }

    if hard_failures > 0 {
        bail!(
            "isolation failed on {} non-target interface(s)",
            hard_failures
        );
    }

    Ok(())
}

fn configure_target_connectivity(
    ops: &dyn NetOps,
    routes: &RouteManager,
    dns: &DnsManager,
    iface: &str,
    is_wireless: bool,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    if is_wireless {
        configure_wireless_target(ops, routes, dns, iface, cancel, outcome)
    } else {
        configure_wired_target(ops, routes, dns, iface, cancel, outcome)
    }
}

fn configure_wireless_target(
    ops: &dyn NetOps,
    routes: &RouteManager,
    dns: &DnsManager,
    iface: &str,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    check_cancel(cancel)?;

    ops.set_rfkill_block(iface, false)
        .with_context(|| format!("failed to clear rfkill block on {}", iface))?;
    ops.bring_up(iface)
        .with_context(|| format!("failed to bring {} UP", iface))?;
    wait_for_admin_state(ops, iface, true, Duration::from_secs(10), cancel)
        .with_context(|| format!("timeout waiting for {} to become admin-UP", iface))?;

    start_wpa_service(iface)?;
    outcome
        .notes
        .push(format!("Started wpa_supplicant for {}", iface));

    let lease = ops
        .acquire_dhcp(iface, Duration::from_secs(45))
        .with_context(|| format!("DHCP timed out for Wi-Fi interface {}", iface))?;

    let gateway = lease
        .gateway
        .ok_or_else(|| anyhow!("DHCP lease for {} has no gateway", iface))?;
    routes
        .set_default_route(iface, gateway, 100)
        .with_context(|| format!("failed to set default route for {}", iface))?;

    if !lease.dns_servers.is_empty() {
        dns.set_dns(&lease.dns_servers)
            .context("failed to write DNS servers")?;
    } else {
        push_warning(
            outcome,
            format!("DHCP lease for {} did not include DNS servers", iface),
        );
    }

    outcome.carrier = ops.has_carrier(iface).ok().flatten();
    outcome.dhcp = Some(SelectionDhcpInfo {
        ip: Some(lease.ip),
        gateway: Some(gateway),
        dns_servers: lease.dns_servers.clone(),
    });
    Ok(())
}

fn configure_wired_target(
    ops: &dyn NetOps,
    routes: &RouteManager,
    dns: &DnsManager,
    iface: &str,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    check_cancel(cancel)?;

    ops.bring_up(iface)
        .with_context(|| format!("failed to bring {} UP", iface))?;
    wait_for_admin_state(ops, iface, true, Duration::from_secs(10), cancel)
        .with_context(|| format!("timeout waiting for {} to become admin-UP", iface))?;

    outcome.carrier = ops
        .has_carrier(iface)
        .with_context(|| format!("failed to read carrier state for {}", iface))?;

    if outcome.carrier == Some(false) {
        bail!("No ethernet carrier on {}", iface);
    }

    let lease = ops
        .acquire_dhcp(iface, Duration::from_secs(30))
        .with_context(|| format!("DHCP failed for {}", iface))?;
    let gateway = lease
        .gateway
        .ok_or_else(|| anyhow!("DHCP lease for {} has no gateway", iface))?;
    routes
        .set_default_route(iface, gateway, 100)
        .with_context(|| format!("failed to set default route for {}", iface))?;

    if !lease.dns_servers.is_empty() {
        dns.set_dns(&lease.dns_servers)
            .context("failed to write DNS servers")?;
    } else {
        push_warning(
            outcome,
            format!("DHCP lease for {} did not include DNS servers", iface),
        );
    }

    outcome.dhcp = Some(SelectionDhcpInfo {
        ip: Some(lease.ip),
        gateway: Some(gateway),
        dns_servers: lease.dns_servers.clone(),
    });

    Ok(())
}

fn rollback_to_safe_all_down(
    ops: &Arc<dyn NetOps>,
    uplinks: &[crate::system::ops::InterfaceSummary],
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> SelectionRollbackInfo {
    let mut issues = Vec::new();

    for iface in uplinks {
        if let Err(err) = check_cancel(cancel) {
            issues.push(format!(
                "rollback cancelled while handling {}: {}",
                iface.name, err
            ));
            break;
        }

        if iface.is_wireless {
            if let Err(err) = stop_wpa_service(&iface.name) {
                issues.push(format!(
                    "failed to stop wpa service for {}: {}",
                    iface.name, err
                ));
            }
        }

        if let Err(err) = ops.release_dhcp(&iface.name) {
            issues.push(format!("failed DHCP release for {}: {}", iface.name, err));
        }
        if let Err(err) = ops.flush_addresses(&iface.name) {
            issues.push(format!("failed address flush for {}: {}", iface.name, err));
        }
        if let Err(err) = ops.delete_default_route(&iface.name) {
            issues.push(format!(
                "failed default-route flush for {}: {}",
                iface.name, err
            ));
        }
        if let Err(err) = ops.bring_down(&iface.name) {
            issues.push(format!("failed bring-down for {}: {}", iface.name, err));
        } else if let Err(err) =
            wait_for_admin_state(&**ops, &iface.name, false, Duration::from_secs(5), cancel)
        {
            issues.push(format!("timeout waiting {} DOWN: {}", iface.name, err));
        }

        if iface.is_wireless {
            if let Err(err) = ops.set_rfkill_block(&iface.name, true) {
                issues.push(format!("failed rfkill block for {}: {}", iface.name, err));
            }
        }
    }

    if !issues.is_empty() {
        let msg = issues.join("; ");
        push_warning(
            outcome,
            format!("safe all-down rollback encountered issues: {}", msg),
        );
        SelectionRollbackInfo {
            attempted: true,
            restored_previous: false,
            previous_interface: None,
            message: Some(msg),
        }
    } else {
        SelectionRollbackInfo {
            attempted: true,
            restored_previous: false,
            previous_interface: None,
            message: Some("safe all-down rollback completed".to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn rollback_after_commit_failure(
    ops: &Arc<dyn NetOps>,
    prefs: &PreferenceManager,
    routes: &RouteManager,
    dns: &DnsManager,
    root: &Path,
    target_iface: &str,
    previous_iface: Option<&str>,
    previous_preference: Option<&str>,
    previous_system_preference: Option<&str>,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> SelectionRollbackInfo {
    let mut rollback = SelectionRollbackInfo {
        attempted: true,
        restored_previous: false,
        previous_interface: previous_iface.map(|s| s.to_string()),
        message: None,
    };

    let mut issues = Vec::new();

    if let Err(err) =
        restore_preference_state(prefs, root, previous_preference, previous_system_preference)
    {
        issues.push(format!("failed to restore preference state: {}", err));
    }

    match previous_iface {
        Some(previous) => {
            match restore_previous_interface(
                ops,
                routes,
                dns,
                target_iface,
                previous,
                cancel,
                outcome,
            ) {
                Ok(()) => {
                    rollback.restored_previous = true;
                }
                Err(err) => {
                    issues.push(format!("failed to restore {}: {}", previous, err));
                }
            }
        }
        None => {
            issues.push("no previous interface available for rollback".to_string());
        }
    }

    if !issues.is_empty() {
        let combined = issues.join("; ");
        rollback.message = Some(combined.clone());
        push_warning(
            outcome,
            format!("rollback encountered issues: {}", combined),
        );
    }

    rollback
}

fn restore_preference_state(
    prefs: &PreferenceManager,
    root: &Path,
    previous_preference: Option<&str>,
    previous_system_preference: Option<&str>,
) -> Result<()> {
    match previous_preference {
        Some(iface) => prefs
            .set_preferred(iface)
            .with_context(|| format!("restoring preferred interface {}", iface))?,
        None => prefs
            .clear_preferred()
            .context("clearing preferred interface during rollback")?,
    }

    restore_system_preferred_key(root, previous_system_preference)
}

fn restore_system_preferred_key(root: &Path, iface: Option<&str>) -> Result<()> {
    if let Some(iface) = iface {
        return crate::system::write_interface_preference(root, "system_preferred", iface)
            .with_context(|| format!("restoring system_preferred to {}", iface));
    }

    let pref_path = root.join("wifi").join("interface_preferences.json");
    if !pref_path.exists() {
        return Ok(());
    }

    let content =
        std::fs::read_to_string(&pref_path).context("reading interface preference file")?;
    let mut map: Map<String, Value> = serde_json::from_str(&content).unwrap_or_default();
    map.remove("system_preferred");

    if map.is_empty() {
        std::fs::remove_file(&pref_path).or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        })?;
        return Ok(());
    }

    std::fs::write(
        &pref_path,
        serde_json::to_string_pretty(&Value::Object(map))?,
    )
    .context("writing interface preference file")
}

fn restore_previous_interface(
    ops: &Arc<dyn NetOps>,
    routes: &RouteManager,
    dns: &DnsManager,
    target_iface: &str,
    previous_iface: &str,
    cancel: Option<&CancelFlag>,
    outcome: &mut InterfaceSelectionOutcome,
) -> Result<()> {
    check_cancel(cancel)?;

    if !ops.interface_exists(previous_iface) {
        bail!("previous interface {} no longer exists", previous_iface);
    }

    if ops.is_wireless(previous_iface) {
        if ops.is_rfkill_hard_blocked(previous_iface).unwrap_or(false) {
            bail!(
                "previous wireless interface {} is hard-blocked",
                previous_iface
            );
        }
        if let Err(err) = ops.set_rfkill_block(previous_iface, false) {
            push_warning(
                outcome,
                format!(
                    "could not clear rfkill for rollback on {}: {}",
                    previous_iface, err
                ),
            );
        }
        if let Err(err) = start_wpa_service(previous_iface) {
            push_warning(
                outcome,
                format!(
                    "could not start wpa_supplicant for rollback on {}: {}",
                    previous_iface, err
                ),
            );
        }
    }

    ops.bring_up(previous_iface)
        .with_context(|| format!("failed to bring {} UP during rollback", previous_iface))?;
    wait_for_admin_state(
        &**ops,
        previous_iface,
        true,
        Duration::from_secs(10),
        cancel,
    )
    .with_context(|| format!("{} did not become admin-UP during rollback", previous_iface))?;

    if !ops.is_wireless(previous_iface) {
        let carrier = ops.has_carrier(previous_iface).ok().flatten();
        if carrier != Some(false) {
            match ops.acquire_dhcp(previous_iface, Duration::from_secs(20)) {
                Ok(lease) => {
                    if let Some(gateway) = lease.gateway {
                        if let Err(err) = routes.set_default_route(previous_iface, gateway, 100) {
                            push_warning(
                                outcome,
                                format!(
                                    "rollback route restore failed on {}: {}",
                                    previous_iface, err
                                ),
                            );
                        }
                    }

                    if !lease.dns_servers.is_empty() {
                        if let Err(err) = dns.set_dns(&lease.dns_servers) {
                            push_warning(outcome, format!("rollback DNS restore failed: {}", err));
                        }
                    }
                }
                Err(err) => {
                    push_warning(
                        outcome,
                        format!("rollback DHCP failed on {}: {}", previous_iface, err),
                    );
                }
            }
        }
    }

    if previous_iface != target_iface {
        if let Err(err) = ops.bring_down(target_iface) {
            push_warning(
                outcome,
                format!(
                    "rollback failed to bring target {} down: {}",
                    target_iface, err
                ),
            );
        } else {
            let _ =
                wait_for_admin_state(&**ops, target_iface, false, Duration::from_secs(5), cancel);
        }

        if ops.is_wireless(target_iface) {
            if let Err(err) = stop_wpa_service(target_iface) {
                push_warning(
                    outcome,
                    format!(
                        "rollback failed to stop wpa_supplicant on {}: {}",
                        target_iface, err
                    ),
                );
            }
            if let Err(err) = ops.set_rfkill_block(target_iface, true) {
                push_warning(
                    outcome,
                    format!("rollback failed to rfkill-block {}: {}", target_iface, err),
                );
            }
        }
    }

    if !ops.admin_is_up(previous_iface)? {
        bail!(
            "rollback could not restore admin-UP state for {}",
            previous_iface
        );
    }

    Ok(())
}

fn snapshot_interface_status(ops: &dyn NetOps, iface: &str) -> Result<SelectionInterfaceStatus> {
    let oper_state = ops
        .list_interfaces()
        .ok()
        .and_then(|ifaces| {
            ifaces
                .into_iter()
                .find(|entry| entry.name == iface)
                .map(|entry| entry.oper_state)
        })
        .unwrap_or_else(|| "unknown".to_string());

    Ok(SelectionInterfaceStatus {
        interface: iface.to_string(),
        is_up: ops.admin_is_up(iface)?,
        oper_state,
        carrier: ops.has_carrier(iface).ok().flatten(),
        ip: ops.get_ipv4_address(iface).ok().flatten(),
    })
}

fn disconnect_station_backend(interface: &str) -> Result<()> {
    let mut backend = wifi_backend_from_env();
    if let Err(err) = station_disconnect_with_backend(interface, backend) {
        if backend == StationBackendKind::WpaSupplicantDbus {
            backend = StationBackendKind::RustWpa2;
            station_disconnect_with_backend(interface, backend).map_err(|fallback_err| {
                anyhow!(
                    "disconnect failed via {:?}: {}; fallback {:?} failed: {}",
                    StationBackendKind::WpaSupplicantDbus,
                    err,
                    backend,
                    fallback_err
                )
            })?;
        } else {
            return Err(anyhow!("disconnect failed: {}", err));
        }
    }
    Ok(())
}

#[cfg(test)]
fn start_wpa_service(_interface: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
fn start_wpa_service(interface: &str) -> Result<()> {
    let unit = format!("rustyjack-wpa_supplicant@{}.service", interface);
    crate::system::start_system_service(&unit).with_context(|| format!("failed to start {}", unit))
}

#[cfg(test)]
fn stop_wpa_service(_interface: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
fn stop_wpa_service(interface: &str) -> Result<()> {
    let unit = format!("rustyjack-wpa_supplicant@{}.service", interface);
    match crate::system::stop_system_service(&unit) {
        Ok(()) => Ok(()),
        Err(err) => {
            let detail = err.to_string().to_ascii_lowercase();
            if detail.contains("not loaded")
                || detail.contains("no such unit")
                || detail.contains("unknown object")
            {
                return Ok(());
            }
            Err(err).with_context(|| format!("failed to stop {}", unit))
        }
    }
}

fn emit_progress<F>(progress: &mut Option<&mut F>, phase: &str, percent: u8, message: &str)
where
    F: FnMut(&str, u8, &str),
{
    if let Some(cb) = progress.as_deref_mut() {
        cb(phase, percent, message);
    }
}

fn push_warning(outcome: &mut InterfaceSelectionOutcome, warning: String) {
    outcome.notes.push(format!("Warning: {}", warning));
    outcome.warnings.push(warning);
}

fn push_error(outcome: &mut InterfaceSelectionOutcome, iface: &str, message: String) {
    outcome.errors.push(ErrorEntry {
        interface: iface.to_string(),
        message: message.clone(),
    });
    push_warning(outcome, format!("{}: {}", iface, message));
}

fn verify_exclusive_network_state(
    ops: &dyn NetOps,
    selected: &str,
    others: &[String],
) -> Result<()> {
    if !ops.admin_is_up(selected)? {
        bail!(
            "verification failed: selected interface {} is not admin-UP",
            selected
        );
    }

    let selected_ip = ops.get_ipv4_address(selected)?;
    if selected_ip.is_none() {
        bail!(
            "verification failed: selected interface {} has no IPv4 address",
            selected
        );
    }

    for other in others {
        if ops.admin_is_up(other)? {
            bail!(
                "verification failed: non-selected interface {} is still admin-UP",
                other
            );
        }
        if ops.is_wireless(other) && !ops.is_rfkill_blocked(other)? {
            bail!(
                "verification failed: non-selected Wi-Fi interface {} is not rfkill-blocked",
                other
            );
        }
    }

    let routes = ops.list_routes()?;
    let default_routes: Vec<_> = routes
        .iter()
        .filter(|route| route.destination.is_none())
        .collect();

    if default_routes.len() != 1 {
        bail!(
            "verification failed: expected exactly one default route, found {}",
            default_routes.len()
        );
    }

    if default_routes[0].interface != selected {
        bail!(
            "verification failed: default route is via {}, expected {}",
            default_routes[0].interface,
            selected
        );
    }

    Ok(())
}

#[derive(Debug, Default)]
struct RfkillState {
    idx: u32,
    type_name: Option<String>,
    name: Option<String>,
    soft: Option<bool>,
    hard: Option<bool>,
}

fn read_rfkill_state(iface: &str) -> Result<Option<RfkillState>> {
    let Some(idx) = rfkill_find_index(iface)? else {
        return Ok(None);
    };
    let soft_path = format!("/sys/class/rfkill/rfkill{}/soft", idx);
    let hard_path = format!("/sys/class/rfkill/rfkill{}/hard", idx);
    let type_path = format!("/sys/class/rfkill/rfkill{}/type", idx);
    let name_path = format!("/sys/class/rfkill/rfkill{}/name", idx);

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
    let type_name = std::fs::read_to_string(&type_path)
        .ok()
        .map(|c| c.trim().to_string());
    let name = std::fs::read_to_string(&name_path)
        .ok()
        .map(|c| c.trim().to_string());

    Ok(Some(RfkillState {
        idx,
        type_name,
        name,
        soft,
        hard,
    }))
}

#[tracing::instrument(target = "wifi", fields(iface = %iface))]
fn wait_for_rfkill(iface: &str, timeout: Duration, cancel: Option<&CancelFlag>) -> Result<()> {
    let start = Instant::now();
    loop {
        check_cancel(cancel)?;
        let Some(state) = read_rfkill_state(iface)? else {
            return Ok(());
        };

        if state.hard.unwrap_or(false) {
            bail!("{}", rfkill_hard_block_error(iface, &state));
        }
        if state.soft == Some(false) {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            bail!("rfkill unblock timed out for {}", iface);
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn rfkill_hard_block_error(iface: &str, state: &RfkillState) -> String {
    format!(
        "Interface {} is hard-blocked by rfkill{} (type={}, name={}, soft={:?}, hard={:?})",
        iface,
        state.idx,
        state.type_name.as_deref().unwrap_or("unknown"),
        state.name.as_deref().unwrap_or("unknown"),
        state.soft,
        state.hard
    )
}

fn wait_for_admin_state(
    ops: &dyn NetOps,
    iface: &str,
    desired_up: bool,
    timeout: Duration,
    cancel: Option<&CancelFlag>,
) -> Result<()> {
    if ops.admin_is_up(iface)? == desired_up {
        return Ok(());
    }

    let start = Instant::now();
    let mut watcher = LinkEventWatcher::new().ok();
    let mut buf = BytesMut::with_capacity(8192);
    buf.reserve(8192);

    loop {
        check_cancel(cancel)?;
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
            let mut fds = [PollFd::new(&w.socket, PollFlags::POLLIN)];
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
                    warn!(target: "net", error = %e, "link_watcher_poll_error");
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
    #[allow(dead_code)]
    carrier: Option<bool>,
}

fn parse_link_state(
    msg: &netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
    target_iface: &str,
) -> Option<LinkState> {
    use netlink_packet_core::NetlinkPayload;
    use netlink_packet_route::link::{LinkAttribute, LinkFlag, State};
    use netlink_packet_route::RouteNetlinkMessage;

    match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            let name = link.attributes.iter().find_map(|nla| {
                if let LinkAttribute::IfName(name) = nla {
                    Some(name.clone())
                } else {
                    None
                }
            })?;

            if name != target_iface {
                return None;
            }

            let admin_up = link.header.flags.contains(&LinkFlag::Up);

            let carrier = link.attributes.iter().find_map(|nla| match nla {
                LinkAttribute::Carrier(v) => Some(*v != 0),
                LinkAttribute::OperState(state) => Some(*state == State::Up),
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
        let mut socket = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_ROUTE)
            .context("netlink socket")?;
        let groups = libc::RTMGRP_LINK as u32;
        socket
            .bind(&netlink_sys::SocketAddr::new(0, groups))
            .context("bind netlink socket")?;
        socket
            .set_non_blocking(true)
            .context("set netlink socket non-blocking")?;
        Ok(Self { socket })
    }

    #[allow(dead_code)]
    fn fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }

    fn recv(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Vec<netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>>>
    {
        use netlink_packet_core::NetlinkBuffer;
        use netlink_packet_core::NetlinkMessage;
        use netlink_packet_core::NetlinkPayload;
        use netlink_packet_route::RouteNetlinkMessage;

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
            let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&slice[..length])
                .map_err(|e| anyhow!("failed to deserialize netlink message: {}", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::ops::{
        DhcpLease, InterfaceCapabilities, InterfaceSummary, NetOps, RouteEntry,
        TxInMonitorCapability,
    };
    use std::collections::{HashMap, HashSet};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Clone, Default)]
    struct MockNetOps {
        interfaces: Arc<Mutex<Vec<InterfaceSummary>>>,
        admin_state: Arc<Mutex<HashMap<String, bool>>>,
        carrier_state: Arc<Mutex<HashMap<String, Option<bool>>>>,
        ip_state: Arc<Mutex<HashMap<String, Option<Ipv4Addr>>>>,
        rfkill_state: Arc<Mutex<HashMap<String, bool>>>,
        routes: Arc<Mutex<Vec<RouteEntry>>>,
        calls: Arc<Mutex<Vec<String>>>,
        fail_bring_down: Arc<Mutex<HashSet<String>>>,
    }

    impl MockNetOps {
        fn new() -> Self {
            Self::default()
        }

        fn add_interface(
            &self,
            name: &str,
            is_wireless: bool,
            admin_up: bool,
            carrier: Option<bool>,
            ip: Option<Ipv4Addr>,
        ) {
            let caps = InterfaceCapabilities {
                name: name.to_string(),
                is_wireless,
                is_physical: true,
                supports_monitor: false,
                supports_ap: false,
                supports_injection: false,
                supports_5ghz: false,
                supports_2ghz: is_wireless,
                mac_address: Some("00:11:22:33:44:55".to_string()),
                driver: Some("mock".to_string()),
                chipset: Some("mock".to_string()),
                tx_in_monitor: TxInMonitorCapability::Unknown,
                tx_in_monitor_reason: "mock".to_string(),
            };

            self.interfaces.lock().unwrap().push(InterfaceSummary {
                name: name.to_string(),
                kind: if is_wireless {
                    "wireless".to_string()
                } else {
                    "wired".to_string()
                },
                oper_state: if admin_up {
                    "up".to_string()
                } else {
                    "down".to_string()
                },
                ip: ip.map(|v| v.to_string()),
                is_wireless,
                admin_up,
                carrier,
                capabilities: Some(caps),
            });
            self.admin_state
                .lock()
                .unwrap()
                .insert(name.to_string(), admin_up);
            self.carrier_state
                .lock()
                .unwrap()
                .insert(name.to_string(), carrier);
            self.ip_state.lock().unwrap().insert(name.to_string(), ip);
            self.rfkill_state
                .lock()
                .unwrap()
                .insert(name.to_string(), false);
        }

        fn fail_bring_down_for(&self, iface: &str) {
            self.fail_bring_down
                .lock()
                .unwrap()
                .insert(iface.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn admin_up_interfaces(&self) -> Vec<String> {
            self.admin_state
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(iface, up)| if *up { Some(iface.clone()) } else { None })
                .collect()
        }
    }

    impl NetOps for MockNetOps {
        fn list_interfaces(&self) -> Result<Vec<InterfaceSummary>> {
            Ok(self.interfaces.lock().unwrap().clone())
        }

        fn bring_up(&self, interface: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("bring_up:{}", interface));
            self.admin_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), true);
            Ok(())
        }

        fn bring_down(&self, interface: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("bring_down:{}", interface));
            if self.fail_bring_down.lock().unwrap().contains(interface) {
                return Err(anyhow!("injected bring_down failure for {}", interface));
            }
            self.admin_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), false);
            self.ip_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), None);
            Ok(())
        }

        fn set_rfkill_block(&self, interface: &str, blocked: bool) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("rfkill:{}:{}", interface, blocked));
            self.rfkill_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), blocked);
            Ok(())
        }

        fn is_wireless(&self, interface: &str) -> bool {
            self.interfaces
                .lock()
                .unwrap()
                .iter()
                .find(|iface| iface.name == interface)
                .map(|iface| iface.is_wireless)
                .unwrap_or(false)
        }

        fn interface_exists(&self, interface: &str) -> bool {
            self.interfaces
                .lock()
                .unwrap()
                .iter()
                .any(|iface| iface.name == interface)
        }

        fn add_default_route(&self, iface: &str, gateway: Ipv4Addr, metric: u32) -> Result<()> {
            self.routes.lock().unwrap().push(RouteEntry {
                interface: iface.to_string(),
                gateway,
                metric,
                destination: None,
            });
            Ok(())
        }

        fn delete_default_route(&self, iface: &str) -> Result<()> {
            self.routes
                .lock()
                .unwrap()
                .retain(|route| route.interface != iface || route.destination.is_some());
            Ok(())
        }

        fn list_routes(&self) -> Result<Vec<RouteEntry>> {
            Ok(self.routes.lock().unwrap().clone())
        }

        fn acquire_dhcp(&self, iface: &str, _timeout: Duration) -> Result<DhcpLease> {
            let lease = DhcpLease {
                ip: Ipv4Addr::new(192, 168, 1, 100),
                prefix_len: 24,
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
            };
            self.ip_state
                .lock()
                .unwrap()
                .insert(iface.to_string(), Some(lease.ip));
            Ok(lease)
        }

        fn release_dhcp(&self, iface: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release_dhcp:{}", iface));
            Ok(())
        }

        fn flush_addresses(&self, interface: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("flush:{}", interface));
            self.ip_state
                .lock()
                .unwrap()
                .insert(interface.to_string(), None);
            Ok(())
        }

        fn get_ipv4_address(&self, iface: &str) -> Result<Option<Ipv4Addr>> {
            Ok(self.ip_state.lock().unwrap().get(iface).copied().flatten())
        }

        fn get_interface_capabilities(&self, iface: &str) -> Result<InterfaceCapabilities> {
            self.interfaces
                .lock()
                .unwrap()
                .iter()
                .find(|entry| entry.name == iface)
                .and_then(|entry| entry.capabilities.clone())
                .ok_or_else(|| anyhow!("capabilities missing for {}", iface))
        }

        fn admin_is_up(&self, interface: &str) -> Result<bool> {
            Ok(*self
                .admin_state
                .lock()
                .unwrap()
                .get(interface)
                .unwrap_or(&false))
        }

        fn has_carrier(&self, interface: &str) -> Result<Option<bool>> {
            Ok(self
                .carrier_state
                .lock()
                .unwrap()
                .get(interface)
                .copied()
                .unwrap_or(None))
        }

        fn is_rfkill_blocked(&self, interface: &str) -> Result<bool> {
            Ok(*self
                .rfkill_state
                .lock()
                .unwrap()
                .get(interface)
                .unwrap_or(&false))
        }

        fn is_rfkill_hard_blocked(&self, _interface: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn two_phase_disables_other_uplinks_before_target_bring_up() {
        let ops = MockNetOps::new();
        ops.add_interface(
            "eth0",
            false,
            true,
            Some(true),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
        );
        ops.add_interface("wlan0", true, false, None, None);

        let root = TempDir::new().unwrap();
        select_interface_with_ops(
            Arc::new(ops.clone()),
            root.path().to_path_buf(),
            "wlan0",
            None::<&mut fn(&str, u8, &str)>,
            None,
        )
        .unwrap();

        let calls = ops.calls();
        let bring_up_target = calls.iter().position(|c| c == "bring_up:wlan0").unwrap();
        let bring_down_other = calls.iter().position(|c| c == "bring_down:eth0").unwrap();
        assert!(
            bring_down_other < bring_up_target,
            "non-target uplinks must be disabled before target is brought up"
        );
    }

    #[test]
    fn rollback_restores_previous_interface_after_post_step5_failure() {
        let ops = MockNetOps::new();
        ops.add_interface(
            "eth0",
            false,
            true,
            Some(true),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
        );
        ops.add_interface(
            "wlan0",
            true,
            false,
            None,
            Some(Ipv4Addr::new(192, 168, 1, 50)),
        );
        ops.fail_bring_down_for("eth0");

        let root = TempDir::new().unwrap();
        let err = select_interface_with_ops(
            Arc::new(ops.clone()),
            root.path().to_path_buf(),
            "wlan0",
            None::<&mut fn(&str, u8, &str)>,
            None,
        )
        .unwrap_err();

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("rollback restored previous interface eth0"),
            "expected rollback restoration in error, got: {}",
            err_msg
        );

        let up = ops.admin_up_interfaces();
        assert!(up.contains(&"eth0".to_string()));
        assert!(
            !up.contains(&"wlan0".to_string()),
            "target should be down after rollback"
        );
    }

    #[test]
    fn success_keeps_single_admin_up_invariant() {
        let ops = MockNetOps::new();
        ops.add_interface(
            "eth0",
            false,
            true,
            Some(true),
            Some(Ipv4Addr::new(10, 0, 0, 2)),
        );
        ops.add_interface("wlan0", true, false, None, None);

        let root = TempDir::new().unwrap();
        let outcome = select_interface_with_ops(
            Arc::new(ops.clone()),
            root.path().to_path_buf(),
            "wlan0",
            None::<&mut fn(&str, u8, &str)>,
            None,
        )
        .unwrap();

        assert_eq!(outcome.allowed, vec!["wlan0".to_string()]);
        assert_eq!(outcome.blocked, vec!["eth0".to_string()]);

        let up = ops.admin_up_interfaces();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0], "wlan0");
    }

    #[test]
    fn success_blocks_non_target_wifi_and_sets_single_default_route() {
        let ops = MockNetOps::new();
        ops.add_interface(
            "eth0",
            false,
            false,
            Some(true),
            Some(Ipv4Addr::new(10, 0, 0, 20)),
        );
        ops.add_interface(
            "wlan0",
            true,
            true,
            None,
            Some(Ipv4Addr::new(192, 168, 1, 50)),
        );
        ops.routes.lock().unwrap().push(RouteEntry {
            interface: "wlan0".to_string(),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            metric: 100,
            destination: None,
        });

        let root = TempDir::new().unwrap();
        let outcome = select_interface_with_ops(
            Arc::new(ops.clone()),
            root.path().to_path_buf(),
            "eth0",
            None::<&mut fn(&str, u8, &str)>,
            None,
        )
        .unwrap();

        assert_eq!(outcome.allowed, vec!["eth0".to_string()]);
        assert_eq!(outcome.blocked, vec!["wlan0".to_string()]);
        assert!(ops.is_rfkill_blocked("wlan0").unwrap());

        let routes = ops.list_routes().unwrap();
        let defaults: Vec<_> = routes
            .into_iter()
            .filter(|route| route.destination.is_none())
            .collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].interface, "eth0");
    }
}
