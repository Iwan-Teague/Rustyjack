use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use chrono::Local;
use rustyjack_core::cli::{StatusCommand, WifiCommand};
use rustyjack_core::system::{
    cached_gateway, clear_lease_record, interface_gateway, is_wireless_interface,
    route_interface, select_active_uplink, try_acquire_dhcp_lease, DhcpAttemptResult,
};
use rustyjack_core::Commands;
use rand::Rng;
use serde_json::Value;
#[cfg(target_os = "linux")]
use libc;
#[cfg(target_os = "linux")]
use rustyjack_netlink::{WpaManager, WpaSupplicantState};

use crate::{
    core::CoreBridge,
    display::StatusOverlay,
    types::WifiListResponse,
};

pub struct StatsSampler {
    data: Arc<Mutex<StatusOverlay>>,
    stop: Arc<AtomicBool>,
}

const MAX_DHCP_FAILURES: u32 = 3;
const MAX_BACKOFF_SECS: u64 = 60;
static LINK_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
static LINK_MONITOR_STARTED: OnceLock<()> = OnceLock::new();
static NETWORK_WATCH_STATE: OnceLock<Mutex<NetworkWatchState>> = OnceLock::new();

#[derive(Debug, Clone)]
struct BackoffState {
    failures: u32,
    next_attempt: u64,
    blocked: bool,
}

#[derive(Debug, Default)]
struct NetworkWatchState {
    backoff: std::collections::HashMap<String, BackoffState>,
    last_ready: std::collections::HashMap<String, bool>,
    last_uplink: Option<String>,
}

impl StatsSampler {
    pub fn spawn(core: CoreBridge) -> Self {
        let data = Arc::new(Mutex::new(StatusOverlay::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let data_clone = data.clone();
        let stop_clone = stop.clone();
        let root = core.root().to_path_buf();

        thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                if let Err(err) = sample_once(&core, &data_clone, &root) {
                    eprintln!("[stats] sampler error: {err:?}");
                }
                thread::sleep(Duration::from_secs(2));
            }
        });

        Self { data, stop }
    }

    pub fn snapshot(&self) -> StatusOverlay {
        self.data
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Drop for StatsSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn sample_once(core: &CoreBridge, shared: &Arc<Mutex<StatusOverlay>>, root: &Path) -> Result<()> {
    let temp = read_temp().unwrap_or_default();
    let (cpu_percent, uptime_secs) = read_cpu_and_uptime().unwrap_or((0.0, 0));
    let (mem_used_mb, mem_total_mb) = read_memory().unwrap_or((0, 0));
    let (disk_used_gb, disk_total_gb) =
        read_disk_usage(root.to_str().unwrap_or("/root/Rustyjack")).unwrap_or((0.0, 0.0));

    let mut overlay = {
        let guard = shared
            .lock()
            .map_err(|e| anyhow::anyhow!("Stats mutex poisoned: {}", e))?;
        let mut snapshot = guard.clone();

        snapshot.temp_c = temp;
        snapshot.cpu_percent = cpu_percent;
        snapshot.mem_used_mb = mem_used_mb;
        snapshot.mem_total_mb = mem_total_mb;
        snapshot.disk_used_gb = disk_used_gb;
        snapshot.disk_total_gb = disk_total_gb;
        snapshot.uptime_secs = uptime_secs;
        snapshot
    };

    if let Ok((_, data)) = core.dispatch(Commands::Status(StatusCommand::Summary)) {
        if let Some(text) = extract_status_text(&data) {
            overlay.text = text;
        }
    }

    if let Ok((_, data)) = core.dispatch(Commands::Wifi(WifiCommand::List)) {
        if let Ok(list) = serde_json::from_value::<WifiListResponse>(data) {
            overlay.interfaces = list.interfaces;
        }
    }

    if let Err(err) = network_watchdog(root) {
        eprintln!("[network] watchdog error: {err:?}");
    }

    if let Ok(mut guard) = shared.lock() {
        *guard = overlay;
    }
    Ok(())
}

fn extract_status_text(data: &Value) -> Option<String> {
    match data {
        Value::Object(map) => map
            .get("status_text")
            .and_then(|value| value.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn start_link_monitor() {
    LINK_MONITOR_STARTED.get_or_init(|| {
        thread::spawn(|| {
            if let Err(err) = link_monitor_loop() {
                eprintln!("[network] link monitor error: {err}");
            }
        });
    });
}

#[cfg(target_os = "linux")]
fn link_monitor_loop() -> std::io::Result<()> {
    use std::mem;

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = libc::RTMGRP_LINK as u32;
    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let mut buf = [0u8; 4096];
    loop {
        let len = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if len < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        LINK_EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(not(target_os = "linux"))]
fn link_monitor_loop() -> std::io::Result<()> {
    Ok(())
}

impl BackoffState {
    fn new() -> Self {
        Self {
            failures: 0,
            next_attempt: 0,
            blocked: false,
        }
    }

    fn reset(&mut self, now: u64) {
        self.failures = 0;
        self.next_attempt = now;
        self.blocked = false;
    }

    fn can_attempt(&self, now: u64) -> bool {
        !self.blocked && now >= self.next_attempt
    }

    fn record_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(6);
        let base = (1u64.checked_shl(shift).unwrap_or(1)).min(MAX_BACKOFF_SECS);
        let jitter = rand::thread_rng().gen_range(0..=base / 4);
        self.next_attempt = now + base + jitter;
        if self.failures >= MAX_DHCP_FAILURES {
            self.blocked = true;
        }
    }
}

fn network_watchdog(root: &Path) -> Result<()> {
    start_link_monitor();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let link_events = LINK_EVENT_COUNTER.swap(0, Ordering::Relaxed) > 0;

    let state = NETWORK_WATCH_STATE.get_or_init(|| Mutex::new(NetworkWatchState::default()));
    let mut guard = match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let route_iface = match route_interface() {
        Ok(name) => name,
        Err(err) => {
            log_watchdog_event(root, &format!("route: no preferred interface ({err})"));
            return Ok(());
        }
    };
    let kind = if is_wireless_interface(&route_iface) {
        "wireless"
    } else {
        "wired"
    };
    let interfaces = vec![(route_iface, kind)];
    for (iface, kind) in interfaces {
        if !interface_exists(&iface) {
            continue;
        }

        let link_ready = match kind {
            "wired" => interface_has_carrier(&iface),
            "wireless" => wireless_ready_for_dhcp(&iface),
            _ => false,
        };

        let was_ready = guard.last_ready.get(&iface).copied().unwrap_or(false);
        if link_ready != was_ready {
            guard.last_ready.insert(iface.clone(), link_ready);
            if link_ready {
                let backoff = guard
                    .backoff
                    .entry(iface.clone())
                    .or_insert_with(BackoffState::new);
                backoff.reset(now);
                log_watchdog_event(root, &format!("link: {} ready=true", iface));
            } else {
                clear_lease_record(&iface);
                log_watchdog_event(root, &format!("link: {} ready=false", iface));
            }
        }

        let gateway = cached_gateway(&iface).or_else(|| interface_gateway(&iface).ok().flatten());
        let has_ipv4 = interface_has_ipv4(&iface);
        let needs_dhcp = !has_ipv4 || gateway.is_none();
        let force_attempt = link_ready && (!was_ready || link_events);

        if link_ready && needs_dhcp {
            let backoff = guard
                .backoff
                .entry(iface.clone())
                .or_insert_with(BackoffState::new);
            if backoff.blocked {
                continue;
            }
            if force_attempt || backoff.can_attempt(now) {
                let reason = if !has_ipv4 { "no_ipv4" } else { "no_gateway" };
                log_watchdog_event(root, &format!("dhcp: attempt {} reason={}", iface, reason));
                match try_acquire_dhcp_lease(&iface)? {
                    DhcpAttemptResult::Lease(lease) => {
                        backoff.reset(now);
                        log_watchdog_event(
                            root,
                            &format!("dhcp: success {} gateway={:?}", iface, lease.gateway),
                        );
                    }
                    DhcpAttemptResult::Failed(err) => {
                        backoff.record_failure(now);
                        log_watchdog_event(
                            root,
                            &format!("dhcp: failed {} error={}", iface, err),
                        );
                        if backoff.blocked {
                            clear_lease_record(&iface);
                            log_watchdog_event(
                                root,
                                &format!("dhcp: giving up {} (clearing lease)", iface),
                            );
                        }
                    }
                    DhcpAttemptResult::Busy => {
                        log_watchdog_event(root, &format!("dhcp: busy {}", iface));
                    }
                }
            }
        } else if link_ready && !needs_dhcp {
            if let Some(backoff) = guard.backoff.get_mut(&iface) {
                backoff.reset(now);
            }
        }
    }

    let selected = select_active_uplink()?;
    if guard.last_uplink != selected {
        log_watchdog_event(
            root,
            &format!("uplink: {:?} -> {:?}", guard.last_uplink, selected),
        );
        guard.last_uplink = selected.clone();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wireless_ready_for_dhcp(interface: &str) -> bool {
    let mgr = match WpaManager::new(interface) {
        Ok(mgr) => mgr,
        Err(err) => {
            log::debug!(
                "[ROUTE] WPA status unavailable for {} (no control socket?): {}",
                interface,
                err
            );
            return false;
        }
    };

    let status = match mgr.status() {
        Ok(status) => status,
        Err(err) => {
            log::debug!("[ROUTE] WPA status read failed for {}: {}", interface, err);
            return false;
        }
    };

    log::info!(
        "[ROUTE] WPA status iface={} state={:?} ssid={:?} ip={:?}",
        interface,
        status.wpa_state,
        status.ssid,
        status.ip_address
    );

    matches!(status.wpa_state, WpaSupplicantState::Completed)
}

#[cfg(not(target_os = "linux"))]
fn wireless_ready_for_dhcp(_interface: &str) -> bool {
    false
}

fn interface_has_carrier(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let carrier_path = format!("/sys/class/net/{}/carrier", interface);
    match fs::read_to_string(&carrier_path) {
        Ok(val) => val.trim() == "1",
        Err(_) => false,
    }
}

fn interface_has_ipv4(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        use tokio::runtime::Handle;

        let fetch = |handle: &Handle| {
            handle.block_on(async {
                let mgr = rustyjack_netlink::InterfaceManager::new()?;
                mgr.get_ipv4_addresses(interface).await
            })
        };

        let addrs = match Handle::try_current() {
            Ok(handle) => fetch(&handle).ok(),
            Err(_) => tokio::runtime::Runtime::new()
                .ok()
                .and_then(|rt| fetch(rt.handle()).ok()),
        };

        addrs
            .unwrap_or_default()
            .iter()
            .any(|addr| matches!(addr.address, std::net::IpAddr::V4(_)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        false
    }
}

fn log_watchdog_event(root: &Path, message: &str) {
    log::info!("[WATCHDOG] {}", message);
    let log_dir = root.join("loot").join("logs");
    if fs::create_dir_all(&log_dir).is_err() {
        return;
    }
    let path = log_dir.join("watchdog.log");
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let ts = Local::now().to_rfc3339();
        let _ = writeln!(file, "{} {}", ts, message);
    }
}

fn interface_exists(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    Path::new("/sys/class/net").join(name).exists()
}

fn read_temp() -> Result<f32> {
    let raw = fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")?;
    let value: f32 = raw.trim().parse::<u32>().unwrap_or(0) as f32 / 1000.0;
    Ok(value)
}

fn read_cpu_and_uptime() -> Result<(f32, u64)> {
    let uptime_raw = fs::read_to_string("/proc/uptime")?;
    let uptime_secs = uptime_raw
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;

    let loadavg_raw = fs::read_to_string("/proc/loadavg")?;
    let load1min = loadavg_raw
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);

    let cpu_count = num_cpus::get() as f32;
    let cpu_percent = (load1min / cpu_count * 100.0).min(100.0);

    Ok((cpu_percent, uptime_secs))
}

fn read_memory() -> Result<(u64, u64)> {
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let mut total = 0u64;
    let mut available = 0u64;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        } else if line.starts_with("MemAvailable:") {
            available = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }

    let total_mb = total / 1024;
    let used_mb = (total.saturating_sub(available)) / 1024;
    Ok((used_mb, total_mb))
}

fn read_disk_usage(path: &str) -> Result<(f32, f32)> {
    let output = std::process::Command::new("df")
        .arg("-BG")
        .arg(path)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1).unwrap_or("");
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() >= 4 {
        let total = parts[1].trim_end_matches('G').parse::<f32>().unwrap_or(0.0);
        let used = parts[2].trim_end_matches('G').parse::<f32>().unwrap_or(0.0);
        return Ok((used, total));
    }

    Ok((0.0, 0.0))
}
