use std::{
    fs,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use rustyjack_core::cli::{
    HotspotCommand, StatusCommand, WifiCommand, WifiRouteCommand, WifiRouteEnsureArgs,
};
use rustyjack_core::{apply_interface_isolation, Commands};
use serde_json::Value;

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::StatusOverlay,
    types::WifiListResponse,
};

pub struct StatsSampler {
    data: Arc<Mutex<StatusOverlay>>,
    stop: Arc<AtomicBool>,
}

const DHCP_RETRY_SECS: u64 = 15;
static LAST_DHCP_ATTEMPT: AtomicU64 = AtomicU64::new(0);
static LAST_ISOLATION_STATE: OnceLock<Mutex<IsolationState>> = OnceLock::new();

#[derive(Debug, Clone)]
struct IsolationState {
    mode: String,
    allow_list: Vec<String>,
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

    // Enforce interface isolation continuously based on active/hotspot state
    if let Err(err) = enforce_isolation_watchdog(core, root) {
        eprintln!("[isolation] watchdog error: {err:?}");
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

fn enforce_isolation_watchdog(core: &CoreBridge, root: &Path) -> Result<()> {
    let cfg = GuiConfig::load(root)?;
    let active_iface = cfg.settings.active_network_interface.trim().to_string();

    let mut allow_list = Vec::new();

    if let Ok((_, hs_data)) = core.dispatch(Commands::Hotspot(HotspotCommand::Status)) {
        let running = hs_data
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if running {
            if let Some(ap) = hs_data.get("ap_interface").and_then(|v| v.as_str()) {
                if !ap.is_empty() && interface_exists(ap) {
                    allow_list.push(ap.to_string());
                }
            }
            if let Some(up) = hs_data.get("upstream_interface").and_then(|v| v.as_str()) {
                if !up.is_empty() && interface_exists(up) {
                    allow_list.push(up.to_string());
                }
            }

            allow_list.sort();
            allow_list.dedup();
            if allow_list.is_empty() {
                log_isolation_state("hotspot", &allow_list);
                return Ok(());
            }

            apply_interface_isolation(&allow_list)?;
            log_isolation_state("hotspot", &allow_list);
            if let Some(up) = hs_data
                .get("upstream_interface")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                maybe_ensure_wired_dhcp(core, up)?;
            }
            return Ok(());
        }
    }

    if active_iface.is_empty() || active_iface.eq_ignore_ascii_case("auto") {
        if let Some(fallback) = select_default_interface() {
            allow_list.push(fallback);
        }
    } else if interface_exists(&active_iface) {
        allow_list.push(active_iface.clone());
    } else {
        eprintln!(
            "[isolation] active interface {} not found; skipping enforcement",
            active_iface
        );
        log_isolation_state("skipped", &[]);
        return Ok(());
    }

    allow_list.retain(|s| !s.is_empty());
    allow_list.sort();
    allow_list.dedup();
    allow_list.retain(|s| interface_exists(s));

    if allow_list.is_empty() {
        log_isolation_state("single", &allow_list);
        return Ok(());
    }

    apply_interface_isolation(&allow_list)?;
    log_isolation_state("single", &allow_list);
    if let Some(primary) = allow_list.first() {
        maybe_ensure_wired_dhcp(core, primary)?;
    }
    Ok(())
}

fn maybe_ensure_wired_dhcp(core: &CoreBridge, interface: &str) -> Result<()> {
    if interface.is_empty() {
        return Ok(());
    }
    if interface_is_wireless(interface) {
        return Ok(());
    }
    if !interface_has_carrier(interface) {
        return Ok(());
    }
    if interface_has_ipv4(interface) {
        return Ok(());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_DHCP_ATTEMPT.load(Ordering::Relaxed);
    if now.saturating_sub(last) < DHCP_RETRY_SECS {
        return Ok(());
    }
    LAST_DHCP_ATTEMPT.store(now, Ordering::Relaxed);

    let args = WifiRouteEnsureArgs {
        interface: interface.to_string(),
    };
    if let Err(err) = core.dispatch(Commands::Wifi(WifiCommand::Route(
        WifiRouteCommand::Ensure(args),
    ))) {
        eprintln!("[route] auto ensure failed for {}: {}", interface, err);
    }
    Ok(())
}

fn interface_is_wireless(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let path = format!("/sys/class/net/{}/wireless", interface);
    Path::new(&path).exists()
}

fn interface_has_carrier(interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let carrier_path = format!("/sys/class/net/{}/carrier", interface);
    let oper_path = format!("/sys/class/net/{}/operstate", interface);
    let oper_state = fs::read_to_string(&oper_path)
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    let oper_ready = matches!(oper_state.as_str(), "up" | "unknown");
    match fs::read_to_string(&carrier_path) {
        Ok(val) => val.trim() == "1" || oper_ready,
        Err(_) => oper_ready,
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

fn log_isolation_state(mode: &str, allow_list: &[String]) {
    let state = LAST_ISOLATION_STATE.get_or_init(|| {
        Mutex::new(IsolationState {
            mode: String::new(),
            allow_list: Vec::new(),
        })
    });
    let mut guard = match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.mode != mode || guard.allow_list != allow_list {
        log::info!("[ISOLATION] mode={} allow={:?}", mode, allow_list);
        guard.mode = mode.to_string();
        guard.allow_list = allow_list.to_vec();
    }
}

fn interface_exists(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    Path::new("/sys/class/net").join(name).exists()
}

fn select_default_interface() -> Option<String> {
    if interface_exists("eth0") {
        return Some("eth0".to_string());
    }
    if interface_exists("wlan0") {
        return Some("wlan0".to_string());
    }
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "lo" {
            return Some(name);
        }
    }
    None
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
