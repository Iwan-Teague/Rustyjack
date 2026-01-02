use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use anyhow::Result;
use rustyjack_commands::{Commands, StatusCommand, WifiCommand};
use serde_json::Value;

use crate::{
    core::CoreBridge,
    display::StatusOverlay,
    types::WifiListResponse,
};

pub struct StatsSampler {
    data: Arc<Mutex<StatusOverlay>>,
    stop: Arc<AtomicBool>,
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
        read_disk_usage(core, root.to_str().unwrap_or("/var/lib/rustyjack"))
            .unwrap_or((0.0, 0.0));

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
        if let Some(running) = extract_dns_spoof_running(&data) {
            overlay.dns_spoof_running = running;
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

fn extract_dns_spoof_running(data: &Value) -> Option<bool> {
    match data {
        Value::Object(map) => map.get("dnsspoof_running").and_then(|value| value.as_bool()),
        _ => None,
    }
}

fn network_watchdog(_root: &Path) -> Result<()> {
    // Network healing belongs to the daemon; keep UI watchdog as a no-op.
    Ok(())
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

fn read_disk_usage(core: &CoreBridge, path: &str) -> Result<(f32, f32)> {
    let (used_bytes, total_bytes) = core.disk_usage(path)?;
    let used_gb = used_bytes as f32 / 1_000_000_000.0;
    let total_gb = total_bytes as f32 / 1_000_000_000.0;
    Ok((used_gb, total_gb))
}
