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
use rustyjack_core::cli::{HotspotCommand, StatusCommand};
use rustyjack_core::{apply_interface_isolation, Commands};
use serde_json::Value;

use crate::{
    config::GuiConfig,
    core::CoreBridge,
    display::StatusOverlay,
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
        read_disk_usage(root.to_str().unwrap_or("/root/Rustyjack")).unwrap_or((0.0, 0.0));

    let mut overlay = {
        let guard = shared.lock()
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

    // Enforce interface isolation continuously based on active/hotspot state
    if let Err(err) = enforce_isolation_watchdog(core, root) {
        eprintln!("[isolation] watchdog error: {err:?}");
    }

    // Check autopilot status
    if let Ok((_, data)) = core.dispatch(Commands::Autopilot(
        rustyjack_core::cli::AutopilotCommand::Status,
    )) {
        overlay.autopilot_running = data
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        overlay.autopilot_mode = data
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    } else {
        overlay.autopilot_running = false;
        overlay.autopilot_mode = String::new();
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
    let mut allow_list = vec![cfg.settings.active_network_interface.trim().to_string()];

    if let Ok((_, hs_data)) = core.dispatch(Commands::Hotspot(HotspotCommand::Status)) {
        let running = hs_data
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if running {
            if let Some(ap) = hs_data.get("ap_interface").and_then(|v| v.as_str()) {
                if !ap.is_empty() {
                    allow_list.push(ap.to_string());
                }
            }
            if let Some(up) = hs_data.get("upstream_interface").and_then(|v| v.as_str()) {
                if !up.is_empty() {
                    allow_list.push(up.to_string());
                }
            }
        }
    }

    allow_list.retain(|s| !s.is_empty());
    allow_list.sort();
    allow_list.dedup();

    if allow_list.is_empty() {
        return Ok(());
    }

    apply_interface_isolation(&allow_list)?;
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
