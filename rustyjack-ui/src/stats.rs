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

use anyhow::{Context, Result};
use rustyjack_commands::{Commands, StatusCommand, WifiCommand};
use serde_json::Value;

use crate::{
    core::CoreBridge,
    display::StatusOverlay,
    types::{InterfaceSummary, WifiListResponse},
};

pub struct StatsSampler {
    data: Arc<Mutex<StatusOverlay>>,
    stop: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
use linux_embedded_hal::gpio_cdev::{Chip, LineHandle, LineRequestFlags};

#[cfg(target_os = "linux")]
struct StatusLed {
    handle: LineHandle,
    is_on: bool,
}

#[cfg(target_os = "linux")]
impl StatusLed {
    fn new(pin: u32) -> Result<Option<Self>> {
        if pin == 0 {
            return Ok(None);
        }
        let mut chip = Chip::new("/dev/gpiochip0").context("opening gpiochip0")?;
        let line = chip
            .get_line(pin)
            .with_context(|| format!("requesting status LED line {}", pin))?;
        let handle = line
            .request(LineRequestFlags::OUTPUT, 0, "rustyjack-status-led")
            .with_context(|| format!("configuring status LED line {}", pin))?;
        Ok(Some(Self {
            handle,
            is_on: false,
        }))
    }

    fn set(&mut self, on: bool) {
        if on == self.is_on {
            return;
        }
        let value = if on { 1 } else { 0 };
        if let Err(err) = self.handle.set_value(value) {
            eprintln!("[status_led] set failed: {err}");
            return;
        }
        self.is_on = on;
    }
}

impl StatsSampler {
    pub fn spawn(core: CoreBridge, status_led_pin: u32) -> Self {
        let data = Arc::new(Mutex::new(StatusOverlay::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let data_clone = data.clone();
        let stop_clone = stop.clone();
        let root = core.root().to_path_buf();

        thread::spawn(move || {
            #[cfg(target_os = "linux")]
            let mut status_led = match StatusLed::new(status_led_pin) {
                Ok(led) => led,
                Err(err) => {
                    eprintln!("[status_led] init failed: {err:?}");
                    None
                }
            };
            #[cfg(not(target_os = "linux"))]
            let _ = status_led_pin;

            while !stop_clone.load(Ordering::Relaxed) {
                let has_ip = match sample_once(&core, &data_clone, &root) {
                    Ok(has_ip) => has_ip,
                    Err(err) => {
                        eprintln!("[stats] sampler error: {err:?}");
                        false
                    }
                };
                #[cfg(target_os = "linux")]
                if let Some(led) = status_led.as_mut() {
                    led.set(has_ip);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = has_ip;
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

fn sample_once(
    core: &CoreBridge,
    shared: &Arc<Mutex<StatusOverlay>>,
    root: &Path,
) -> Result<bool> {
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
    let mut has_ip = has_network_ip(&overlay.interfaces);

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
            has_ip = has_network_ip(&list.interfaces);
            overlay.interfaces = list.interfaces;
        }
    }

    if let Err(err) = network_watchdog(root) {
        eprintln!("[network] watchdog error: {err:?}");
    }

    if let Ok(mut guard) = shared.lock() {
        *guard = overlay;
    }
    Ok(has_ip)
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

fn has_network_ip(interfaces: &[InterfaceSummary]) -> bool {
    interfaces.iter().any(|iface| {
        if iface.name == "lo" {
            return false;
        }
        if iface.oper_state == "down"
            || iface.oper_state == "dormant"
            || iface.oper_state == "lowerlayerdown"
        {
            return false;
        }
        let ip = match iface.ip.as_deref() {
            Some(ip) => ip,
            None => return false,
        };
        if ip == "0.0.0.0" || ip.starts_with("127.") {
            return false;
        }
        true
    })
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
