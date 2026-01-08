use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

use crate::services::error::ServiceError;

const MAX_LOG_BUNDLE_BYTES: usize = 900_000;
const MAX_SECTION_BYTES: usize = 200_000;
const MAX_CMD_OUTPUT_BYTES: usize = 100_000;
const MAX_LOG_TAIL_BYTES: usize = 150_000;

pub fn collect_log_bundle(root: &Path) -> Result<String, ServiceError> {
    let mut out = String::new();

    // Rust-native log collection (Phase 3 implementation)
    append_rustyjack_log_tail(&mut out, root, "rustyjackd.log", "Daemon Logs");
    append_rustyjack_log_tail(&mut out, root, "rustyjack-ui.log", "UI Logs");
    append_rustyjack_log_tail(&mut out, root, "portal.log", "Portal Logs");

    // Kernel log tail (replaces journalctl -k)
    append_kernel_log_tail(&mut out);

    // For external system logs (NetworkManager, wpa_supplicant), fall back to journalctl if available
    // but don't fail if it's not present
    append_command_output_optional(
        &mut out,
        "journalctl (NetworkManager)",
        "journalctl",
        &[
            "-u",
            "NetworkManager",
            "-b",
            "--no-pager",
            "-n",
            "200",
            "-o",
            "short-precise",
        ],
    );
    append_command_output_optional(
        &mut out,
        "journalctl (wpa_supplicant)",
        "journalctl",
        &[
            "-u",
            "wpa_supplicant",
            "-b",
            "--no-pager",
            "-n",
            "200",
            "-o",
            "short-precise",
        ],
    );

    append_sysfs_network_snapshot(&mut out);
    append_rfkill_status(&mut out);
    append_wpa_supplicant_status(&mut out);
    append_netlink_routes(&mut out);
    append_file_section(&mut out, "/etc/resolv.conf");
    append_file_section(&mut out, "/proc/net/route");
    append_file_section(&mut out, "/proc/net/arp");
    append_file_section(&mut out, "/proc/net/dev");
    append_file_section_path(&mut out, &root.join("loot").join("logs").join("watchdog.log"));

    if out.len() > MAX_LOG_BUNDLE_BYTES {
        out.truncate(MAX_LOG_BUNDLE_BYTES);
        out.push_str("\n\n--- TRUNCATED: exceeded MAX_LOG_BUNDLE_BYTES ---\n");
    }

    Ok(out)
}

pub fn gpio_diagnostics() -> Result<String, ServiceError> {
    let mut out = String::new();

    // Rust-native GPIO diagnostics (Phase 3 implementation)
    out.push_str("--- GPIO Chip Information (Rust-native) ---\n");
    append_gpio_chip_info(&mut out);

    out.push_str("\n--- Processes using /dev/gpiochip0 (Rust-native) ---\n");
    append_device_users(&mut out, "/dev/gpiochip0");

    out.push_str("\n--- Device File Information (Rust-native) ---\n");
    append_device_file_info(&mut out, "/dev/gpiochip0");
    append_device_file_info(&mut out, "/dev/spidev0.0");
    append_device_file_info(&mut out, "/dev/spidev0.1");

    Ok(out)
}

fn append_sysfs_network_snapshot(buf: &mut String) {
    buf.push_str("\n===== sysfs network interfaces =====\n");
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(err) => {
            buf.push_str(&format!("ERROR reading /sys/class/net: {err}\n"));
            return;
        }
    };

    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        if iface == "lo" {
            continue;
        }
        let base = Path::new("/sys/class/net").join(&iface);
        let read_trim = |path: &Path| -> Option<String> {
            fs::read_to_string(path).ok().map(|v| v.trim().to_string())
        };
        let oper = read_trim(&base.join("operstate")).unwrap_or_else(|| "unknown".to_string());
        let carrier = read_trim(&base.join("carrier")).unwrap_or_else(|| "unknown".to_string());
        let mac = read_trim(&base.join("address")).unwrap_or_else(|| "unknown".to_string());
        let mtu = read_trim(&base.join("mtu")).unwrap_or_else(|| "unknown".to_string());
        let kind = if base.join("wireless").exists() {
            "wireless"
        } else {
            "wired"
        };
        buf.push_str(&format!(
            "{iface}: kind={kind} operstate={oper} carrier={carrier} mac={mac} mtu={mtu}\n"
        ));
    }
}

fn append_rfkill_status(buf: &mut String) {
    buf.push_str("\n===== rfkill status =====\n");
    let entries = match fs::read_dir("/sys/class/rfkill") {
        Ok(entries) => entries,
        Err(err) => {
            buf.push_str(&format!("ERROR reading /sys/class/rfkill: {err}\n"));
            return;
        }
    };

    let mut found = false;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("rfkill") {
            continue;
        }
        found = true;
        let base = entry.path();
        let read_trim = |path: &Path| -> Option<String> {
            fs::read_to_string(path).ok().map(|v| v.trim().to_string())
        };
        let rf_type = read_trim(&base.join("type")).unwrap_or_else(|| "unknown".to_string());
        let rf_name = read_trim(&base.join("name")).unwrap_or_else(|| "unknown".to_string());
        let soft = read_trim(&base.join("soft")).unwrap_or_else(|| "unknown".to_string());
        let hard = read_trim(&base.join("hard")).unwrap_or_else(|| "unknown".to_string());
        buf.push_str(&format!(
            "{}: type={} name={} soft={} hard={}\n",
            name, rf_type, rf_name, soft, hard
        ));
    }
    if !found {
        buf.push_str("No rfkill devices found\n");
    }
}

fn append_wpa_supplicant_status(buf: &mut String) {
    buf.push_str("\n===== wireless link status =====\n");

    #[cfg(target_os = "linux")]
    {
        let mut found = false;
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let iface = entry.file_name().to_string_lossy().to_string();
                if iface == "lo" {
                    continue;
                }
                if !Path::new("/sys/class/net")
                    .join(&iface)
                    .join("wireless")
                    .exists()
                {
                    continue;
                }
                found = true;
                let operstate = fs::read_to_string(format!("/sys/class/net/{}/operstate", iface))
                    .ok()
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let carrier = fs::read_to_string(format!("/sys/class/net/{}/carrier", iface))
                    .ok()
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let ip = crate::netlink_helpers::netlink_get_ipv4_addresses(&iface)
                    .ok()
                    .and_then(|addrs| addrs.into_iter().find_map(|addr| match addr.address {
                        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                        _ => None,
                    }));
                buf.push_str(&format!(
                    "{}: operstate={} carrier={} ip={:?}\n",
                    iface, operstate, carrier, ip
                ));
            }
        }
        if !found {
            buf.push_str("No wireless interfaces found\n");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        buf.push_str("Not supported on this platform\n");
    }
}

fn append_netlink_routes(buf: &mut String) {
    buf.push_str("\n===== netlink routes by interface =====\n");

    #[cfg(target_os = "linux")]
    {
        use crate::netlink_helpers::{netlink_list_interfaces, netlink_list_routes};

        let interfaces = match netlink_list_interfaces() {
            Ok(list) => list,
            Err(err) => {
                buf.push_str(&format!("ERROR listing interfaces: {err}\n"));
                return;
            }
        };
        let routes = match netlink_list_routes() {
            Ok(list) => list,
            Err(err) => {
                buf.push_str(&format!("ERROR listing routes: {err}\n"));
                return;
            }
        };

        let mut iface_map = std::collections::HashMap::new();
        for iface in &interfaces {
            iface_map.insert(iface.index, iface.name.clone());
        }

        let mut routes_by_iface: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for route in &routes {
            let iface_name = route
                .interface_index
                .and_then(|idx| iface_map.get(&idx).cloned())
                .unwrap_or_else(|| "unknown".to_string());
            let dst = route
                .destination
                .map(|d| d.to_string())
                .unwrap_or_else(|| "default".to_string());
            let gw = route
                .gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "-".to_string());
            let metric = route
                .metric
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".to_string());
            let entry = format!("dst={}/{} gw={} metric={}", dst, route.prefix_len, gw, metric);
            routes_by_iface
                .entry(iface_name)
                .or_default()
                .push(entry);
        }

        let mut iface_names: Vec<String> = routes_by_iface.keys().cloned().collect();
        iface_names.sort();
        if iface_names.is_empty() {
            buf.push_str("No routes found\n");
            return;
        }
        for name in iface_names {
            buf.push_str(&format!("{}:\n", name));
            if let Some(entries) = routes_by_iface.get(&name) {
                for entry in entries {
                    buf.push_str(&format!("  {}\n", entry));
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        buf.push_str("Not supported on this platform\n");
    }
}

fn append_command_output(buf: &mut String, title: &str, program: &str, args: &[&str]) {
    buf.push_str(&format!("\n===== {title} =====\n"));
    let output = Command::new(program).args(args).output();
    match output {
        Ok(output) => {
            if !output.status.success() {
                buf.push_str(&format!(
                    "ERROR: command exited with {:?}\n",
                    output.status.code()
                ));
            }
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            if stdout_str.len() > MAX_CMD_OUTPUT_BYTES {
                buf.push_str(&stdout_str[..MAX_CMD_OUTPUT_BYTES]);
                buf.push_str("\n[truncated stdout]\n");
            } else {
                buf.push_str(&stdout_str);
            }
            if !output.stderr.is_empty() {
                buf.push_str("\n[stderr]\n");
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                if stderr_str.len() > MAX_CMD_OUTPUT_BYTES {
                    buf.push_str(&stderr_str[..MAX_CMD_OUTPUT_BYTES]);
                    buf.push_str("\n[truncated stderr]\n");
                } else {
                    buf.push_str(&stderr_str);
                }
            }
        }
        Err(err) => {
            buf.push_str(&format!("ERROR: failed to run {program}: {err}\n"));
        }
    }
}

fn append_file_section(buf: &mut String, path: &str) {
    buf.push_str(&format!("\n===== {path} =====\n"));
    match fs::read_to_string(path) {
        Ok(contents) => {
            if contents.len() > MAX_SECTION_BYTES {
                buf.push_str(&contents[..MAX_SECTION_BYTES]);
                buf.push_str("\n[truncated file]\n");
            } else {
                buf.push_str(&contents);
            }
        }
        Err(err) => buf.push_str(&format!("ERROR: {err}\n")),
    }
}

fn append_file_section_path(buf: &mut String, path: &Path) {
    buf.push_str(&format!("\n===== {} =====\n", path.display()));
    match fs::read_to_string(path) {
        Ok(contents) => {
            if contents.len() > MAX_SECTION_BYTES {
                buf.push_str(&contents[..MAX_SECTION_BYTES]);
                buf.push_str("\n[truncated file]\n");
            } else {
                buf.push_str(&contents);
            }
        }
        Err(err) => buf.push_str(&format!("ERROR: {err}\n")),
    }
}

fn run_cmd_output(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output();
    match output {
        Ok(o) => {
            let mut out = String::new();
            if !o.stdout.is_empty() {
                out.push_str(&String::from_utf8_lossy(&o.stdout));
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            if !o.stderr.is_empty() {
                out.push_str("[stderr]\n");
                out.push_str(&String::from_utf8_lossy(&o.stderr));
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            out
        }
        Err(err) => format!("ERROR: failed to run {program}: {err}\n"),
    }
}

/// Tail a Rustyjack log file from /var/lib/rustyjack/logs/
fn append_rustyjack_log_tail(buf: &mut String, root: &Path, filename: &str, title: &str) {
    buf.push_str(&format!("\n===== {} =====\n", title));

    let log_path = root.join("logs").join(filename);

    if !log_path.exists() {
        buf.push_str(&format!("Log file not found: {}\n", log_path.display()));
        return;
    }

    match tail_file(&log_path, MAX_LOG_TAIL_BYTES) {
        Ok(contents) => {
            if contents.is_empty() {
                buf.push_str("(empty log file)\n");
            } else {
                buf.push_str(&contents);
                if !contents.ends_with('\n') {
                    buf.push('\n');
                }
            }
        }
        Err(err) => {
            buf.push_str(&format!("ERROR reading log file: {}\n", err));
        }
    }
}

/// Read the tail of a file (last N bytes)
fn tail_file(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len() as usize;

    if file_len == 0 {
        return Ok(String::new());
    }

    let start_pos = if file_len > max_bytes {
        file_len - max_bytes
    } else {
        0
    };

    file.seek(SeekFrom::Start(start_pos as u64))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Convert to string, handling potential UTF-8 issues
    let mut contents = String::from_utf8_lossy(&buffer).to_string();

    // If we started mid-file and mid-line, skip to the next newline
    if start_pos > 0 {
        if let Some(first_newline) = contents.find('\n') {
            contents = contents[first_newline + 1..].to_string();
        }
    }

    Ok(contents)
}

/// Capture kernel log tail from /dev/kmsg (replaces journalctl -k)
fn append_kernel_log_tail(out: &mut String) {
    out.push_str("\n===== Kernel Log Tail =====\n");

    #[cfg(target_os = "linux")]
    {
        // Try to read from /dev/kmsg for real-time kernel messages
        // This requires root privileges
        match read_kmsg_tail(300) {
            Ok(logs) => {
                if logs.is_empty() {
                    out.push_str("(no recent kernel messages)\n");
                } else {
                    out.push_str(&logs);
                }
            }
            Err(err) => {
                out.push_str(&format!("ERROR reading /dev/kmsg: {}\n", err));
                // Fall back to dmesg if kmsg fails
                out.push_str("\nAttempting fallback to dmesg...\n");
                let dmesg_output = Command::new("dmesg")
                    .args(&["-T", "--level=err,warn,notice,info"])
                    .output();
                match dmesg_output {
                    Ok(output) if output.status.success() => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let lines: Vec<&str> = stdout.lines().collect();
                        let tail_lines = if lines.len() > 300 {
                            &lines[lines.len() - 300..]
                        } else {
                            &lines[..]
                        };
                        out.push_str(&tail_lines.join("\n"));
                        out.push('\n');
                    }
                    _ => {
                        out.push_str("dmesg also unavailable\n");
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        out.push_str("Kernel logging not supported on this platform\n");
    }
}

/// Read recent kernel messages from /dev/kmsg
#[cfg(target_os = "linux")]
fn read_kmsg_tail(max_lines: usize) -> std::io::Result<String> {
    use std::fs::File;
    use std::io::BufRead;

    // /dev/kmsg is a special file that provides kernel ring buffer messages
    // Opening it in read mode gives us continuous stream, but we just want recent messages
    let file = File::open("/dev/kmsg")?;
    let reader = std::io::BufReader::new(file);

    let mut lines = Vec::new();
    for line in reader.lines() {
        match line {
            Ok(l) => {
                lines.push(l);
                if lines.len() > max_lines {
                    lines.remove(0);
                }
            }
            Err(_) => break, // Stop on error (non-blocking read will error when no more data)
        }
    }

    Ok(lines.join("\n"))
}

/// Like append_command_output but doesn't print ERROR if command doesn't exist
fn append_command_output_optional(buf: &mut String, title: &str, program: &str, args: &[&str]) {
    buf.push_str(&format!("\n===== {title} =====\n"));
    let output = Command::new(program).args(args).output();
    match output {
        Ok(output) => {
            if !output.status.success() {
                buf.push_str(&format!(
                    "Command exited with {:?}\n",
                    output.status.code()
                ));
            }
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            if stdout_str.len() > MAX_CMD_OUTPUT_BYTES {
                buf.push_str(&stdout_str[..MAX_CMD_OUTPUT_BYTES]);
                buf.push_str("\n[truncated stdout]\n");
            } else {
                buf.push_str(&stdout_str);
            }
            if !output.stderr.is_empty() {
                buf.push_str("\n[stderr]\n");
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                if stderr_str.len() > MAX_CMD_OUTPUT_BYTES {
                    buf.push_str(&stderr_str[..MAX_CMD_OUTPUT_BYTES]);
                    buf.push_str("\n[truncated stderr]\n");
                } else {
                    buf.push_str(&stderr_str);
                }
            }
        }
        Err(_) => {
            buf.push_str(&format!("{program} not available\n"));
        }
    }
}

/// Read GPIO chip information from sysfs (replaces gpioinfo)
fn append_gpio_chip_info(buf: &mut String) {
    #[cfg(target_os = "linux")]
    {
        // Read GPIO chip information from /sys/class/gpio or /sys/kernel/debug/gpio
        let gpio_base = Path::new("/sys/class/gpio");
        if gpio_base.exists() {
            match fs::read_dir(gpio_base) {
                Ok(entries) => {
                    let mut found = false;
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("gpiochip") {
                            found = true;
                            let chip_path = entry.path();
                            let base = fs::read_to_string(chip_path.join("base"))
                                .ok()
                                .and_then(|s| s.trim().parse::<u32>().ok())
                                .unwrap_or(0);
                            let ngpio = fs::read_to_string(chip_path.join("ngpio"))
                                .ok()
                                .and_then(|s| s.trim().parse::<u32>().ok())
                                .unwrap_or(0);
                            let label = fs::read_to_string(chip_path.join("label"))
                                .ok()
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|| "unknown".to_string());

                            buf.push_str(&format!(
                                "{}: base={} ngpio={} label={}\n",
                                name, base, ngpio, label
                            ));
                        }
                    }
                    if !found {
                        buf.push_str("No GPIO chips found in sysfs\n");
                    }
                }
                Err(err) => {
                    buf.push_str(&format!("ERROR reading {}: {}\n", gpio_base.display(), err));
                }
            }
        } else {
            buf.push_str("GPIO sysfs not available\n");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        buf.push_str("GPIO information not supported on this platform\n");
    }
}

/// Find processes using a device file by scanning /proc/*/fd (replaces lsof/fuser)
fn append_device_users(buf: &mut String, device_path: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        // Get the device's inode for comparison
        let device_metadata = match fs::metadata(device_path) {
            Ok(meta) => meta,
            Err(err) => {
                buf.push_str(&format!("ERROR: Cannot stat {}: {}\n", device_path, err));
                return;
            }
        };

        let device_dev = device_metadata.dev();
        let device_ino = device_metadata.ino();

        let proc_dir = match fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(err) => {
                buf.push_str(&format!("ERROR reading /proc: {}\n", err));
                return;
            }
        };

        let mut users = Vec::new();
        for entry in proc_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip non-numeric entries (we want PIDs)
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let pid = name.clone();
            let fd_dir_path = entry.path().join("fd");

            if let Ok(fd_entries) = fs::read_dir(&fd_dir_path) {
                for fd_entry in fd_entries.flatten() {
                    if let Ok(target) = fs::read_link(fd_entry.path()) {
                        if target.to_string_lossy() == device_path {
                            // Found a match! Get process name
                            let comm_path = entry.path().join("comm");
                            let proc_name = fs::read_to_string(&comm_path)
                                .ok()
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|| "unknown".to_string());

                            let fd_name = fd_entry.file_name().to_string_lossy().to_string();
                            users.push(format!("PID {} ({}): fd {}", pid, proc_name, fd_name));
                        } else if let Ok(meta) = fs::metadata(&target) {
                            // Compare by device/inode in case the symlink shows differently
                            if meta.dev() == device_dev && meta.ino() == device_ino {
                                let comm_path = entry.path().join("comm");
                                let proc_name = fs::read_to_string(&comm_path)
                                    .ok()
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_else(|| "unknown".to_string());

                                let fd_name = fd_entry.file_name().to_string_lossy().to_string();
                                users.push(format!(
                                    "PID {} ({}): fd {} -> {}",
                                    pid,
                                    proc_name,
                                    fd_name,
                                    target.display()
                                ));
                            }
                        }
                    }
                }
            }
        }

        if users.is_empty() {
            buf.push_str(&format!("No processes using {}\n", device_path));
        } else {
            for user in users {
                buf.push_str(&format!("{}\n", user));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        buf.push_str("Process scanning not supported on this platform\n");
    }
}

/// Get device file metadata (replaces ls -l)
fn append_device_file_info(buf: &mut String, device_path: &str) {
    match fs::metadata(device_path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};

                let perms = metadata.permissions();
                let mode = perms.mode();
                let file_type = if metadata.is_dir() {
                    'd'
                } else if metadata.is_symlink() {
                    'l'
                } else {
                    'c' // character device (typical for /dev files)
                };

                // Format permissions as rwxrwxrwx
                let fmt_perms = format!(
                    "{}{}{}{}{}{}{}{}{}",
                    if mode & 0o400 != 0 { 'r' } else { '-' },
                    if mode & 0o200 != 0 { 'w' } else { '-' },
                    if mode & 0o100 != 0 { 'x' } else { '-' },
                    if mode & 0o040 != 0 { 'r' } else { '-' },
                    if mode & 0o020 != 0 { 'w' } else { '-' },
                    if mode & 0o010 != 0 { 'x' } else { '-' },
                    if mode & 0o004 != 0 { 'r' } else { '-' },
                    if mode & 0o002 != 0 { 'w' } else { '-' },
                    if mode & 0o001 != 0 { 'x' } else { '-' },
                );

                let uid = metadata.uid();
                let gid = metadata.gid();
                let rdev = metadata.rdev();
                let major = (rdev >> 8) & 0xFF;
                let minor = rdev & 0xFF;

                buf.push_str(&format!(
                    "{}{} uid={} gid={} major={} minor={} {}\n",
                    file_type, fmt_perms, uid, gid, major, minor, device_path
                ));
            }

            #[cfg(not(unix))]
            {
                buf.push_str(&format!("{}: exists, {} bytes\n", device_path, metadata.len()));
            }
        }
        Err(err) => {
            buf.push_str(&format!("{}: ERROR - {}\n", device_path, err));
        }
    }
}
