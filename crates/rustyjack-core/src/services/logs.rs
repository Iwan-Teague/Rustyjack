use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use chrono::Local;

use crate::services::error::ServiceError;

const MAX_LOG_BUNDLE_BYTES: usize = 900_000;
const MAX_SECTION_BYTES: usize = 200_000;
const MAX_LOG_TAIL_BYTES: usize = 150_000;

struct SectionStatus {
    name: &'static str,
    ok: bool,
    err: Option<String>,
}

pub fn collect_log_bundle(root: &Path) -> Result<String, ServiceError> {
    let cfg = rustyjack_logging::fs::read_config(root);
    let selected_iface = crate::system::PreferenceManager::new(root.to_path_buf())
        .get_preferred()
        .ok()
        .flatten();

    let mut body = String::new();
    let mut statuses = Vec::new();

    append_section(&mut body, &mut statuses, "Daemon Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("rustyjackd.log"))
    });
    append_section(&mut body, &mut statuses, "UI Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("rustyjack-ui.log"))
    });
    append_section(&mut body, &mut statuses, "Portal Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("portal.log"))
    });
    append_section(&mut body, &mut statuses, "USB Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("usb.log"))
    });
    append_section(&mut body, &mut statuses, "WiFi Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("wifi.log"))
    });
    append_section(&mut body, &mut statuses, "Net Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("net.log"))
    });
    append_section(&mut body, &mut statuses, "Crypto Logs", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("crypto.log"))
    });
    append_section(&mut body, &mut statuses, "Audit Log", |buf| {
        append_log_tail_path(buf, &root.join("logs").join("audit").join("audit.log"))
    });

    append_section(
        &mut body,
        &mut statuses,
        "Kernel Log Tail",
        append_kernel_log_tail,
    );
    append_section(
        &mut body,
        &mut statuses,
        "sysfs network interfaces",
        append_sysfs_network_snapshot,
    );
    append_section(
        &mut body,
        &mut statuses,
        "rfkill status",
        append_rfkill_status,
    );
    append_section(
        &mut body,
        &mut statuses,
        "wireless link status",
        append_wpa_supplicant_status,
    );
    append_section(
        &mut body,
        &mut statuses,
        "netlink routes by interface",
        append_netlink_routes,
    );
    append_section(&mut body, &mut statuses, "/etc/resolv.conf", |buf| {
        append_file_section(buf, "/etc/resolv.conf")
    });
    append_section(&mut body, &mut statuses, "/proc/net/route", |buf| {
        append_file_section(buf, "/proc/net/route")
    });
    append_section(&mut body, &mut statuses, "/proc/net/arp", |buf| {
        append_file_section(buf, "/proc/net/arp")
    });
    append_section(&mut body, &mut statuses, "/proc/net/dev", |buf| {
        append_file_section(buf, "/proc/net/dev")
    });
    append_section(&mut body, &mut statuses, "Watchdog Log", |buf| {
        append_file_section_path(buf, &root.join("loot").join("logs").join("watchdog.log"))
    });

    let mut out = String::new();
    append_manifest(&mut out, root, &cfg, selected_iface.as_deref());
    out.push_str(&build_summary(&statuses));
    out.push_str(&body);

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

fn append_manifest(
    out: &mut String,
    root: &Path,
    cfg: &rustyjack_logging::LoggingConfig,
    selected_iface: Option<&str>,
) {
    out.push_str("===== Rustyjack Log Bundle =====\n");
    out.push_str(&format!("timestamp: {}\n", Local::now().to_rfc3339()));
    out.push_str(&format!("version: {}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!("root: {}\n", root.display()));
    out.push_str(&format!(
        "logging: enabled={} level={} keep_days={}\n",
        cfg.enabled, cfg.level, cfg.keep_days
    ));
    out.push_str(&format!(
        "selected_interface: {}\n",
        selected_iface.unwrap_or("unknown")
    ));
    out.push('\n');
}

fn build_summary(statuses: &[SectionStatus]) -> String {
    let mut out = String::new();
    let missing: Vec<&SectionStatus> = statuses.iter().filter(|s| !s.ok).collect();
    if missing.is_empty() {
        out.push_str("Bundle Summary: all sections collected\n\n");
        return out;
    }

    out.push_str("Bundle Summary: missing sections:\n");
    for section in missing {
        let err = section.err.as_deref().unwrap_or("unknown error");
        out.push_str(&format!("- {}: {}\n", section.name, err));
    }
    out.push('\n');
    out
}

fn append_section<F>(
    out: &mut String,
    statuses: &mut Vec<SectionStatus>,
    name: &'static str,
    append: F,
) where
    F: FnOnce(&mut String) -> Result<(), ServiceError>,
{
    out.push_str(&format!("\n===== {} =====\n", name));
    match append(out) {
        Ok(()) => statuses.push(SectionStatus {
            name,
            ok: true,
            err: None,
        }),
        Err(err) => {
            out.push_str("(section unavailable)\n");
            statuses.push(SectionStatus {
                name,
                ok: false,
                err: Some(err.to_string()),
            });
        }
    }
}

fn append_sysfs_network_snapshot(buf: &mut String) -> Result<(), ServiceError> {
    let entries = fs::read_dir("/sys/class/net")?;

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
    Ok(())
}

fn append_rfkill_status(buf: &mut String) -> Result<(), ServiceError> {
    let entries = fs::read_dir("/sys/class/rfkill")?;

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
    Ok(())
}

fn append_wpa_supplicant_status(buf: &mut String) -> Result<(), ServiceError> {
    #[cfg(target_os = "linux")]
    {
        let mut found = false;
        let entries = fs::read_dir("/sys/class/net")?;
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
                .and_then(|addrs| {
                    addrs.into_iter().find_map(|addr| match addr.address {
                        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                        _ => None,
                    })
                });
            buf.push_str(&format!(
                "{}: operstate={} carrier={} ip={:?}\n",
                iface, operstate, carrier, ip
            ));
        }
        if !found {
            buf.push_str("No wireless interfaces found\n");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        buf.push_str("Not supported on this platform\n");
    }
    Ok(())
}

fn append_netlink_routes(buf: &mut String) -> Result<(), ServiceError> {
    #[cfg(target_os = "linux")]
    {
        use crate::netlink_helpers::{netlink_list_interfaces, netlink_list_routes};

        let interfaces = netlink_list_interfaces()
            .map_err(|err| ServiceError::Netlink(format!("list interfaces: {err}")))?;
        let routes = netlink_list_routes()
            .map_err(|err| ServiceError::Netlink(format!("list routes: {err}")))?;

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
            let entry = format!(
                "dst={}/{} gw={} metric={}",
                dst, route.prefix_len, gw, metric
            );
            routes_by_iface.entry(iface_name).or_default().push(entry);
        }

        let mut iface_names: Vec<String> = routes_by_iface.keys().cloned().collect();
        iface_names.sort();
        if iface_names.is_empty() {
            buf.push_str("No routes found\n");
            return Ok(());
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
    Ok(())
}

fn append_file_section(buf: &mut String, path: &str) -> Result<(), ServiceError> {
    append_file_section_path(buf, Path::new(path))
}

fn append_file_section_path(buf: &mut String, path: &Path) -> Result<(), ServiceError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(ServiceError::OperationFailed(format!(
            "skipping symlink: {}",
            path.display()
        )));
    }

    let contents = fs::read_to_string(path)?;
    if contents.len() > MAX_SECTION_BYTES {
        buf.push_str(&contents[..MAX_SECTION_BYTES]);
        buf.push_str("\n[truncated file]\n");
    } else {
        buf.push_str(&contents);
    }
    Ok(())
}

fn append_log_tail_path(buf: &mut String, path: &Path) -> Result<(), ServiceError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Err(ServiceError::OperationFailed(format!(
                    "log file not found: {}",
                    path.display()
                )));
            }
            return Err(err.into());
        }
    };

    if meta.file_type().is_symlink() {
        return Err(ServiceError::OperationFailed(format!(
            "skipping symlink: {}",
            path.display()
        )));
    }

    let contents = tail_file(path, MAX_LOG_TAIL_BYTES)?;
    if contents.is_empty() {
        buf.push_str("(empty log file)\n");
    } else {
        buf.push_str(&contents);
        if !contents.ends_with('\n') {
            buf.push('\n');
        }
    }
    Ok(())
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
fn append_kernel_log_tail(out: &mut String) -> Result<(), ServiceError> {
    #[cfg(target_os = "linux")]
    {
        let logs = read_kmsg_tail(300)?;
        if logs.is_empty() {
            out.push_str("(no recent kernel messages)\n");
        } else {
            out.push_str(&logs);
            if !logs.ends_with('\n') {
                out.push('\n');
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        out.push_str("Kernel logging not supported on this platform\n");
    }
    Ok(())
}

/// Read recent kernel messages from /dev/kmsg
#[cfg(target_os = "linux")]
fn read_kmsg_tail(max_lines: usize) -> std::io::Result<String> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::OpenOptionsExt;

    if max_lines == 0 {
        return Ok(String::new());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")?;

    let mut lines: VecDeque<String> = VecDeque::new();
    let mut pending = String::new();
    let mut buf = [0u8; 4096];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = String::from_utf8_lossy(&buf[..n]);
                pending.push_str(&chunk);
                while let Some(pos) = pending.find('\n') {
                    let line = pending[..pos].to_string();
                    pending = pending[pos + 1..].to_string();
                    if lines.len() == max_lines {
                        lines.pop_front();
                    }
                    lines.push_back(line);
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }

    if !pending.is_empty() {
        if lines.len() == max_lines {
            lines.pop_front();
        }
        lines.push_back(pending);
    }

    Ok(lines.into_iter().collect::<Vec<_>>().join("\n"))
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
                buf.push_str(&format!(
                    "{}: exists, {} bytes\n",
                    device_path,
                    metadata.len()
                ));
            }
        }
        Err(err) => {
            buf.push_str(&format!("{}: ERROR - {}\n", device_path, err));
        }
    }
}
