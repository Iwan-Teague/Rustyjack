use std::fs;
use std::path::Path;
use std::process::Command;

use crate::services::error::ServiceError;

const MAX_LOG_BUNDLE_BYTES: usize = 900_000;
const MAX_SECTION_BYTES: usize = 200_000;
const MAX_CMD_OUTPUT_BYTES: usize = 100_000;

pub fn collect_log_bundle(root: &Path) -> Result<String, ServiceError> {
    let mut out = String::new();

    append_command_output(
        &mut out,
        "journalctl (rustyjack-ui.service)",
        "journalctl",
        &[
            "-u",
            "rustyjack-ui.service",
            "-b",
            "--no-pager",
            "-n",
            "500",
            "-o",
            "short-precise",
        ],
    );
    append_command_output(
        &mut out,
        "journalctl (kernel)",
        "journalctl",
        &["-k", "-b", "--no-pager", "-n", "300", "-o", "short-precise"],
    );
    append_command_output(
        &mut out,
        "journalctl (system)",
        "journalctl",
        &["-b", "--no-pager", "-n", "500", "-o", "short-precise"],
    );
    append_command_output(
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
    append_command_output(
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
    append_wpa_preflight(&mut out);
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
    out.push_str("--- gpioinfo stdout ---\n");
    out.push_str(&run_cmd_output("gpioinfo", &[]));
    out.push_str("--- lsof /dev/gpiochip0 stdout ---\n");
    out.push_str(&run_cmd_output("lsof", &["/dev/gpiochip0"]));
    out.push_str("--- fuser -v /dev/gpiochip0 stdout ---\n");
    out.push_str(&run_cmd_output("fuser", &["-v", "/dev/gpiochip0"]));
    out.push_str("--- ls -l /dev/gpiochip0 /dev/spidev0.0 /dev/spidev0.1 stdout ---\n");
    out.push_str(&run_cmd_output(
        "ls",
        &["-l", "/dev/gpiochip0", "/dev/spidev0.0", "/dev/spidev0.1"],
    ));
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
    buf.push_str("\n===== wpa_supplicant status =====\n");

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
                match rustyjack_netlink::WpaManager::new(&iface) {
                    Ok(wpa) => match wpa.status() {
                        Ok(status) => {
                            buf.push_str(&format!(
                                "{}: state={} ssid={:?} bssid={:?} freq={:?} ip={:?}\n",
                                iface,
                                status.wpa_state,
                                status.ssid,
                                status.bssid,
                                status.freq,
                                status.ip_address
                            ));
                        }
                        Err(err) => {
                            buf.push_str(&format!(
                                "{}: ERROR reading status: {}\n",
                                iface, err
                            ));
                        }
                    },
                    Err(err) => {
                        buf.push_str(&format!(
                            "{}: ERROR opening control: {}\n",
                            iface, err
                        ));
                    }
                }
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

fn append_wpa_preflight(buf: &mut String) {
    buf.push_str("\n===== wpa_supplicant preflight =====\n");

    #[cfg(target_os = "linux")]
    {
        use rustyjack_netlink::ProcessManager;

        let mut found = false;
        let pm = ProcessManager::new();
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

                let candidates = rustyjack_netlink::wpa_control_socket_status(&iface);
                if candidates.is_empty() {
                    buf.push_str(&format!("{iface}: no control socket candidates\n"));
                } else {
                    let rendered = candidates
                        .iter()
                        .map(|(path, exists)| {
                            format!(
                                "{}={}",
                                path.display(),
                                if *exists { "ok" } else { "missing" }
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    buf.push_str(&format!("{iface}: ctrl_sockets: {rendered}\n"));
                }

                match pm.find_by_pattern("wpa_supplicant") {
                    Ok(list) => {
                        let matches: Vec<String> = list
                            .into_iter()
                            .filter(|p| p.cmdline.contains(&iface))
                            .map(|p| format!("pid={} cmd={}", p.pid, p.cmdline))
                            .collect();
                        if matches.is_empty() {
                            buf.push_str(&format!("{iface}: wpa_supplicant process: none\n"));
                        } else {
                            buf.push_str(&format!(
                                "{iface}: wpa_supplicant process: {}\n",
                                matches.join(" | ")
                            ));
                        }
                    }
                    Err(err) => {
                        buf.push_str(&format!(
                            "{iface}: wpa_supplicant process lookup error: {err}\n"
                        ));
                    }
                }
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
