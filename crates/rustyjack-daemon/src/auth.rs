use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;

use tokio::net::UnixStream;
use tracing::debug;

use rustyjack_ipc::{AuthorizationTier, Endpoint, JobKind, RequestBody, SystemCommand};

use crate::config::DaemonConfig;

#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCred> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerCred {
        pid: cred.pid as u32,
        uid: cred.uid as u32,
        gid: cred.gid as u32,
    })
}

pub fn authorization_for(uid: u32) -> AuthorizationTier {
    if uid == 0 {
        AuthorizationTier::Admin
    } else {
        AuthorizationTier::Operator
    }
}

/// Determine authorization tier based on uid and supplementary groups.
///
/// Checks:
/// 1. uid == 0 => Admin (root always admin)
/// 2. Member of admin_group => Admin
/// 3. Member of operator_group => Operator
/// 4. Otherwise => ReadOnly
pub fn authorization_for_peer(peer: &PeerCred, config: &DaemonConfig) -> AuthorizationTier {
    // Root is always admin
    if peer.uid == 0 {
        return AuthorizationTier::Admin;
    }

    // Check supplementary groups
    match read_supplementary_groups(peer) {
        Ok(group_names) => {
            debug!(
                "peer pid {} uid {} groups: {:?}",
                peer.pid, peer.uid, group_names
            );

            if group_names.contains(&config.admin_group) {
                return AuthorizationTier::Admin;
            }

            if group_names.contains(&config.operator_group) {
                return AuthorizationTier::Operator;
            }

            // Not in any special group
            AuthorizationTier::ReadOnly
        }
        Err(err) => {
            debug!(
                "failed to read groups for pid {} uid {}: {}",
                peer.pid, peer.uid, err
            );
            // Fail closed when peer groups cannot be determined.
            AuthorizationTier::ReadOnly
        }
    }
}

/// Read supplementary group names for a process from /proc/<pid>/status.
///
/// Parses the "Groups:" line which contains space-separated GIDs,
/// then resolves each GID to a group name via /etc/group.
fn read_supplementary_groups(peer: &PeerCred) -> io::Result<Vec<String>> {
    let status_path = format!("/proc/{}/status", peer.pid);
    let content = fs::read_to_string(&status_path)?;

    // Verify Uid matches the kernel-provided peer credential.
    let uid_line = content
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Uid line not found"))?;
    let mut uid_parts = uid_line.split_whitespace();
    let _label = uid_parts.next();
    let real_uid = uid_parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Uid parse failed"))?;
    if real_uid != peer.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pid uid mismatch",
        ));
    }

    // Find "Groups:" line
    let groups_line = content
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Groups line not found"))?;

    // Parse GIDs
    let gids: Vec<u32> = groups_line
        .trim_start_matches("Groups:")
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    let map = parse_group_file()?;
    Ok(gids
        .into_iter()
        .filter_map(|gid| map.get(&gid).cloned())
        .collect())
}

/// Resolve GID to group name by reading /etc/group.
///
/// This is a simple parser for the group file format:
/// groupname:x:gid:members
fn parse_group_file() -> io::Result<HashMap<u32, String>> {
    let group_content = fs::read_to_string("/etc/group")?;
    let mut map = HashMap::new();

    for line in group_content.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        let _pw = parts.next();
        let gid = parts.next().and_then(|s| s.parse::<u32>().ok());
        if let Some(gid) = gid {
            map.insert(gid, name.to_string());
        }
    }

    Ok(map)
}

pub fn required_tier(endpoint: Endpoint) -> AuthorizationTier {
    match endpoint {
        Endpoint::Health => AuthorizationTier::ReadOnly,
        Endpoint::Version => AuthorizationTier::ReadOnly,
        Endpoint::Status => AuthorizationTier::ReadOnly,
        Endpoint::OpsConfigGet => AuthorizationTier::Operator,
        Endpoint::OpsConfigSet => AuthorizationTier::Operator,
        Endpoint::JobStart => AuthorizationTier::Operator,
        Endpoint::JobStatus => AuthorizationTier::Operator,
        Endpoint::JobCancel => AuthorizationTier::Operator,
        Endpoint::CoreDispatch => AuthorizationTier::Operator,
        Endpoint::StatusCommand => AuthorizationTier::ReadOnly,
        Endpoint::WifiCommand => AuthorizationTier::Operator,
        Endpoint::EthernetCommand => AuthorizationTier::Operator,
        Endpoint::LootCommand => AuthorizationTier::Operator,
        Endpoint::NotifyCommand => AuthorizationTier::Operator,
        Endpoint::SystemCommand => AuthorizationTier::Operator,
        Endpoint::HardwareCommand => AuthorizationTier::Operator,
        Endpoint::DnsSpoofCommand => AuthorizationTier::Operator,
        Endpoint::MitmCommand => AuthorizationTier::Operator,
        Endpoint::ReverseCommand => AuthorizationTier::Operator,
        Endpoint::HotspotCommand => AuthorizationTier::Operator,
        Endpoint::ScanCommand => AuthorizationTier::Operator,
        Endpoint::BridgeCommand => AuthorizationTier::Operator,
        Endpoint::ProcessCommand => AuthorizationTier::Operator,
        Endpoint::SystemStatusGet => AuthorizationTier::ReadOnly,
        Endpoint::DiskUsageGet => AuthorizationTier::ReadOnly,
        Endpoint::SystemReboot => AuthorizationTier::Admin,
        Endpoint::SystemShutdown => AuthorizationTier::Admin,
        Endpoint::SystemSync => AuthorizationTier::Admin,
        Endpoint::HostnameRandomizeNow => AuthorizationTier::Admin,
        Endpoint::BlockDevicesList => AuthorizationTier::ReadOnly,
        Endpoint::SystemLogsGet => AuthorizationTier::Operator,
        Endpoint::ActiveInterfaceGet => AuthorizationTier::ReadOnly,
        Endpoint::ActiveInterfaceClear => AuthorizationTier::Operator,
        Endpoint::InterfaceStatusGet => AuthorizationTier::ReadOnly,
        Endpoint::WifiCapabilitiesGet => AuthorizationTier::ReadOnly,
        Endpoint::HotspotWarningsGet => AuthorizationTier::Operator,
        Endpoint::HotspotDiagnosticsGet => AuthorizationTier::Operator,
        Endpoint::HotspotClientsList => AuthorizationTier::Operator,
        Endpoint::GpioDiagnosticsGet => AuthorizationTier::Operator,
        Endpoint::WifiInterfacesList => AuthorizationTier::ReadOnly,
        Endpoint::WifiDisconnect => AuthorizationTier::Operator,
        Endpoint::WifiScanStart => AuthorizationTier::Operator,
        Endpoint::WifiConnectStart => AuthorizationTier::Operator,
        Endpoint::HotspotStart => AuthorizationTier::Operator,
        Endpoint::HotspotStop => AuthorizationTier::Operator,
        Endpoint::PortalStart => AuthorizationTier::Operator,
        Endpoint::PortalStop => AuthorizationTier::Operator,
        Endpoint::PortalStatus => AuthorizationTier::ReadOnly,
        Endpoint::MountList => AuthorizationTier::ReadOnly,
        Endpoint::MountStart => AuthorizationTier::Operator,
        Endpoint::UnmountStart => AuthorizationTier::Operator,
        Endpoint::SetActiveInterface => AuthorizationTier::Operator,
        Endpoint::HotplugNotify => AuthorizationTier::Operator,
        Endpoint::LogTailGet => AuthorizationTier::Operator,
        Endpoint::LoggingConfigGet => AuthorizationTier::ReadOnly,
        Endpoint::LoggingConfigSet => AuthorizationTier::Admin,
    }
}

pub fn required_tier_for_request(endpoint: Endpoint, body: &RequestBody) -> AuthorizationTier {
    use AuthorizationTier as T;
    use Endpoint as E;
    use RequestBody as B;

    match endpoint {
        E::Health
        | E::Version
        | E::Status
        | E::OpsConfigGet
        | E::SystemStatusGet
        | E::SystemLogsGet
        | E::InterfaceStatusGet
        | E::WifiCapabilitiesGet
        | E::WifiInterfacesList
        | E::HotspotWarningsGet
        | E::HotspotDiagnosticsGet
        | E::HotspotClientsList
        | E::GpioDiagnosticsGet
        | E::LoggingConfigGet
        | E::LogTailGet
        | E::StatusCommand => return T::ReadOnly,
        _ => {}
    }

    if endpoint == E::JobStart {
        if let B::JobStart(req) = body {
            return required_tier_for_jobkind(&req.job.kind);
        }
        return T::Admin;
    }

    if endpoint == E::SystemCommand {
        if let B::SystemCommand(cmd) = body {
            return required_tier_for_system_command(cmd);
        }
        return T::Admin;
    }

    if endpoint == E::CoreDispatch {
        return T::Admin;
    }

    required_tier(endpoint)
}

fn required_tier_for_system_command(cmd: &SystemCommand) -> AuthorizationTier {
    use rustyjack_ipc::SystemCommand as SC;
    use AuthorizationTier as T;

    match cmd {
        SC::RandomizeHostname | SC::UsbMount(_) | SC::UsbUnmount(_) | SC::ExportLogsToUsb(_) => {
            T::Operator
        }
        _ => T::Admin,
    }
}

pub fn tier_allows(actual: AuthorizationTier, required: AuthorizationTier) -> bool {
    match (actual, required) {
        (AuthorizationTier::Admin, _) => true,
        (AuthorizationTier::Operator, AuthorizationTier::Operator)
        | (AuthorizationTier::Operator, AuthorizationTier::ReadOnly) => true,
        (AuthorizationTier::ReadOnly, AuthorizationTier::ReadOnly) => true,
        _ => false,
    }
}

pub fn required_tier_for_jobkind(kind: &JobKind) -> AuthorizationTier {
    match kind {
        JobKind::Noop => AuthorizationTier::ReadOnly,
        JobKind::Sleep { .. } => AuthorizationTier::ReadOnly,
        JobKind::WifiScan { .. } => AuthorizationTier::Operator,
        JobKind::WifiConnect { .. } => AuthorizationTier::Operator,
        JobKind::HotspotStart { .. } => AuthorizationTier::Operator,
        JobKind::PortalStart { .. } => AuthorizationTier::Operator,
        JobKind::MountStart { .. } => AuthorizationTier::Operator,
        JobKind::UnmountStart { .. } => AuthorizationTier::Operator,
        JobKind::InterfaceSelect { .. } => AuthorizationTier::Operator,
        JobKind::ScanRun { .. } => AuthorizationTier::Admin,
        JobKind::SystemUpdate { .. } => AuthorizationTier::Operator,
        JobKind::CoreCommand { .. } => AuthorizationTier::Admin,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RequiredOps {
    None,
    Wifi,
    Eth,
    Hotspot,
    Portal,
    Storage,
    Power,
    System,
    Update,
    Dev,
    Offensive,
    Loot,
    Process,
}

pub fn required_ops_for_request(endpoint: Endpoint, body: &RequestBody) -> RequiredOps {
    use Endpoint as E;
    use RequestBody as B;

    match endpoint {
        E::Health
        | E::Version
        | E::Status
        | E::OpsConfigGet
        | E::SystemStatusGet
        | E::SystemLogsGet
        | E::ActiveInterfaceGet
        | E::InterfaceStatusGet
        | E::WifiCapabilitiesGet
        | E::WifiInterfacesList
        | E::HotspotWarningsGet
        | E::HotspotDiagnosticsGet
        | E::HotspotClientsList
        | E::GpioDiagnosticsGet
        | E::LoggingConfigGet
        | E::LogTailGet
        | E::PortalStatus
        | E::StatusCommand
        | E::HardwareCommand
        | E::JobStatus
        | E::JobCancel => return RequiredOps::None,
        _ => {}
    }

    match endpoint {
        E::WifiDisconnect | E::WifiScanStart | E::WifiConnectStart => RequiredOps::Wifi,
        E::WifiCommand => match body {
            B::WifiCommand(cmd) => match cmd {
                rustyjack_ipc::WifiCommand::Deauth(_)
                | rustyjack_ipc::WifiCommand::EvilTwin(_)
                | rustyjack_ipc::WifiCommand::PmkidCapture(_)
                | rustyjack_ipc::WifiCommand::ProbeSniff(_)
                | rustyjack_ipc::WifiCommand::Crack(_)
                | rustyjack_ipc::WifiCommand::Karma(_)
                | rustyjack_ipc::WifiCommand::PipelinePreflight(_) => RequiredOps::Offensive,
                _ => RequiredOps::Wifi,
            },
            _ => RequiredOps::Wifi,
        },
        E::OpsConfigSet => RequiredOps::None,
        E::EthernetCommand | E::SetActiveInterface | E::ActiveInterfaceClear => RequiredOps::Eth,
        E::HotspotStart | E::HotspotStop | E::HotspotCommand => RequiredOps::Hotspot,
        E::PortalStart | E::PortalStop => RequiredOps::Portal,
        E::MountList | E::MountStart | E::UnmountStart | E::BlockDevicesList | E::DiskUsageGet => {
            RequiredOps::Storage
        }
        E::SystemReboot | E::SystemShutdown | E::SystemSync => RequiredOps::Power,
        E::HostnameRandomizeNow | E::LoggingConfigSet => RequiredOps::System,
        E::JobStart => match body {
            B::JobStart(req) => required_ops_for_jobkind(&req.job.kind),
            _ => RequiredOps::Dev,
        },
        E::SystemCommand | E::NotifyCommand => match body {
            B::SystemCommand(cmd) => required_ops_for_system_command(cmd),
            _ => RequiredOps::System,
        },
        E::CoreDispatch => RequiredOps::Dev,
        E::DnsSpoofCommand
        | E::MitmCommand
        | E::ReverseCommand
        | E::ScanCommand
        | E::BridgeCommand => RequiredOps::Offensive,
        E::LootCommand => RequiredOps::Loot,
        E::ProcessCommand => RequiredOps::Process,
        E::HotplugNotify => RequiredOps::Eth,
        _ => RequiredOps::Dev,
    }
}

fn required_ops_for_system_command(cmd: &SystemCommand) -> RequiredOps {
    use rustyjack_ipc::SystemCommand as SC;

    match cmd {
        SC::Update(_) => RequiredOps::Update,
        SC::UsbMount(_) | SC::UsbUnmount(_) | SC::ExportLogsToUsb(_) => RequiredOps::Storage,
        SC::Reboot | SC::Poweroff => RequiredOps::Power,
        _ => RequiredOps::System,
    }
}

pub fn required_ops_for_jobkind(kind: &JobKind) -> RequiredOps {
    match kind {
        JobKind::WifiScan { .. } | JobKind::WifiConnect { .. } => RequiredOps::Wifi,
        JobKind::HotspotStart { .. } => RequiredOps::Hotspot,
        JobKind::PortalStart { .. } => RequiredOps::Portal,
        JobKind::MountStart { .. } | JobKind::UnmountStart { .. } => RequiredOps::Storage,
        JobKind::SystemUpdate { .. } => RequiredOps::Update,
        JobKind::ScanRun { .. } => RequiredOps::Offensive,
        JobKind::CoreCommand { .. } => RequiredOps::Dev,
        JobKind::InterfaceSelect { .. } => RequiredOps::Eth,
        JobKind::Noop | JobKind::Sleep { .. } => RequiredOps::None,
    }
}

pub fn ops_allows(cfg: &crate::ops::OpsConfig, required: RequiredOps) -> bool {
    match required {
        RequiredOps::None => true,
        RequiredOps::Wifi => cfg.wifi_ops,
        RequiredOps::Eth => cfg.eth_ops,
        RequiredOps::Hotspot => cfg.hotspot_ops,
        RequiredOps::Portal => cfg.portal_ops,
        RequiredOps::Storage => cfg.storage_ops,
        RequiredOps::Power => cfg.power_ops,
        RequiredOps::System => cfg.system_ops,
        RequiredOps::Update => cfg.update_ops,
        RequiredOps::Dev => cfg.dev_ops,
        RequiredOps::Offensive => cfg.offensive_ops,
        RequiredOps::Loot => cfg.loot_ops,
        RequiredOps::Process => cfg.process_ops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyjack_commands::{UsbMountArgs, WifiDeauthArgs};
    use rustyjack_ipc::WifiPipelinePreflightArgs;
    use rustyjack_ipc::{JobKind, SystemCommand, WifiCommand};

    #[test]
    fn test_tier_allows_admin_can_do_anything() {
        assert!(tier_allows(
            AuthorizationTier::Admin,
            AuthorizationTier::Admin
        ));
        assert!(tier_allows(
            AuthorizationTier::Admin,
            AuthorizationTier::Operator
        ));
        assert!(tier_allows(
            AuthorizationTier::Admin,
            AuthorizationTier::ReadOnly
        ));
    }

    #[test]
    fn test_tier_allows_operator_cannot_admin() {
        assert!(!tier_allows(
            AuthorizationTier::Operator,
            AuthorizationTier::Admin
        ));
        assert!(tier_allows(
            AuthorizationTier::Operator,
            AuthorizationTier::Operator
        ));
        assert!(tier_allows(
            AuthorizationTier::Operator,
            AuthorizationTier::ReadOnly
        ));
    }

    #[test]
    fn test_tier_allows_readonly_only_readonly() {
        assert!(!tier_allows(
            AuthorizationTier::ReadOnly,
            AuthorizationTier::Admin
        ));
        assert!(!tier_allows(
            AuthorizationTier::ReadOnly,
            AuthorizationTier::Operator
        ));
        assert!(tier_allows(
            AuthorizationTier::ReadOnly,
            AuthorizationTier::ReadOnly
        ));
    }

    #[test]
    fn test_authorization_for_root_is_admin() {
        assert_eq!(authorization_for(0), AuthorizationTier::Admin);
    }

    #[test]
    fn test_authorization_for_non_root_is_operator() {
        assert_eq!(authorization_for(1000), AuthorizationTier::Operator);
    }

    #[test]
    fn test_required_tier_for_jobkind_sleep_is_readonly() {
        let kind = JobKind::Sleep { seconds: 10 };
        assert_eq!(
            required_tier_for_jobkind(&kind),
            AuthorizationTier::ReadOnly
        );
    }

    #[test]
    fn test_required_tier_for_jobkind_mount_is_operator() {
        let kind = JobKind::MountStart {
            req: rustyjack_ipc::MountStartRequestIpc {
                device: "/dev/sda1".to_string(),
                filesystem: Some("ext4".to_string()),
            },
        };
        assert_eq!(
            required_tier_for_jobkind(&kind),
            AuthorizationTier::Operator
        );
    }

    #[test]
    fn test_required_tier_for_jobkind_update_is_operator() {
        let kind = JobKind::SystemUpdate {
            req: rustyjack_ipc::UpdateRequestIpc {
                url: "https://example.com/update.tar.zst".to_string(),
            },
        };
        assert_eq!(
            required_tier_for_jobkind(&kind),
            AuthorizationTier::Operator
        );
    }

    #[test]
    fn test_required_tier_system_reboot_is_admin() {
        assert_eq!(
            required_tier(Endpoint::SystemReboot),
            AuthorizationTier::Admin
        );
        assert_eq!(
            required_tier(Endpoint::SystemShutdown),
            AuthorizationTier::Admin
        );
    }

    #[test]
    fn test_required_ops_for_wifi_command_offensive() {
        let body = RequestBody::WifiCommand(WifiCommand::Deauth(WifiDeauthArgs {
            bssid: "00:11:22:33:44:55".to_string(),
            ssid: None,
            interface: "wlan0".to_string(),
            channel: 1,
            duration: 1,
            packets: 1,
            client: None,
            continuous: true,
            interval: 1,
        }));
        assert_eq!(
            required_ops_for_request(Endpoint::WifiCommand, &body),
            RequiredOps::Offensive
        );

        let preflight =
            RequestBody::WifiCommand(WifiCommand::PipelinePreflight(WifiPipelinePreflightArgs {
                interface: Some("wlan0".to_string()),
                pipeline: "get_password".to_string(),
                requires_monitor: true,
            }));
        assert_eq!(
            required_ops_for_request(Endpoint::WifiCommand, &preflight),
            RequiredOps::Offensive
        );

        let benign = RequestBody::WifiCommand(WifiCommand::List);
        assert_eq!(
            required_ops_for_request(Endpoint::WifiCommand, &benign),
            RequiredOps::Wifi
        );
    }

    #[test]
    fn test_required_ops_opsconfig_get_is_none() {
        let body = RequestBody::OpsConfigGet;
        assert_eq!(
            required_ops_for_request(Endpoint::OpsConfigGet, &body),
            RequiredOps::None
        );
    }

    #[test]
    fn test_required_tier_version_is_readonly() {
        assert_eq!(
            required_tier(Endpoint::Version),
            AuthorizationTier::ReadOnly
        );
        assert_eq!(required_tier(Endpoint::Health), AuthorizationTier::ReadOnly);
    }

    #[test]
    fn test_required_tier_job_start_is_operator() {
        assert_eq!(
            required_tier(Endpoint::JobStart),
            AuthorizationTier::Operator
        );
    }

    #[test]
    fn test_required_tier_for_request_system_command_update_is_admin() {
        let tier = required_tier_for_request(
            Endpoint::SystemCommand,
            &RequestBody::SystemCommand(SystemCommand::Update(
                rustyjack_commands::SystemUpdateArgs {
                    url: "https://example.com/update.tar.zst".to_string(),
                },
            )),
        );
        assert_eq!(tier, AuthorizationTier::Admin);
    }

    #[test]
    fn test_required_tier_for_request_system_command_randomize_is_operator() {
        let tier = required_tier_for_request(
            Endpoint::SystemCommand,
            &RequestBody::SystemCommand(SystemCommand::RandomizeHostname),
        );
        assert_eq!(tier, AuthorizationTier::Operator);
    }

    #[test]
    fn test_required_ops_for_request_update_job_is_update() {
        let kind = JobKind::SystemUpdate {
            req: rustyjack_ipc::UpdateRequestIpc {
                url: "https://example.com/update.tar.zst".to_string(),
            },
        };
        let body = RequestBody::JobStart(rustyjack_ipc::JobStartRequest {
            job: rustyjack_ipc::JobSpec {
                kind,
                requested_by: None,
            },
        });
        assert_eq!(
            required_ops_for_request(Endpoint::JobStart, &body),
            RequiredOps::Update
        );
    }

    #[test]
    fn test_required_ops_for_request_core_dispatch_is_dev() {
        let body = RequestBody::CoreDispatch(rustyjack_ipc::CoreDispatchRequest {
            legacy: rustyjack_ipc::LegacyCommand::CommandDispatch,
            args: serde_json::json!({}),
        });
        assert_eq!(
            required_ops_for_request(Endpoint::CoreDispatch, &body),
            RequiredOps::Dev
        );
    }

    #[test]
    fn test_required_ops_for_request_system_command_mount_is_storage() {
        let body = RequestBody::SystemCommand(SystemCommand::UsbMount(UsbMountArgs {
            device: "/dev/sda1".to_string(),
            mode: rustyjack_commands::UsbMountMode::ReadOnly,
            name: None,
        }));
        assert_eq!(
            required_ops_for_request(Endpoint::SystemCommand, &body),
            RequiredOps::Storage
        );
    }

    #[test]
    fn test_required_ops_for_request_system_command_reboot_is_power() {
        let body = RequestBody::SystemCommand(SystemCommand::Reboot);
        assert_eq!(
            required_ops_for_request(Endpoint::SystemCommand, &body),
            RequiredOps::Power
        );
        let body = RequestBody::SystemCommand(SystemCommand::Poweroff);
        assert_eq!(
            required_ops_for_request(Endpoint::SystemCommand, &body),
            RequiredOps::Power
        );
    }

    #[test]
    fn test_required_ops_for_request_portal_status_is_none() {
        let body = RequestBody::PortalStatus;
        assert_eq!(
            required_ops_for_request(Endpoint::PortalStatus, &body),
            RequiredOps::None
        );
    }

    #[test]
    fn test_required_ops_for_power_endpoints() {
        let body = RequestBody::SystemReboot;
        assert_eq!(
            required_ops_for_request(Endpoint::SystemReboot, &body),
            RequiredOps::Power
        );
        let body = RequestBody::SystemShutdown;
        assert_eq!(
            required_ops_for_request(Endpoint::SystemShutdown, &body),
            RequiredOps::Power
        );
        let body = RequestBody::SystemSync;
        assert_eq!(
            required_ops_for_request(Endpoint::SystemSync, &body),
            RequiredOps::Power
        );
    }

    #[test]
    fn test_required_ops_for_request_active_interface_get_is_none() {
        let body = RequestBody::ActiveInterfaceGet;
        assert_eq!(
            required_ops_for_request(Endpoint::ActiveInterfaceGet, &body),
            RequiredOps::None
        );
    }
}
