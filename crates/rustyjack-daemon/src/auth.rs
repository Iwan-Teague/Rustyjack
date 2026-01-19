use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::collections::HashMap;

use tracing::debug;
use tokio::net::UnixStream;

use rustyjack_ipc::{AuthorizationTier, Endpoint, JobKind};

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
        let gid = parts
            .next()
            .and_then(|s| s.parse::<u32>().ok());
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
        JobKind::ScanRun { .. } => AuthorizationTier::Operator,
        JobKind::SystemUpdate { .. } => AuthorizationTier::Admin,
        JobKind::CoreCommand { .. } => AuthorizationTier::Operator,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyjack_ipc::JobKind;

    #[test]
    fn test_tier_allows_admin_can_do_anything() {
        assert!(tier_allows(AuthorizationTier::Admin, AuthorizationTier::Admin));
        assert!(tier_allows(AuthorizationTier::Admin, AuthorizationTier::Operator));
        assert!(tier_allows(AuthorizationTier::Admin, AuthorizationTier::ReadOnly));
    }

    #[test]
    fn test_tier_allows_operator_cannot_admin() {
        assert!(!tier_allows(AuthorizationTier::Operator, AuthorizationTier::Admin));
        assert!(tier_allows(AuthorizationTier::Operator, AuthorizationTier::Operator));
        assert!(tier_allows(AuthorizationTier::Operator, AuthorizationTier::ReadOnly));
    }

    #[test]
    fn test_tier_allows_readonly_only_readonly() {
        assert!(!tier_allows(AuthorizationTier::ReadOnly, AuthorizationTier::Admin));
        assert!(!tier_allows(AuthorizationTier::ReadOnly, AuthorizationTier::Operator));
        assert!(tier_allows(AuthorizationTier::ReadOnly, AuthorizationTier::ReadOnly));
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
        assert_eq!(required_tier_for_jobkind(&kind), AuthorizationTier::ReadOnly);
    }

    #[test]
    fn test_required_tier_for_jobkind_mount_is_operator() {
        let kind = JobKind::MountStart {
            req: rustyjack_ipc::MountStartRequestIpc {
                device: "/dev/sda1".to_string(),
                filesystem: Some("ext4".to_string()),
            },
        };
        assert_eq!(required_tier_for_jobkind(&kind), AuthorizationTier::Operator);
    }

    #[test]
    fn test_required_tier_for_jobkind_update_is_admin() {
        let kind = JobKind::SystemUpdate {
            req: rustyjack_ipc::UpdateRequestIpc {
                service: "rustyjack".to_string(),
                remote: "origin".to_string(),
                branch: "main".to_string(),
                backup_dir: None,
            },
        };
        assert_eq!(required_tier_for_jobkind(&kind), AuthorizationTier::Admin);
    }

    #[test]
    fn test_required_tier_system_reboot_is_admin() {
        assert_eq!(required_tier(Endpoint::SystemReboot), AuthorizationTier::Admin);
        assert_eq!(required_tier(Endpoint::SystemShutdown), AuthorizationTier::Admin);
    }

    #[test]
    fn test_required_tier_version_is_readonly() {
        assert_eq!(required_tier(Endpoint::Version), AuthorizationTier::ReadOnly);
        assert_eq!(required_tier(Endpoint::Health), AuthorizationTier::ReadOnly);
    }

    #[test]
    fn test_required_tier_job_start_is_operator() {
        assert_eq!(required_tier(Endpoint::JobStart), AuthorizationTier::Operator);
    }
}
