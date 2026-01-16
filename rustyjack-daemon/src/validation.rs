use rustyjack_ipc::{DaemonError, ErrorCode, JobKind, ScanModeIpc};

const MAX_INTERFACE_NAME_LEN: usize = 64;
const MAX_SSID_LEN: usize = 32;
const MAX_PSK_LEN: usize = 64;
const MIN_PSK_LEN: usize = 8;
const MAX_DEVICE_PATH_LEN: usize = 256;
const MAX_PORT: u16 = 65535;
const MIN_PORT: u16 = 1;
const MAX_TIMEOUT_MS: u64 = 3_600_000;
const MAX_SLEEP_SECONDS: u64 = 86400;
const MAX_SCAN_TARGET_LEN: usize = 256;
const MAX_SCAN_PORTS: usize = 128;
const MAX_SERVICE_NAME_LEN: usize = 64;
const MAX_GIT_REMOTE_LEN: usize = 512;
const MAX_GIT_REF_LEN: usize = 128;
const MAX_BACKUP_DIR_LEN: usize = 256;

pub fn validate_interface_name(interface: &str) -> Result<(), DaemonError> {
    if interface.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "interface name cannot be empty",
            false,
        ));
    }
    if interface.len() > MAX_INTERFACE_NAME_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "interface name too long",
            false,
        ));
    }
    if !interface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "interface name contains invalid characters",
            false,
        ));
    }
    Ok(())
}

pub fn validate_ssid(ssid: &str) -> Result<(), DaemonError> {
    if ssid.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "SSID cannot be empty",
            false,
        ));
    }
    if ssid.len() > MAX_SSID_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "SSID too long (max 32 bytes)",
            false,
        ));
    }
    Ok(())
}

pub fn validate_psk(psk: &Option<String>) -> Result<(), DaemonError> {
    if let Some(ref passphrase) = psk {
        if passphrase.len() < MIN_PSK_LEN {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "PSK too short (min 8 characters)",
                false,
            ));
        }
        if passphrase.len() > MAX_PSK_LEN {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "PSK too long (max 64 characters)",
                false,
            ));
        }
    }
    Ok(())
}

pub fn validate_channel(channel: &Option<u8>) -> Result<(), DaemonError> {
    if let Some(ch) = channel {
        if *ch == 0 || *ch > 165 {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "invalid channel (must be 1-165)",
                false,
            ));
        }
    }
    Ok(())
}

pub fn validate_port(port: u16) -> Result<(), DaemonError> {
    if port < MIN_PORT || port > MAX_PORT {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "invalid port number",
            false,
        ));
    }
    if port < 1024 {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "privileged ports (<1024) not allowed",
            false,
        ));
    }
    Ok(())
}

pub fn validate_timeout_ms(timeout_ms: u64) -> Result<(), DaemonError> {
    if timeout_ms == 0 {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "timeout cannot be zero",
            false,
        ));
    }
    if timeout_ms > MAX_TIMEOUT_MS {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "timeout too large (max 1 hour)",
            false,
        ));
    }
    Ok(())
}

pub fn validate_device_path(device: &str) -> Result<(), DaemonError> {
    if device.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "device path cannot be empty",
            false,
        ));
    }
    if device.len() > MAX_DEVICE_PATH_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "device path too long",
            false,
        ));
    }
    if !device.starts_with('/') {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "device path must be absolute",
            false,
        ));
    }
    if device.contains("..") {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "device path contains directory traversal",
            false,
        ));
    }
    Ok(())
}

pub fn validate_filesystem(filesystem: &Option<String>) -> Result<(), DaemonError> {
    if let Some(ref fs) = filesystem {
        if fs.is_empty() {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "filesystem type cannot be empty",
                false,
            ));
        }
        let valid_filesystems = [
            "ext4", "ext3", "ext2", "vfat", "exfat", "ntfs", "ntfs-3g", "f2fs", "xfs", "btrfs",
        ];
        if !valid_filesystems.contains(&fs.as_str()) {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "unsupported filesystem type",
                false,
            ));
        }
    }
    Ok(())
}

pub fn validate_sleep_seconds(seconds: u64) -> Result<(), DaemonError> {
    if seconds == 0 {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "sleep duration cannot be zero",
            false,
        ));
    }
    if seconds > MAX_SLEEP_SECONDS {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "sleep duration too large (max 24 hours)",
            false,
        ));
    }
    Ok(())
}

pub fn validate_scan_target(target: &str) -> Result<(), DaemonError> {
    if target.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "scan target cannot be empty",
            false,
        ));
    }
    if target.len() > MAX_SCAN_TARGET_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "scan target too long",
            false,
        ));
    }
    if target.chars().any(|c| c.is_control()) {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "scan target contains control characters",
            false,
        ));
    }
    Ok(())
}

pub fn validate_scan_ports(mode: ScanModeIpc, ports: Option<&[u16]>) -> Result<(), DaemonError> {
    match mode {
        ScanModeIpc::DiscoveryOnly => {
            if ports.is_some() && !ports.unwrap().is_empty() {
                return Err(DaemonError::new(
                    ErrorCode::BadRequest,
                    "ports must be empty for DiscoveryOnly mode",
                    false,
                ));
            }
        }
        ScanModeIpc::DiscoveryAndPorts => {
            if let Some(port_list) = ports {
                if port_list.is_empty() {
                    return Err(DaemonError::new(
                        ErrorCode::BadRequest,
                        "ports cannot be empty for DiscoveryAndPorts mode",
                        false,
                    ));
                }
                if port_list.len() > MAX_SCAN_PORTS {
                    return Err(DaemonError::new(
                        ErrorCode::BadRequest,
                        "too many ports (max 128)",
                        false,
                    ));
                }
                for &port in port_list {
                    validate_port(port)?;
                }
            } else {
                return Err(DaemonError::new(
                    ErrorCode::BadRequest,
                    "ports required for DiscoveryAndPorts mode",
                    false,
                ));
            }
        }
    }
    Ok(())
}

pub fn validate_update_service(service: &str) -> Result<(), DaemonError> {
    if service.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "service name cannot be empty",
            false,
        ));
    }
    if service.len() > MAX_SERVICE_NAME_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "service name too long",
            false,
        ));
    }
    let allowed_services = ["rustyjack", "rustyjack-ui", "rustyjackd"];
    if !allowed_services.contains(&service) {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "unsupported service name",
            false,
        ));
    }
    if service.chars().any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == '\\') {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "service name contains invalid characters",
            false,
        ));
    }
    Ok(())
}

pub fn validate_git_remote(remote: &str) -> Result<(), DaemonError> {
    if remote.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git remote cannot be empty",
            false,
        ));
    }
    if remote.len() > MAX_GIT_REMOTE_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git remote too long",
            false,
        ));
    }
    if remote == "origin" {
        return Ok(());
    }
    if remote.starts_with("https://") || remote.starts_with("git@") {
        if remote.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(DaemonError::new(
                ErrorCode::BadRequest,
                "git remote contains invalid characters",
                false,
            ));
        }
        Ok(())
    } else {
        Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git remote must be 'origin' or start with https:// or git@",
            false,
        ))
    }
}

pub fn validate_git_ref(branch: &str) -> Result<(), DaemonError> {
    if branch.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git ref cannot be empty",
            false,
        ));
    }
    if branch.len() > MAX_GIT_REF_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git ref too long",
            false,
        ));
    }
    let invalid_chars = ['~', '^', ':', '?', '*', '[', ']', ' ', '\t', '\r', '\n'];
    if branch.chars().any(|c| invalid_chars.contains(&c) || c.is_control()) {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git ref contains invalid characters",
            false,
        ));
    }
    if branch.contains("..") {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "git ref contains directory traversal",
            false,
        ));
    }
    Ok(())
}

pub fn validate_backup_dir(path: &str) -> Result<(), DaemonError> {
    if path.is_empty() {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "backup dir cannot be empty",
            false,
        ));
    }
    if path.len() > MAX_BACKUP_DIR_LEN {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "backup dir too long",
            false,
        ));
    }
    if path.contains("..") {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "backup dir contains directory traversal",
            false,
        ));
    }
    let rustyjack_roots = ["/var/lib/rustyjack/backups", "/tmp/rustyjack/backups"];
    if !rustyjack_roots.iter().any(|root| path.starts_with(root)) {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "backup dir must be under /var/lib/rustyjack/backups or /tmp/rustyjack/backups",
            false,
        ));
    }
    Ok(())
}

pub fn validate_mount_device_hint(device: &str) -> Result<(), DaemonError> {
    validate_device_path(device)?;
    
    if !device.starts_with("/dev/") {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "device path must start with /dev/",
            false,
        ));
    }
    
    if device.starts_with("/dev/mmcblk") || device.starts_with("/dev/loop") {
        return Err(DaemonError::new(
            ErrorCode::BadRequest,
            "mounting internal mmc or loop devices not allowed",
            false,
        ));
    }
    
    Ok(())
}

pub fn validate_job_kind(kind: &JobKind) -> Result<(), DaemonError> {
    match kind {
        JobKind::Noop => Ok(()),
        JobKind::Sleep { seconds } => validate_sleep_seconds(*seconds),
        JobKind::ScanRun { req } => {
            validate_scan_target(&req.target)?;
            validate_timeout_ms(req.timeout_ms)?;
            validate_scan_ports(req.mode.clone(), req.ports.as_deref())?;
            Ok(())
        }
        JobKind::SystemUpdate { req } => {
            validate_update_service(&req.service)?;
            validate_git_remote(&req.remote)?;
            validate_git_ref(&req.branch)?;
            if let Some(dir) = &req.backup_dir {
                validate_backup_dir(dir)?;
            }
            Ok(())
        }
        JobKind::WifiScan { req } => {
            validate_interface_name(&req.interface)?;
            validate_timeout_ms(req.timeout_ms)?;
            Ok(())
        }
        JobKind::WifiConnect { req } => {
            validate_interface_name(&req.interface)?;
            validate_ssid(&req.ssid)?;
            validate_psk(&req.psk)?;
            validate_timeout_ms(req.timeout_ms)?;
            Ok(())
        }
        JobKind::HotspotStart { req } => {
            validate_interface_name(&req.interface)?;
            validate_ssid(&req.ssid)?;
            validate_psk(&req.passphrase)?;
            validate_channel(&req.channel)?;
            Ok(())
        }
        JobKind::PortalStart { req } => {
            validate_interface_name(&req.interface)?;
            validate_port(req.port)?;
            Ok(())
        }
        JobKind::MountStart { req } => {
            validate_mount_device_hint(&req.device)?;
            validate_filesystem(&req.filesystem)?;
            Ok(())
        }
        JobKind::UnmountStart { req } => {
            validate_mount_device_hint(&req.device)?;
            Ok(())
        }
        JobKind::InterfaceSelect { interface } => {
            validate_interface_name(interface)?;
            Ok(())
        }
        JobKind::CoreCommand { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyjack_ipc::{JobKind, MountStartRequestIpc, ScanModeIpc, ScanRequestIpc, UpdateRequestIpc, WifiConnectRequestIpc};

    #[test]
    fn test_validate_mount_device_rejects_mmcblk() {
        let result = validate_mount_device_hint("/dev/mmcblk0p1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("mmcblk"));
    }

    #[test]
    fn test_validate_mount_device_rejects_loop() {
        let result = validate_mount_device_hint("/dev/loop0");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("loop"));
    }

    #[test]
    fn test_validate_mount_device_requires_dev_prefix() {
        let result = validate_mount_device_hint("/mnt/usb");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("/dev/"));
    }

    #[test]
    fn test_validate_mount_device_accepts_sda() {
        let result = validate_mount_device_hint("/dev/sda1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_filesystem_accepts_common_types() {
        assert!(validate_filesystem(&Some("ext4".to_string())).is_ok());
        assert!(validate_filesystem(&Some("vfat".to_string())).is_ok());
        assert!(validate_filesystem(&Some("exfat".to_string())).is_ok());
        assert!(validate_filesystem(&Some("ntfs".to_string())).is_ok());
    }

    #[test]
    fn test_validate_filesystem_rejects_unknown() {
        let result = validate_filesystem(&Some("invalid_fs".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_channel_rejects_zero() {
        let result = validate_channel(&Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_channel_rejects_out_of_range() {
        let result = validate_channel(&Some(166));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_channel_accepts_valid() {
        assert!(validate_channel(&Some(1)).is_ok());
        assert!(validate_channel(&Some(11)).is_ok());
        assert!(validate_channel(&Some(165)).is_ok());
    }

    #[test]
    fn test_validate_port_rejects_privileged() {
        let result = validate_port(80);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("1024"));
    }

    #[test]
    fn test_validate_port_accepts_high_ports() {
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(3000).is_ok());
    }

    #[test]
    fn test_validate_sleep_seconds_rejects_zero() {
        let result = validate_sleep_seconds(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_sleep_seconds_rejects_too_large() {
        let result = validate_sleep_seconds(MAX_SLEEP_SECONDS + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_job_kind_mount_rejects_mmcblk() {
        let kind = JobKind::MountStart {
            req: MountStartRequestIpc {
                device: "/dev/mmcblk0p1".to_string(),
                filesystem: None,
            },
        };
        let result = validate_job_kind(&kind);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_job_kind_wifi_connect_requires_valid_ssid() {
        let kind = JobKind::WifiConnect {
            req: WifiConnectRequestIpc {
                interface: "wlan0".to_string(),
                ssid: "".to_string(),
                psk: None,
                timeout_ms: 30000,
            },
        };
        let result = validate_job_kind(&kind);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_job_kind_scan_rejects_empty_target() {
        let kind = JobKind::ScanRun {
            req: ScanRequestIpc {
                target: "".to_string(),
                mode: ScanModeIpc::DiscoveryOnly,
                ports: None,
                timeout_ms: 60000,
            },
        };
        let result = validate_job_kind(&kind);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_service_only_allows_known_services() {
        assert!(validate_update_service("rustyjack").is_ok());
        assert!(validate_update_service("rustyjack-ui").is_ok());
        assert!(validate_update_service("rustyjackd").is_ok());
        
        let result = validate_update_service("arbitrary-service");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_git_remote_requires_https_or_git() {
        assert!(validate_git_remote("origin").is_ok());
        assert!(validate_git_remote("https://github.com/user/repo").is_ok());
        assert!(validate_git_remote("git@github.com:user/repo").is_ok());
        
        let result = validate_git_remote("http://insecure.com/repo");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_backup_dir_requires_rustyjack_prefix() {
        assert!(validate_backup_dir("/var/lib/rustyjack/backups/test").is_ok());
        assert!(validate_backup_dir("/tmp/rustyjack/backups/test").is_ok());
        
        let result = validate_backup_dir("/tmp/evil");
        assert!(result.is_err());
    }
}
