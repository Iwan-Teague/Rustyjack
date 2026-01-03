use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::mount::{
    enumerate_usb_block_devices, list_mounts_under, mount_device as policy_mount_device,
    unmount as policy_unmount, FsType, MountMode, MountPolicy, MountRequest as PolicyMountRequest,
    UnmountRequest as PolicyUnmountRequest,
};
use crate::services::error::ServiceError;

#[derive(Debug, Clone)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub size: String,
    pub model: String,
    pub transport: String,
    pub removable: bool,
}

fn default_mount_policy() -> MountPolicy {
    let root = crate::resolve_root(None).unwrap_or_else(|_| PathBuf::from("/var/lib/rustyjack"));
    let mount_root = root.join("mounts");
    
    let mut allowed_fs = std::collections::BTreeSet::new();
    allowed_fs.insert(FsType::Vfat);
    allowed_fs.insert(FsType::Ext4);
    allowed_fs.insert(FsType::Exfat);
    
    MountPolicy {
        mount_root,
        allowed_fs,
        default_mode: MountMode::ReadOnly,
        allow_rw: false,
        max_devices: 4,
        lock_timeout: Duration::from_secs(10),
    }
}

pub fn list_block_devices() -> Result<Vec<BlockDeviceInfo>, ServiceError> {
    let devices = enumerate_usb_block_devices()
        .map_err(|e| ServiceError::External(format!("enumerate USB devices: {}", e)))?;
    
    let mut result = Vec::new();
    for dev in devices {
        let size = dev
            .partitions
            .first()
            .and_then(|p| p.size_bytes)
            .map(|s| format_size(s))
            .unwrap_or_else(|| "unknown".to_string());
        
        result.push(BlockDeviceInfo {
            name: dev.devnode.to_string_lossy().to_string(),
            size,
            model: "USB Device".to_string(),
            transport: if dev.is_usb { "usb" } else { "unknown" }.to_string(),
            removable: dev.removable,
        });
        
        for part in dev.partitions {
            let part_size = part
                .size_bytes
                .map(format_size)
                .unwrap_or_else(|| "unknown".to_string());
            
            result.push(BlockDeviceInfo {
                name: part.devnode.to_string_lossy().to_string(),
                size: part_size,
                model: "Partition".to_string(),
                transport: if dev.is_usb { "usb" } else { "unknown" }.to_string(),
                removable: dev.removable,
            });
        }
    }
    
    Ok(result)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[derive(Debug, Clone)]
pub struct MountInfo {
    pub device: String,
    pub mountpoint: String,
    pub filesystem: String,
    pub size: String,
}

pub fn list_mounts() -> Result<Vec<MountInfo>, ServiceError> {
    let policy = default_mount_policy();
    let mounts = list_mounts_under(&policy)
        .map_err(|e| ServiceError::External(format!("list mounts: {}", e)))?;
    
    let mut result = Vec::new();
    for m in mounts {
        result.push(MountInfo {
            device: m.device.to_string_lossy().to_string(),
            mountpoint: m.mountpoint.to_string_lossy().to_string(),
            filesystem: format!("{:?}", m.fs_type).to_lowercase(),
            size: "".to_string(),
        });
    }
    
    Ok(result)
}

pub struct MountRequest {
    pub device: String,
    pub filesystem: Option<String>,
}

pub fn mount<F>(req: MountRequest, mut on_progress: F) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.device.trim().is_empty() {
        return Err(ServiceError::InvalidInput("device".to_string()));
    }
    
    if !req.device.starts_with("/dev/") {
        return Err(ServiceError::InvalidInput(
            "device must start with /dev/".to_string(),
        ));
    }
    
    on_progress(10, "Validating device");
    
    let policy = default_mount_policy();
    let device = PathBuf::from(&req.device);
    
    let policy_req = PolicyMountRequest {
        device: device.clone(),
        mode: MountMode::ReadOnly,
        preferred_name: None,
    };
    
    on_progress(30, "Checking device");
    
    let response = policy_mount_device(&policy, policy_req)
        .map_err(|e| ServiceError::OperationFailed(format!("mount failed: {}", e)))?;
    
    on_progress(100, "Mounted");
    
    Ok(serde_json::json!({
        "device": response.device.to_string_lossy(),
        "mountpoint": response.mountpoint.to_string_lossy(),
        "filesystem": format!("{:?}", response.fs_type).to_lowercase(),
        "readonly": response.readonly,
        "mounted": true
    }))
}

pub struct UnmountRequest {
    pub device: String,
}

pub fn unmount<F>(req: UnmountRequest, mut on_progress: F) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.device.trim().is_empty() {
        return Err(ServiceError::InvalidInput("device".to_string()));
    }
    
    on_progress(10, "Finding mount");
    
    let policy = default_mount_policy();
    let device = PathBuf::from(&req.device);
    
    let mounts = list_mounts_under(&policy)
        .map_err(|e| ServiceError::External(format!("list mounts: {}", e)))?;
    
    let mount_entry = mounts
        .iter()
        .find(|m| m.device == device)
        .ok_or_else(|| ServiceError::InvalidInput("device not mounted".to_string()))?;
    
    on_progress(30, "Unmounting");
    
    let policy_req = PolicyUnmountRequest {
        mountpoint: mount_entry.mountpoint.clone(),
        detach: false,
    };
    
    policy_unmount(&policy, policy_req)
        .map_err(|e| ServiceError::OperationFailed(format!("unmount failed: {}", e)))?;
    
    on_progress(100, "Unmounted");
    
    Ok(serde_json::json!({
        "device": req.device,
        "unmounted": true
    }))
}
