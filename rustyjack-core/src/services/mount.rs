use std::process::Command;

use serde_json::Value;

use crate::services::error::ServiceError;

#[derive(Debug, Clone)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub size: String,
    pub model: String,
    pub transport: String,
    pub removable: bool,
}

pub fn list_block_devices() -> Result<Vec<BlockDeviceInfo>, ServiceError> {
    let output = Command::new("lsblk")
        .args(["-J", "-p", "-o", "NAME,TYPE,RM,SIZE,MODEL,TRAN"])
        .output()
        .map_err(ServiceError::Io)?;
    if !output.status.success() {
        return Err(ServiceError::External(format!(
            "lsblk failed with status {:?}",
            output.status.code()
        )));
    }

    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| ServiceError::External(format!("parsing lsblk JSON output: {err}")))?;
    let blockdevices = parsed
        .get("blockdevices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ServiceError::External("lsblk JSON missing blockdevices".to_string()))?;

    let mut devices = Vec::new();
    for dev in blockdevices {
        let dev_type = dev.get("type").and_then(Value::as_str).unwrap_or("");
        if dev_type != "disk" {
            continue;
        }
        let name = dev.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }

        if name.starts_with("/dev/mmcblk")
            || name.starts_with("/dev/loop")
            || name.starts_with("/dev/ram")
        {
            continue;
        }

        let removable = match dev.get("rm") {
            Some(Value::Bool(v)) => *v,
            Some(Value::Number(v)) => v.as_u64().unwrap_or(0) != 0,
            Some(Value::String(v)) => v == "1" || v.eq_ignore_ascii_case("true"),
            _ => false,
        };
        let size = dev
            .get("size")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let model = dev
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let transport = dev
            .get("tran")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        devices.push(BlockDeviceInfo {
            name: name.to_string(),
            size,
            model,
            transport,
            removable,
        });
    }

    Ok(devices)
}
