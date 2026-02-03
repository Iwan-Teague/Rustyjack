use crate::cancel::CancelFlag;
use crate::services::error::ServiceError;
use crate::wireless_native::{check_capabilities, WirelessCapabilities};
use serde_json::Value;

pub fn capabilities(interface: &str) -> Result<WirelessCapabilities, ServiceError> {
    if interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }
    Ok(check_capabilities(interface))
}

pub fn list_interfaces() -> Result<Vec<String>, ServiceError> {
    use std::fs;
    let sys_class = std::path::Path::new("/sys/class/net");
    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir(sys_class) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name != "lo" {
                    let wireless_path = entry.path().join("wireless");
                    if wireless_path.exists() {
                        interfaces.push(name);
                    }
                }
            }
        }
    }

    Ok(interfaces)
}

pub struct WifiScanRequest {
    pub interface: String,
    pub timeout_ms: u64,
}

pub struct WifiConnectRequest {
    pub interface: String,
    pub ssid: String,
    pub psk: Option<String>,
    pub timeout_ms: u64,
}

pub fn scan<F>(
    req: WifiScanRequest,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }

    if crate::cancel::check_cancel(cancel).is_err() {
        return Err(ServiceError::Cancelled);
    }

    on_progress(10, "Starting scan");

    on_progress(50, "Scanning networks");
    let networks = crate::system::scan_wifi_networks_with_timeout_cancel(
        &req.interface,
        std::time::Duration::from_millis(req.timeout_ms),
        cancel,
    )
    .map_err(|e| {
        if crate::operations::is_cancelled_error(&e) {
            ServiceError::Cancelled
        } else {
            ServiceError::OperationFailed(format!("WiFi scan failed: {}", e))
        }
    })?;

    if crate::cancel::check_cancel(cancel).is_err() {
        return Err(ServiceError::Cancelled);
    }

    on_progress(100, "Scan complete");
    let count = networks.len();
    Ok(serde_json::json!({
        "interface": req.interface,
        "count": count,
        "networks": networks
    }))
}

pub fn connect<F>(
    req: WifiConnectRequest,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }
    if req.ssid.trim().is_empty() {
        return Err(ServiceError::InvalidInput("ssid".to_string()));
    }

    if crate::cancel::check_cancel(cancel).is_err() {
        return Err(ServiceError::Cancelled);
    }

    on_progress(10, "Connecting to network");

    crate::system::connect_wifi_network_with_cancel(
        &req.interface,
        &req.ssid,
        req.psk.as_deref(),
        cancel,
    )
    .map_err(|e| {
        if crate::operations::is_cancelled_error(&e) {
            ServiceError::Cancelled
        } else {
            ServiceError::OperationFailed(format!("WiFi connect failed: {}", e))
        }
    })?;

    on_progress(100, "Connected");
    Ok(serde_json::json!({
        "interface": req.interface,
        "ssid": req.ssid,
        "connected": true
    }))
}

pub fn disconnect(interface: &str) -> Result<bool, ServiceError> {
    if interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }

    crate::system::disconnect_wifi_interface(Some(interface.to_string()))
        .map_err(|e| ServiceError::OperationFailed(format!("WiFi disconnect failed: {}", e)))?;
    Ok(true)
}
