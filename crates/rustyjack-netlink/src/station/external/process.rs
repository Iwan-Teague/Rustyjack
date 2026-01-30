use std::path::PathBuf;

use crate::error::{NetlinkError, Result};

#[cfg(feature = "station_external")]
pub fn is_wpa_running(interface: &str) -> Result<bool> {
    let _ = interface;
    Err(NetlinkError::Wpa(
        "station_external disabled (wpa_supplicant removed; use station_rust_wpa2)".to_string(),
    ))
}

#[cfg(not(feature = "station_external"))]
pub fn is_wpa_running(_interface: &str) -> Result<bool> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn start_wpa_supplicant(interface: &str, config_path: Option<&str>) -> Result<()> {
    let _ = (interface, config_path);
    Err(NetlinkError::Wpa(
        "station_external disabled (wpa_supplicant removed; use station_rust_wpa2)".to_string(),
    ))
}

#[cfg(not(feature = "station_external"))]
pub fn start_wpa_supplicant(_interface: &str, _config_path: Option<&str>) -> Result<()> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn stop_wpa_supplicant(interface: &str) -> Result<()> {
    let _ = interface;
    Err(NetlinkError::Wpa(
        "station_external disabled (wpa_supplicant removed; use station_rust_wpa2)".to_string(),
    ))
}

#[cfg(not(feature = "station_external"))]
pub fn stop_wpa_supplicant(_interface: &str) -> Result<()> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn ensure_wpa_control_socket(interface: &str, config_path: Option<&str>) -> Result<PathBuf> {
    let _ = (interface, config_path);
    Err(NetlinkError::Wpa(
        "station_external disabled (wpa_supplicant removed; use station_rust_wpa2)".to_string(),
    ))
}

#[cfg(not(feature = "station_external"))]
pub fn ensure_wpa_control_socket(_interface: &str, _config_path: Option<&str>) -> Result<PathBuf> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}
