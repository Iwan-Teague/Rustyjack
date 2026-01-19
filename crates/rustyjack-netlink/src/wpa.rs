#[cfg(feature = "station_external")]
pub use crate::station::external::ctrl::{
    wpa_control_socket_status, BssInfo, WpaManager, WpaNetworkConfig, WpaState, WpaStatus,
};
#[cfg(feature = "station_external")]
pub use crate::station::external::process::{
    ensure_wpa_control_socket, is_wpa_running, start_wpa_supplicant, stop_wpa_supplicant,
};

#[cfg(not(feature = "station_external"))]
/// WPA supplicant status (Rust backend).
#[derive(Debug, Clone, PartialEq)]
pub struct WpaStatus {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub freq: Option<u32>,
    pub mode: Option<String>,
    pub pairwise_cipher: Option<String>,
    pub group_cipher: Option<String>,
    pub key_mgmt: Option<String>,
    pub wpa_state: WpaState,
    pub ip_address: Option<String>,
    pub address: Option<String>,
}

#[cfg(not(feature = "station_external"))]
/// WPA connection state (Rust backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpaState {
    Disconnected,
    Scanning,
    Authenticating,
    Associating,
    Associated,
    FourWayHandshake,
    GroupHandshake,
    Completed,
    Unknown,
}

#[cfg(not(feature = "station_external"))]
impl std::fmt::Display for WpaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WpaState::Disconnected => write!(f, "DISCONNECTED"),
            WpaState::Scanning => write!(f, "SCANNING"),
            WpaState::Authenticating => write!(f, "AUTHENTICATING"),
            WpaState::Associating => write!(f, "ASSOCIATING"),
            WpaState::Associated => write!(f, "ASSOCIATED"),
            WpaState::FourWayHandshake => write!(f, "4WAY_HANDSHAKE"),
            WpaState::GroupHandshake => write!(f, "GROUP_HANDSHAKE"),
            WpaState::Completed => write!(f, "COMPLETED"),
            WpaState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[cfg(not(feature = "station_external"))]
impl WpaState {
    pub(crate) fn from_str(value: &str) -> Self {
        match value.to_uppercase().as_str() {
            "DISCONNECTED" | "INACTIVE" => WpaState::Disconnected,
            "SCANNING" => WpaState::Scanning,
            "AUTHENTICATING" => WpaState::Authenticating,
            "ASSOCIATING" => WpaState::Associating,
            "ASSOCIATED" => WpaState::Associated,
            "4WAY_HANDSHAKE" => WpaState::FourWayHandshake,
            "GROUP_HANDSHAKE" => WpaState::GroupHandshake,
            "COMPLETED" => WpaState::Completed,
            _ => WpaState::Unknown,
        }
    }
}

#[cfg(not(feature = "station_external"))]
/// Network configuration for WPA (Rust backend).
#[derive(Debug, Clone)]
pub struct WpaNetworkConfig {
    pub ssid: String,
    pub psk: Option<String>,
    pub key_mgmt: String,
    pub scan_ssid: bool,
    pub priority: i32,
    pub bssid: Option<String>,
    pub proto: Option<String>,
    pub pairwise: Option<String>,
    pub group: Option<String>,
}

#[cfg(not(feature = "station_external"))]
impl Default for WpaNetworkConfig {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            psk: None,
            key_mgmt: "WPA-PSK".to_string(),
            scan_ssid: false,
            priority: 0,
            bssid: None,
            proto: None,
            pairwise: None,
            group: None,
        }
    }
}

#[cfg(not(feature = "station_external"))]
/// BSS details (Rust backend).
#[derive(Debug, Clone)]
pub struct BssInfo {
    pub bssid: Option<String>,
    pub freq: Option<u32>,
    pub level: Option<i32>,
    pub flags: Option<String>,
    pub ssid: Option<String>,
    pub ie: Option<Vec<u8>>,
    pub beacon_ie: Option<Vec<u8>>,
}
