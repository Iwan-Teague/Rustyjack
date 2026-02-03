use crate::cancel::CancelFlag;
use crate::services::error::ServiceError;

use rustyjack_ipc::{
    HotspotApSupport, HotspotClient, HotspotClientsResponse, HotspotDiagnosticsResponse,
    HotspotWarningsResponse, RfkillEntry,
};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use rustyjack_netlink::{
    allowed_ap_channels, peek_last_start_ap_error, take_last_ap_error, RfkillManager,
    WirelessManager,
};
#[cfg(target_os = "linux")]
use rustyjack_wireless::{hotspot_leases, read_regdom_info, take_last_hotspot_warning};

pub fn warnings() -> Result<HotspotWarningsResponse, ServiceError> {
    #[cfg(target_os = "linux")]
    {
        Ok(HotspotWarningsResponse {
            last_warning: take_last_hotspot_warning(),
            last_ap_error: take_last_ap_error(),
            last_start_error: peek_last_start_ap_error(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HotspotWarningsResponse {
            last_warning: None,
            last_ap_error: None,
            last_start_error: None,
        })
    }
}

pub fn diagnostics(ap_interface: &str) -> Result<HotspotDiagnosticsResponse, ServiceError> {
    if ap_interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }

    #[cfg(target_os = "linux")]
    {
        let regdom = read_regdom_info();
        let rfkill = match RfkillManager::new().list() {
            Ok(devices) => devices
                .into_iter()
                .map(|dev| RfkillEntry {
                    idx: dev.idx,
                    type_name: dev.type_.name().to_string(),
                    state: dev.state_string().to_string(),
                    name: dev.name.clone(),
                })
                .collect(),
            Err(err) => return Err(ServiceError::Netlink(format!("rfkill list error: {err}"))),
        };

        let ap_support = match WirelessManager::new() {
            Ok(mut mgr) => match mgr.get_phy_capabilities(ap_interface) {
                Ok(caps) => Some(HotspotApSupport {
                    supports_ap: caps.supports_ap,
                    supported_modes: caps
                        .supported_modes
                        .iter()
                        .map(|mode| mode.to_string().to_string())
                        .collect(),
                    supported_bands: caps.supported_bands.clone(),
                }),
                Err(_) => None,
            },
            Err(_) => None,
        };

        let allowed_channels = allowed_ap_channels(ap_interface).unwrap_or_default();

        Ok(HotspotDiagnosticsResponse {
            regdom_raw: regdom.raw,
            regdom_valid: regdom.valid,
            rfkill,
            ap_support,
            allowed_channels,
            last_start_error: peek_last_start_ap_error(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ap_interface;
        Ok(HotspotDiagnosticsResponse {
            regdom_raw: None,
            regdom_valid: false,
            rfkill: Vec::new(),
            ap_support: None,
            allowed_channels: Vec::new(),
            last_start_error: None,
        })
    }
}

pub fn clients() -> Result<HotspotClientsResponse, ServiceError> {
    #[cfg(target_os = "linux")]
    {
        let clients = hotspot_leases()
            .into_iter()
            .map(|lease| HotspotClient {
                mac: format_mac(&lease.mac),
                ip: lease.ip.to_string(),
                hostname: lease.hostname,
                lease_start: lease.lease_start,
            })
            .collect();
        Ok(HotspotClientsResponse { clients })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HotspotClientsResponse {
            clients: Vec::new(),
        })
    }
}

#[cfg(target_os = "linux")]
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub struct HotspotStartRequest {
    pub interface: String,
    pub upstream_interface: String,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub channel: Option<u8>,
}

pub fn start<F>(
    req: HotspotStartRequest,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<serde_json::Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }
    if req.ssid.trim().is_empty() {
        return Err(ServiceError::InvalidInput("ssid".to_string()));
    }
    // Allow empty upstream for offline hotspots.
    let has_upstream = !req.upstream_interface.trim().is_empty();

    if crate::cancel::check_cancel(cancel).is_err() {
        return Err(ServiceError::Cancelled);
    }

    on_progress(5, "Registering hotspot exception");

    if has_upstream {
        // Register hotspot exception FIRST, before any interface manipulation
        // This allows the isolation engine to permit both interfaces
        if let Err(e) = crate::system::set_hotspot_exception(
            req.interface.clone(),
            req.upstream_interface.clone(),
        ) {
            return Err(ServiceError::OperationFailed(format!(
                "Failed to set hotspot exception: {}",
                e
            )));
        }
    }

    if crate::cancel::check_cancel(cancel).is_err() {
        let _ = crate::system::clear_hotspot_exception();
        return Err(ServiceError::Cancelled);
    }

    on_progress(10, "Starting hotspot");

    #[cfg(target_os = "linux")]
    {
        use rustyjack_wireless::{start_hotspot, stop_hotspot};

        on_progress(50, "Configuring access point");

        // Create config for hotspot
        let config = rustyjack_wireless::HotspotConfig {
            ap_interface: req.interface.clone(),
            upstream_interface: req.upstream_interface.clone(),
            ssid: req.ssid.clone(),
            password: req.passphrase.clone().unwrap_or_default(),
            channel: req.channel.unwrap_or(6),
            restore_nm_on_stop: true,
        };

        match start_hotspot(config) {
            Ok(_) => {
                if crate::cancel::check_cancel(cancel).is_err() {
                    let _ = stop_hotspot();
                    let _ = crate::system::clear_hotspot_exception();
                    return Err(ServiceError::Cancelled);
                }

                let mut isolation_enforced = false;
                let mut isolation_error = None;

                if has_upstream {
                    on_progress(75, "Enforcing hotspot isolation");
                    let root = crate::system::resolve_root(None).map_err(|e| {
                        ServiceError::OperationFailed(format!("Failed to resolve root: {}", e))
                    })?;
                    let engine = crate::system::IsolationEngine::new(
                        Arc::new(crate::system::RealNetOps),
                        root,
                    );
                    match engine.enforce() {
                        Ok(_) => {
                            isolation_enforced = true;
                        }
                        Err(e) => {
                            isolation_error = Some(format!("Isolation enforcement failed: {}", e));
                        }
                    }
                } else {
                    on_progress(75, "Isolating hotspot interface");
                    match crate::system::apply_interface_isolation(&[req.interface.clone()]) {
                        Ok(()) => {
                            isolation_enforced = true;
                        }
                        Err(e) => {
                            isolation_error = Some(format!("Isolation enforcement failed: {}", e));
                        }
                    }
                }

                if crate::cancel::check_cancel(cancel).is_err() {
                    let _ = stop_hotspot();
                    let _ = crate::system::clear_hotspot_exception();
                    return Err(ServiceError::Cancelled);
                }

                on_progress(100, "Hotspot started");
                Ok(serde_json::json!({
                    "interface": req.interface,
                    "upstream": req.upstream_interface,
                    "ssid": req.ssid,
                    "started": true,
                    "isolation_enforced": isolation_enforced,
                    "isolation_error": isolation_error
                }))
            }
            Err(e) => {
                // Clear exception on failure
                if has_upstream {
                    let _ = crate::system::clear_hotspot_exception();
                }
                Err(ServiceError::OperationFailed(format!(
                    "Hotspot start failed: {}",
                    e
                )))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (req, on_progress);
        // Clear exception if we set it
        let _ = crate::system::clear_hotspot_exception();
        Err(ServiceError::External(
            "Hotspot not supported on this platform".to_string(),
        ))
    }
}

pub fn stop() -> Result<bool, ServiceError> {
    #[cfg(target_os = "linux")]
    {
        use rustyjack_wireless::stop_hotspot;

        // Clear hotspot exception FIRST to return to single-interface mode
        if let Err(e) = crate::system::clear_hotspot_exception() {
            // Log but don't fail - still try to stop hotspot
            eprintln!("Warning: Failed to clear hotspot exception: {}", e);
        }

        match stop_hotspot() {
            Ok(_) => Ok(true),
            Err(e) => Err(ServiceError::OperationFailed(format!(
                "Hotspot stop failed: {}",
                e
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(ServiceError::External(
            "Not supported on this platform".to_string(),
        ))
    }
}
