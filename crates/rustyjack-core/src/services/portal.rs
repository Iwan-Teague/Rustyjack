use crate::cancel::CancelFlag;
use crate::services::error::ServiceError;
use serde_json::Value;
use std::sync::Mutex;

static PORTAL_STATE: Mutex<Option<PortalState>> = Mutex::new(None);

#[derive(Clone)]
struct PortalState {
    interface: String,
    port: u16,
}

pub struct PortalStartRequest {
    pub interface: String,
    pub port: u16,
}

pub fn start<F>(
    req: PortalStartRequest,
    cancel: Option<&CancelFlag>,
    mut on_progress: F,
) -> Result<Value, ServiceError>
where
    F: FnMut(u8, &str),
{
    if req.interface.trim().is_empty() {
        return Err(ServiceError::InvalidInput("interface".to_string()));
    }
    if req.port == 0 {
        return Err(ServiceError::InvalidInput("port".to_string()));
    }

    if crate::cancel::check_cancel(cancel).is_err() {
        return Err(ServiceError::Cancelled);
    }

    on_progress(10, "Starting captive portal");

    #[cfg(target_os = "linux")]
    {
        use rustyjack_portal;
        use std::net::Ipv4Addr;
        use std::path::PathBuf;
        use std::time::Duration;

        on_progress(50, "Configuring portal");

        let listen_ip = match crate::system::detect_interface(Some(req.interface.clone())) {
            Ok(info) => info.address,
            Err(_) => Ipv4Addr::new(0, 0, 0, 0),
        };

        let config = rustyjack_portal::PortalConfig {
            interface: req.interface.clone(),
            listen_ip,
            listen_port: req.port,
            site_dir: PathBuf::from("/var/lib/rustyjack/portal/site"),
            capture_dir: PathBuf::from("/var/lib/rustyjack/loot/Portal"),
            max_body_bytes: 1024 * 1024, // 1MB
            max_concurrency: 100,
            request_timeout: Duration::from_secs(30),
            dnat_mode: true,
            bind_to_device: true,
        };

        match rustyjack_portal::start_portal(config) {
            Ok(_) => {
                if crate::cancel::check_cancel(cancel).is_err() {
                    let _ = rustyjack_portal::stop_portal();
                    let mut state = PORTAL_STATE.lock().unwrap();
                    *state = None;
                    return Err(ServiceError::Cancelled);
                }

                let mut state = PORTAL_STATE.lock().unwrap();
                *state = Some(PortalState {
                    interface: req.interface.clone(),
                    port: req.port,
                });

                on_progress(100, "Portal started");
                Ok(serde_json::json!({
                    "interface": req.interface,
                    "port": req.port,
                    "listen_ip": listen_ip.to_string(),
                    "started": true
                }))
            }
            Err(e) => Err(ServiceError::OperationFailed(format!(
                "Portal start failed: {}",
                e
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (req, on_progress);
        Err(ServiceError::External(
            "Portal not supported on this platform".to_string(),
        ))
    }
}

pub fn stop() -> Result<bool, ServiceError> {
    #[cfg(target_os = "linux")]
    {
        use rustyjack_portal;

        match rustyjack_portal::stop_portal() {
            Ok(_) => {
                let mut state = PORTAL_STATE.lock().unwrap();
                *state = None;
                Ok(true)
            }
            Err(e) => Err(ServiceError::OperationFailed(format!(
                "Portal stop failed: {}",
                e
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(ServiceError::External(
            "Portal not supported on this platform".to_string(),
        ))
    }
}

pub fn status() -> Result<Value, ServiceError> {
    let state = PORTAL_STATE.lock().unwrap();

    if let Some(ref portal) = *state {
        Ok(serde_json::json!({
            "running": true,
            "interface": portal.interface,
            "port": portal.port
        }))
    } else {
        Ok(serde_json::json!({
            "running": false,
            "interface": null,
            "port": null
        }))
    }
}
