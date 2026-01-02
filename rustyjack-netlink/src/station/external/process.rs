use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::error::{NetlinkError, Result};
use crate::process::ProcessManager;

use super::ctrl::{control_socket_candidates, default_control_dir, find_control_socket, WpaManager};

#[cfg(feature = "station_external")]
pub fn is_wpa_running(interface: &str) -> Result<bool> {
    Ok(find_control_socket(interface).is_some())
}

#[cfg(not(feature = "station_external"))]
pub fn is_wpa_running(_interface: &str) -> Result<bool> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn start_wpa_supplicant(interface: &str, config_path: Option<&str>) -> Result<()> {
    use std::process::Command;

    if is_wpa_running(interface)? {
        return Ok(());
    }

    let control_dir = default_control_dir();
    if let Err(e) = fs::create_dir_all(&control_dir) {
        return Err(NetlinkError::Wpa(format!(
            "Failed to create wpa_supplicant control dir {:?}: {}",
            control_dir, e
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&control_dir, fs::Permissions::from_mode(0o755));
    }

    let conf_path = if let Some(path) = config_path {
        path.to_string()
    } else {
        // Generate minimal config
        let default_conf = format!("/tmp/wpa_supplicant_{}.conf", interface);
        fs::write(
            &default_conf,
            format!(
                "ctrl_interface={}\nupdate_config=1\n",
                control_dir.display()
            ),
        )
        .map_err(|e| NetlinkError::Wpa(format!("Failed to create wpa_supplicant config: {}", e)))?;
        default_conf
    };

    info!(
        "Starting wpa_supplicant for {} (ctrl_interface={})",
        interface,
        control_dir.display()
    );
    let output = Command::new("wpa_supplicant")
        .args(["-B", "-i", interface, "-c", &conf_path])
        .output()
        .map_err(|e| NetlinkError::Wpa(format!("Failed to start wpa_supplicant: {}", e)))?;

    if !output.status.success() {
        return Err(NetlinkError::Wpa(format!(
            "wpa_supplicant failed to start: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Wait for control socket to appear
    let start = Instant::now();
    while find_control_socket(interface).is_none() {
        if start.elapsed() > Duration::from_secs(5) {
            return Err(NetlinkError::Wpa(
                "wpa_supplicant control socket did not appear".to_string(),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(not(feature = "station_external"))]
pub fn start_wpa_supplicant(_interface: &str, _config_path: Option<&str>) -> Result<()> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn stop_wpa_supplicant(interface: &str) -> Result<()> {
    if !is_wpa_running(interface)? {
        return Ok(());
    }

    let mgr = WpaManager::new(interface)?;
    let _ = mgr.terminate();

    // Wait for socket to disappear
    let start = Instant::now();
    while find_control_socket(interface).is_some() {
        if start.elapsed() > Duration::from_secs(5) {
            // Force kill if terminate didn't work
            let pm = ProcessManager::new();
            let _ = pm.kill_pattern(&format!("wpa_supplicant.*{}", interface));
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(not(feature = "station_external"))]
pub fn stop_wpa_supplicant(_interface: &str) -> Result<()> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}

#[cfg(feature = "station_external")]
pub fn ensure_wpa_control_socket(interface: &str, config_path: Option<&str>) -> Result<PathBuf> {
    let status = control_socket_candidates(interface);
    if status.is_empty() {
        warn!(
            "wpa_supplicant control socket candidates missing for {}",
            interface
        );
    } else {
        let rendered = status
            .iter()
            .map(|path| format!("{}={}", path.display(), if path.exists() { "ok" } else { "missing" }))
            .collect::<Vec<_>>()
            .join(", ");
        info!(
            "wpa_supplicant control socket preflight for {}: {}",
            interface, rendered
        );
    }

    if let Some(path) = find_control_socket(interface) {
        return Ok(path);
    }

    warn!(
        "wpa_supplicant control socket missing for {}; attempting start",
        interface
    );
    let mut started = match start_wpa_supplicant(interface, config_path) {
        Ok(_) => true,
        Err(err) => {
            warn!(
                "wpa_supplicant start failed for {}: {}",
                interface, err
            );
            false
        }
    };

    if !started || find_control_socket(interface).is_none() {
        warn!(
            "wpa_supplicant control socket still missing for {}; restarting",
            interface
        );
        let pm = ProcessManager::new();
        let _ = pm.kill_pattern(&format!("wpa_supplicant.*{}", interface));
        std::thread::sleep(Duration::from_millis(200));
        start_wpa_supplicant(interface, config_path)?;
        started = true;
    }

    if started {
        if let Some(path) = find_control_socket(interface) {
            return Ok(path);
        }
    }

    Err(NetlinkError::Wpa(format!(
        "wpa_supplicant control socket still missing for {} after restart",
        interface
    )))
}

#[cfg(not(feature = "station_external"))]
pub fn ensure_wpa_control_socket(_interface: &str, _config_path: Option<&str>) -> Result<PathBuf> {
    Err(NetlinkError::Wpa(
        "station_external feature disabled".to_string(),
    ))
}
