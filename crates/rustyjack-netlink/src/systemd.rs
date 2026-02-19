//! Minimal systemd D-Bus helpers (no systemctl binary).

use crate::error::{NetlinkError, Result};

#[cfg(target_os = "linux")]
async fn call_unit_method(unit: &str, method: &str) -> Result<()> {
    if unit.trim().is_empty() {
        return Err(NetlinkError::InvalidInput(
            "service name cannot be empty".to_string(),
        ));
    }

    let conn = zbus::Connection::system()
        .await
        .map_err(|e| NetlinkError::OperationFailed(format!("systemd dbus connect: {}", e)))?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .map_err(|e| NetlinkError::OperationFailed(format!("systemd dbus proxy: {}", e)))?;

    proxy.call_method(method, &(unit, "replace")).await.map_err(|e| {
        NetlinkError::OperationFailed(format!("systemd {} {}: {}", method, unit, e))
    })?;

    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn restart_unit(unit: &str) -> Result<()> {
    call_unit_method(unit, "RestartUnit").await
}

#[cfg(target_os = "linux")]
pub async fn start_unit(unit: &str) -> Result<()> {
    call_unit_method(unit, "StartUnit").await
}

#[cfg(target_os = "linux")]
pub async fn stop_unit(unit: &str) -> Result<()> {
    call_unit_method(unit, "StopUnit").await
}

#[cfg(not(target_os = "linux"))]
pub async fn restart_unit(_unit: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "systemd D-Bus is supported on Linux only".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn start_unit(_unit: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "systemd D-Bus is supported on Linux only".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn stop_unit(_unit: &str) -> Result<()> {
    Err(NetlinkError::OperationNotSupported(
        "systemd D-Bus is supported on Linux only".to_string(),
    ))
}
