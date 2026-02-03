use anyhow::{bail, Context, Result};

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use zbus::zvariant::OwnedObjectPath;

#[cfg(target_os = "linux")]
use zbus::{Connection, Proxy};

const ENABLE_UNITS: &[&str] = &[
    "rustyjackd.socket",
    "rustyjackd.service",
    "rustyjack-ui.service",
    "rustyjack-wpa_supplicant@wlan0.service",
    "rustyjack-portal.service",
];

const START_UNITS: &[&str] = &[
    "rustyjackd.service",
    "rustyjack-ui.service",
    "rustyjack-wpa_supplicant@wlan0.service",
    "rustyjack-portal.service",
    "rustyjackd.socket",
];

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    bail!("systemd install supported on Linux only");
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ensure_unit_files_present(ENABLE_UNITS)?;

    let conn = Connection::system().await.context("dbus connect")?;
    let proxy = Proxy::new(
        &conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .context("dbus proxy")?;

    let _: () = proxy.call("Reload", &()).await.context("reload units")?;

    let (_result, _changes): (bool, Vec<(String, String, String)>) = proxy
        .call("EnableUnitFiles", &(ENABLE_UNITS.to_vec(), false, true))
        .await
        .context("enable unit files")?;

    for unit in START_UNITS {
        start_unit_if_inactive(&conn, &proxy, unit)
            .await
            .with_context(|| format!("start {}", unit))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn start_unit_if_inactive(conn: &Connection, manager: &Proxy<'_>, unit: &str) -> Result<()> {
    if let Ok(state) = unit_active_state(conn, manager, unit).await {
        if state == "active" || state == "activating" {
            return Ok(());
        }
    }

    let (_job,): (OwnedObjectPath,) = manager
        .call("StartUnit", &(unit, "replace"))
        .await
        .with_context(|| format!("start unit {}", unit))?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn unit_active_state(conn: &Connection, manager: &Proxy<'_>, unit: &str) -> Result<String> {
    let (path,): (OwnedObjectPath,) = manager.call("GetUnit", &(unit)).await?;
    let unit_proxy = Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        path.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .await?;
    let state: String = unit_proxy.get_property("ActiveState").await?;
    Ok(state)
}

#[cfg(target_os = "linux")]
fn ensure_unit_files_present(units: &[&str]) -> Result<()> {
    let mut missing = Vec::new();
    for unit in units {
        if !unit_file_exists(unit) {
            missing.push(unit.to_string());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    bail!("missing systemd unit files: {}", missing.join(", "));
}

#[cfg(target_os = "linux")]
fn unit_file_exists(unit: &str) -> bool {
    let mut names = vec![unit.to_string()];
    if let Some(template) = template_from_instance(unit) {
        names.push(template);
    }

    let dirs = [
        Path::new("/etc/systemd/system"),
        Path::new("/usr/lib/systemd/system"),
        Path::new("/lib/systemd/system"),
    ];

    for name in names {
        for dir in dirs.iter() {
            if dir.join(&name).is_file() {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn template_from_instance(unit: &str) -> Option<String> {
    let at = unit.find('@')?;
    let suffix = unit.rfind(".service")?;
    if at >= suffix {
        return None;
    }
    Some(format!("{}@.service", &unit[..at]))
}
