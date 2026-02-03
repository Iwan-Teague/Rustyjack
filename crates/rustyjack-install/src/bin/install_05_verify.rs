use anyhow::{bail, Context, Result};

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use zbus::names::BusName;

#[cfg(target_os = "linux")]
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

#[cfg(target_os = "linux")]
use zbus::{Connection, Proxy};

const REQUIRED_FILES: &[&str] = &[
    "/usr/local/bin/rustyjackd",
    "/usr/local/bin/rustyjack-ui",
    "/usr/local/bin/rustyjack-portal",
    "/etc/systemd/system/rustyjackd.socket",
    "/etc/systemd/system/rustyjackd.service",
    "/etc/systemd/system/rustyjack-ui.service",
    "/etc/systemd/system/rustyjack-portal.service",
    "/etc/systemd/system/rustyjack-wpa_supplicant@.service",
    "/etc/rustyjack/update_pubkey.ed25519",
    "/etc/rustyjack/wpa_supplicant.conf",
    "/var/lib/rustyjack",
];

const REQUIRED_GROUPS: &[&str] = &["rustyjack", "rustyjack-ui", "rustyjack-portal"];
const REQUIRED_USERS: &[&str] = &["rustyjack-ui", "rustyjack-portal"];

const REQUIRED_UNITS: &[&str] = &[
    "rustyjackd.socket",
    "rustyjackd.service",
    "rustyjack-ui.service",
    "rustyjack-wpa_supplicant@wlan0.service",
    "rustyjack-portal.service",
];

const WIFI_INTERFACE: &str = "wlan0";

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    bail!("verification supported on Linux only");
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut failures: Vec<String> = Vec::new();

    check_files(&mut failures);
    check_users_groups(&mut failures)?;

    let conn = Connection::system().await.context("dbus connect")?;
    check_systemd_units(&conn, &mut failures).await?;

    if wifi_backend_is_dbus() {
        check_wpa_dbus(&conn, &mut failures).await?;
    }

    if failures.is_empty() {
        println!("verification OK");
        return Ok(());
    }

    let mut message = String::from("verification failed:\n");
    for failure in failures {
        message.push_str("- ");
        message.push_str(&failure);
        message.push('\n');
    }
    bail!(message);
}

#[cfg(target_os = "linux")]
fn check_files(failures: &mut Vec<String>) {
    for path in REQUIRED_FILES {
        let path = Path::new(path);
        let exists = if path == Path::new("/var/lib/rustyjack") {
            path.is_dir()
        } else {
            path.is_file()
        };
        if !exists {
            failures.push(format!("missing required path {}", path.display()));
        }
    }
}

#[cfg(target_os = "linux")]
fn check_users_groups(failures: &mut Vec<String>) -> Result<()> {
    let users = read_passwd()?;
    let groups = read_group()?;

    for group in REQUIRED_GROUPS {
        if !groups.contains_key(*group) {
            failures.push(format!("missing group {}", group));
        }
    }

    for user in REQUIRED_USERS {
        if !users.contains_key(*user) {
            failures.push(format!("missing user {}", user));
        }
    }

    if let (Some(ui), Some(ui_group)) = (users.get("rustyjack-ui"), groups.get("rustyjack-ui")) {
        if ui.gid != ui_group.gid {
            failures.push("rustyjack-ui primary group mismatch".to_string());
        }
    }

    if let (Some(portal), Some(portal_group)) = (
        users.get("rustyjack-portal"),
        groups.get("rustyjack-portal"),
    ) {
        if portal.gid != portal_group.gid {
            failures.push("rustyjack-portal primary group mismatch".to_string());
        }
    }

    if let Some(rustyjack_group) = groups.get("rustyjack") {
        for member in ["rustyjack-ui", "rustyjack-portal"] {
            if !rustyjack_group.members.contains(member) {
                failures.push(format!("{} not in rustyjack supplementary group", member));
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn check_systemd_units(conn: &Connection, failures: &mut Vec<String>) -> Result<()> {
    let manager = Proxy::new(
        conn,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .context("systemd manager proxy")?;

    for unit in REQUIRED_UNITS {
        match manager.call("GetUnitFileState", &(*unit,)).await {
            Ok((state,)) => {
                if !is_enabled_state(&state) {
                    failures.push(format!("unit {} not enabled (state={})", unit, state));
                }
            }
            Err(err) => failures.push(format!("unit {} enablement check failed: {}", unit, err)),
        }

        match unit_active_state(conn, &manager, unit).await {
            Ok(state) => {
                if !is_active_state(&state) {
                    failures.push(format!("unit {} not active (state={})", unit, state));
                }
            }
            Err(err) => failures.push(format!("unit {} active check failed: {}", unit, err)),
        }
    }

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
fn is_enabled_state(state: &str) -> bool {
    matches!(state, "enabled" | "enabled-runtime")
}

#[cfg(target_os = "linux")]
fn is_active_state(state: &str) -> bool {
    matches!(state, "active" | "activating")
}

#[cfg(target_os = "linux")]
async fn check_wpa_dbus(conn: &Connection, failures: &mut Vec<String>) -> Result<()> {
    let dbus = zbus::fdo::DBusProxy::new(conn)
        .await
        .context("dbus proxy")?;
    let bus = BusName::try_from("fi.w1.wpa_supplicant1").context("wpa_supplicant bus name")?;
    let has_owner = dbus
        .name_has_owner(bus)
        .await
        .context("wpa_supplicant name check")?;
    if !has_owner {
        failures.push("wpa_supplicant D-Bus service not available".to_string());
        return Ok(());
    }

    let proxy = Proxy::new(
        conn,
        "fi.w1.wpa_supplicant1",
        "/fi/w1/wpa_supplicant1",
        "fi.w1.wpa_supplicant1",
    )
    .await
    .context("wpa_supplicant proxy")?;

    match proxy.call_method("GetInterface", &(WIFI_INTERFACE,)).await {
        Ok(_) => return Ok(()),
        Err(err) if is_interface_unknown(&err) => {
            let mut args: HashMap<String, OwnedValue> = HashMap::new();
            args.insert(
                "Ifname".to_string(),
                owned_value(WIFI_INTERFACE.to_string())?,
            );
            args.insert("Driver".to_string(), owned_value("nl80211".to_string())?);
            match proxy.call_method("CreateInterface", &(args)).await {
                Ok(_) => Ok(()),
                Err(err) if is_interface_exists(&err) => Ok(()),
                Err(err) => {
                    failures.push(format!("wpa_supplicant CreateInterface failed: {}", err));
                    Ok(())
                }
            }
        }
        Err(err) => {
            failures.push(format!("wpa_supplicant GetInterface failed: {}", err));
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn is_interface_unknown(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => name.as_str().ends_with("InterfaceUnknown"),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn is_interface_exists(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => name.as_str().ends_with("InterfaceExists"),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    Value<'static>: From<T>,
{
    OwnedValue::try_from(Value::from(value)).context("dbus value encode")
}

#[cfg(target_os = "linux")]
fn wifi_backend_is_dbus() -> bool {
    let candidates = [
        "/etc/systemd/system/rustyjackd.service",
        "/usr/lib/systemd/system/rustyjackd.service",
        "/lib/systemd/system/rustyjackd.service",
    ];
    for path in candidates {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            let line = line.trim();
            if !line.starts_with("Environment=") {
                continue;
            }
            if let Some(value) = line.strip_prefix("Environment=RUSTYJACK_WIFI_BACKEND=") {
                let value = value.trim_matches('"').trim_matches('`');
                return matches!(value, "dbus" | "wpa_dbus" | "supplicant_dbus");
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
struct UserEntry {
    gid: u32,
}

#[cfg(target_os = "linux")]
struct GroupEntry {
    gid: u32,
    members: HashSet<String>,
}

#[cfg(target_os = "linux")]
fn read_passwd() -> Result<HashMap<String, UserEntry>> {
    let contents = fs::read_to_string("/etc/passwd").context("read /etc/passwd")?;
    let mut users = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let name = parts[0].to_string();
        let gid = parts[3].parse::<u32>().unwrap_or(0);
        users.insert(name, UserEntry { gid });
    }
    Ok(users)
}

#[cfg(target_os = "linux")]
fn read_group() -> Result<HashMap<String, GroupEntry>> {
    let contents = fs::read_to_string("/etc/group").context("read /etc/group")?;
    let mut groups = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        let name = parts[0].to_string();
        let gid = parts[2].parse::<u32>().unwrap_or(0);
        let members = parts
            .get(3)
            .map(|raw| {
                raw.split(',')
                    .filter(|entry| !entry.trim().is_empty())
                    .map(|entry| entry.trim().to_string())
                    .collect::<HashSet<String>>()
            })
            .unwrap_or_default();
        groups.insert(name, GroupEntry { gid, members });
    }
    Ok(groups)
}
