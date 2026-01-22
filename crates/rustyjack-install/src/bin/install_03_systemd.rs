use anyhow::{bail, Context, Result};

#[cfg(target_os = "linux")]
use zbus::Connection;

#[cfg(target_os = "linux")]
use zbus::Proxy;

#[cfg(target_os = "linux")]
use zbus::zvariant::OwnedObjectPath;

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    bail!("systemd install supported on Linux only");
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
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
        .call("EnableUnitFiles", &(vec!["rustyjackd.socket"], false, true))
        .await
        .context("enable rustyjackd.socket")?;

    let (_job,): (OwnedObjectPath,) = proxy
        .call("StartUnit", &("rustyjackd.socket", "replace"))
        .await
        .context("start rustyjackd.socket")?;

    Ok(())
}
