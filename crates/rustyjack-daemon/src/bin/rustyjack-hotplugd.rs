use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Local;
use rustyjack_client::{ClientConfig, DaemonClient};
use rustyjack_ipc::{RequestBody, ResponseBody, ResponseOk};
use tokio::time::sleep;

const DAEMON_SOCKET: &str = "/run/rustyjack/rustyjackd.sock";
const LOG_FILE: &str = "/var/log/rustyjack_wifi_hotplug.log";

struct Logger {
    path: PathBuf,
}

impl Logger {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn log(&self, message: impl AsRef<str>) {
        let line = format!(
            "[{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            message.as_ref()
        );
        eprintln!("{line}");
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn daemon_socket_present() -> bool {
    let path = Path::new(DAEMON_SOCKET);
    match fs::metadata(path) {
        Ok(meta) => meta.file_type().is_socket(),
        Err(_) => false,
    }
}

fn list_wireless_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name_os = entry.file_name();
            if let Ok(name) = name_os.into_string() {
                let wireless_path = entry.path().join("wireless");
                if wireless_path.exists() {
                    interfaces.push(name);
                }
            }
        }
    }
    interfaces.sort_unstable();
    interfaces
}

async fn hotplug_notify() -> Result<()> {
    if !daemon_socket_present() {
        return Err(anyhow!("Daemon socket not found: {DAEMON_SOCKET}"));
    }

    let config = ClientConfig {
        socket_path: PathBuf::from(DAEMON_SOCKET),
        client_name: "rustyjack-hotplugd".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        ..ClientConfig::default()
    };

    let mut client = DaemonClient::connect_with_config(config)
        .await
        .context("failed to connect to daemon socket")?;
    let response = client
        .request(RequestBody::HotplugNotify)
        .await
        .context("failed to send HotplugNotify request")?;

    match response {
        ResponseBody::Ok(ResponseOk::HotplugNotify(resp)) => {
            if resp.acknowledged {
                Ok(())
            } else {
                Err(anyhow!("daemon did not acknowledge HotplugNotify"))
            }
        }
        ResponseBody::Err(err) => Err(anyhow!("daemon error: {}", err)),
        other => Err(anyhow!("unexpected daemon response: {:?}", other)),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let logger = Logger::new(LOG_FILE);
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_else(|| "unknown".to_string());
    let device = args.next().unwrap_or_else(|| "unknown".to_string());

    logger.log("========================================");
    logger.log("Hotplug event triggered");
    logger.log(format!("ACTION: {action}"));
    logger.log(format!("DEVICE: {device}"));
    logger.log("========================================");

    match action.as_str() {
        "add" => {
            logger.log(format!("USB WiFi device inserted: {device}"));
            logger.log("Waiting 2s for device initialization...");
            sleep(Duration::from_secs(2)).await;

            let interfaces = list_wireless_interfaces();
            if interfaces.is_empty() {
                logger.log("Detected wireless interfaces: none");
            } else {
                logger.log(format!(
                    "Detected wireless interfaces: {}",
                    interfaces.join(" ")
                ));
            }

            logger.log("Waiting additional 2s for driver stabilization...");
            sleep(Duration::from_secs(2)).await;

            if let Err(err) = hotplug_notify().await {
                logger.log(format!("ERROR: Failed to send HotplugNotify to daemon: {err}"));
                return Err(err);
            }
            logger.log("SUCCESS: Sent HotplugNotify to daemon");
        }
        "remove" => {
            logger.log(format!("USB WiFi device removed: {device}"));
            if let Err(err) = hotplug_notify().await {
                logger.log(format!(
                    "WARNING: Failed to send HotplugNotify (removal) to daemon: {err}"
                ));
            } else {
                logger.log("SUCCESS: Sent HotplugNotify (removal) to daemon");
            }
        }
        "interface_add" => {
            logger.log(format!("Wireless interface added: {device}"));
            if let Err(err) = hotplug_notify().await {
                logger.log(format!(
                    "WARNING: Failed to send HotplugNotify (interface_add) to daemon: {err}"
                ));
            } else {
                logger.log("SUCCESS: Sent HotplugNotify (interface_add) to daemon");
            }
        }
        _ => {
            logger.log(format!("WARNING: Unknown action: {action}"));
            return Ok(());
        }
    }

    logger.log("Hotplug handler completed successfully");
    Ok(())
}
