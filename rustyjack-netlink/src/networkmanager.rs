use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use zbus::Connection;

/// NetworkManager device states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NmDeviceState {
    Unknown = 0,
    Unmanaged = 10,
    Unavailable = 20,
    Disconnected = 30,
    Prepare = 40,
    Config = 50,
    NeedAuth = 60,
    IpConfig = 70,
    IpCheck = 80,
    Secondaries = 90,
    Activated = 100,
    Deactivating = 110,
    Failed = 120,
}

impl NmDeviceState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Unknown,
            10 => Self::Unmanaged,
            20 => Self::Unavailable,
            30 => Self::Disconnected,
            40 => Self::Prepare,
            50 => Self::Config,
            60 => Self::NeedAuth,
            70 => Self::IpConfig,
            80 => Self::IpCheck,
            90 => Self::Secondaries,
            100 => Self::Activated,
            110 => Self::Deactivating,
            120 => Self::Failed,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Unmanaged => "unmanaged",
            Self::Unavailable => "unavailable",
            Self::Disconnected => "disconnected",
            Self::Prepare => "preparing",
            Self::Config => "configuring",
            Self::NeedAuth => "need-auth",
            Self::IpConfig => "ip-config",
            Self::IpCheck => "ip-check",
            Self::Secondaries => "secondaries",
            Self::Activated => "activated",
            Self::Deactivating => "deactivating",
            Self::Failed => "failed",
        }
    }
}

/// Information about a WiFi access point
#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub signal_strength: u8,
    pub frequency: u32,
    pub max_bitrate: u32,
    pub security_flags: Vec<String>,
}

/// NetworkManager client for managing network connections
pub struct NetworkManagerClient {
    connection: Connection,
}

impl NetworkManagerClient {
    /// Create a new NetworkManager client
    pub async fn new() -> Result<Self> {
        let connection = Connection::system()
            .await
            .context("Failed to connect to system D-Bus - is D-Bus running?")?;

        Ok(Self { connection })
    }

    /// Check if NetworkManager is available and running
    pub async fn is_available(&self) -> bool {
        let proxy = match zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        {
            Ok(p) => p,
            Err(_) => return false,
        };

        proxy.get_property::<String>("Version").await.is_ok()
    }

    /// Get NetworkManager version
    pub async fn version(&self) -> Result<String> {
        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .context("Failed to create NetworkManager proxy - is NetworkManager running?")?;

        proxy
            .get_property::<String>("Version")
            .await
            .context("Failed to get NetworkManager version - NetworkManager may not be responding")
    }

    /// Get device object path by interface name
    async fn get_device_path(&self, interface: &str) -> Result<zbus::zvariant::OwnedObjectPath> {
        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .context("Failed to create NetworkManager proxy")?;

        let device_path: zbus::zvariant::OwnedObjectPath = proxy
            .call_method("GetDeviceByIpIface", &(interface))
            .await
            .with_context(|| format!("Failed to get device path for interface '{}' - interface may not exist or may not be managed by NetworkManager", interface))?
            .body()
            .deserialize()
            .context("Failed to parse device path from NetworkManager response")?;

        Ok(device_path)
    }

    /// Set device managed state
    pub async fn set_device_managed(&self, interface: &str, managed: bool) -> Result<()> {
        let device_path = self.get_device_path(interface).await?;

        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path.clone(),
            "org.freedesktop.NetworkManager.Device",
        )
        .await
        .context("Failed to create device proxy")?;

        proxy
            .set_property("Managed", managed)
            .await
            .with_context(|| {
                format!(
                    "Failed to set interface '{}' to {} by NetworkManager - permission denied or device in invalid state",
                    interface,
                    if managed { "managed" } else { "unmanaged" }
                )
            })?;

        tracing::info!(
            "Interface '{}' set to {} by NetworkManager",
            interface,
            if managed { "managed" } else { "unmanaged" }
        );
        Ok(())
    }

    /// Get device state
    pub async fn get_device_state(&self, interface: &str) -> Result<NmDeviceState> {
        let device_path = self.get_device_path(interface).await?;

        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path,
            "org.freedesktop.NetworkManager.Device",
        )
        .await
        .context("Failed to create device proxy")?;

        let state_val: u32 = proxy.get_property("State").await.with_context(|| {
            format!(
                "Failed to get state for interface '{}' - NetworkManager may not be responding",
                interface
            )
        })?;

        Ok(NmDeviceState::from_u32(state_val))
    }

    /// Disconnect a device
    pub async fn disconnect_device(&self, interface: &str) -> Result<()> {
        let device_path = self.get_device_path(interface).await?;

        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path.clone(),
            "org.freedesktop.NetworkManager.Device",
        )
        .await
        .context("Failed to create device proxy")?;

        proxy
            .call_method("Disconnect", &())
            .await
            .with_context(|| format!("Failed to disconnect interface '{}' - device may already be disconnected or in invalid state", interface))?;

        tracing::info!("Interface '{}' disconnected via NetworkManager", interface);
        Ok(())
    }

    /// Reconnect a device (disconnect and trigger connection)
    pub async fn reconnect_device(&self, interface: &str) -> Result<()> {
        // First disconnect
        if let Err(e) = self.disconnect_device(interface).await {
            tracing::warn!(
                "Disconnect before reconnect failed (may already be disconnected): {}",
                e
            );
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Get device path
        let device_path = self.get_device_path(interface).await?;

        // Get the wireless device to find available connections
        let wireless_proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path.clone(),
            "org.freedesktop.NetworkManager.Device.Wireless",
        )
        .await
        .context("Failed to create wireless device proxy - interface may not be a WiFi device")?;

        // Get access points
        let ap_paths: Vec<zbus::zvariant::OwnedObjectPath> = wireless_proxy
            .call_method("GetAccessPoints", &())
            .await
            .context("Failed to get access points - interface may not support WiFi scanning")?
            .body()
            .deserialize()
            .context("Failed to parse access points from NetworkManager response")?;

        if ap_paths.is_empty() {
            bail!(
                "No access points available for reconnection on interface '{}'",
                interface
            );
        }

        // Use the first available AP
        let ap_path = &ap_paths[0];

        // Get NetworkManager main proxy
        let nm_proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .context("Failed to create NetworkManager proxy")?;

        // Activate connection (use "/" for no specific connection, let NM auto-connect)
        nm_proxy
            .call_method(
                "ActivateConnection",
                &(
                    zbus::zvariant::ObjectPath::from_str_unchecked("/"),
                    device_path.as_ref(),
                    ap_path.as_ref(),
                ),
            )
            .await
            .with_context(|| format!("Failed to activate connection on interface '{}' - no saved connection profile or authentication required", interface))?;

        tracing::info!(
            "Interface '{}' reconnection initiated via NetworkManager",
            interface
        );
        Ok(())
    }

    /// Connect to a WiFi network
    pub async fn connect_wifi(
        &self,
        interface: &str,
        ssid: &str,
        password: Option<&str>,
        timeout_secs: u32,
    ) -> Result<()> {
        let device_path = self.get_device_path(interface).await?;

        // Get the wireless device proxy
        let wireless_proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path.clone(),
            "org.freedesktop.NetworkManager.Device.Wireless",
        )
        .await
        .context("Failed to create wireless device proxy - interface may not be a WiFi device")?;

        // Find the access point with matching SSID
        let ap_paths: Vec<zbus::zvariant::OwnedObjectPath> = wireless_proxy
            .call_method("GetAccessPoints", &())
            .await
            .context("Failed to get access points - interface may not support WiFi scanning")?
            .body()
            .deserialize()
            .context("Failed to parse access points")?;

        let mut target_ap_path = None;
        for ap_path in ap_paths {
            let ap_proxy = zbus::Proxy::new(
                &self.connection,
                "org.freedesktop.NetworkManager",
                ap_path.clone(),
                "org.freedesktop.NetworkManager.AccessPoint",
            )
            .await?;

            let ap_ssid: Vec<u8> = ap_proxy.get_property("Ssid").await?;
            let ap_ssid_str = String::from_utf8_lossy(&ap_ssid);

            if ap_ssid_str == ssid {
                target_ap_path = Some(ap_path);
                break;
            }
        }

        let ap_path = target_ap_path.with_context(|| {
            format!(
                "Access point with SSID '{}' not found - network may be out of range or hidden",
                ssid
            )
        })?;

        // Build connection settings
        let mut connection_settings: HashMap<String, HashMap<String, zbus::zvariant::Value>> =
            HashMap::new();

        // Connection settings
        let mut conn_map = HashMap::new();
        conn_map.insert(
            "type".to_string(),
            zbus::zvariant::Value::new("802-11-wireless"),
        );
        conn_map.insert("id".to_string(), zbus::zvariant::Value::new(ssid));
        conn_map.insert(
            "uuid".to_string(),
            zbus::zvariant::Value::new(uuid::Uuid::new_v4().to_string()),
        );
        connection_settings.insert("connection".to_string(), conn_map);

        // Wireless settings
        let mut wireless_map = HashMap::new();
        wireless_map.insert(
            "ssid".to_string(),
            zbus::zvariant::Value::new(ssid.as_bytes()),
        );
        wireless_map.insert(
            "mode".to_string(),
            zbus::zvariant::Value::new("infrastructure"),
        );
        connection_settings.insert("802-11-wireless".to_string(), wireless_map);

        // Security settings if password provided
        if let Some(pass) = password {
            if !pass.is_empty() {
                let mut security_map = HashMap::new();
                security_map.insert(
                    "key-mgmt".to_string(),
                    zbus::zvariant::Value::new("wpa-psk"),
                );
                security_map.insert("psk".to_string(), zbus::zvariant::Value::new(pass));
                connection_settings.insert("802-11-wireless-security".to_string(), security_map);
            }
        }

        // IPv4 settings (auto DHCP)
        let mut ipv4_map = HashMap::new();
        ipv4_map.insert("method".to_string(), zbus::zvariant::Value::new("auto"));
        connection_settings.insert("ipv4".to_string(), ipv4_map);

        // IPv6 settings (auto)
        let mut ipv6_map = HashMap::new();
        ipv6_map.insert("method".to_string(), zbus::zvariant::Value::new("auto"));
        connection_settings.insert("ipv6".to_string(), ipv6_map);

        // Get NetworkManager main proxy
        let nm_proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .await
        .context("Failed to create NetworkManager proxy")?;

        // Add and activate connection
        let result: Result<
            (
                zbus::zvariant::OwnedObjectPath,
                zbus::zvariant::OwnedObjectPath,
            ),
            zbus::Error,
        > = nm_proxy
            .call_method(
                "AddAndActivateConnection",
                &(connection_settings, device_path.as_ref(), ap_path.as_ref()),
            )
            .await
            .and_then(|r| r.body().deserialize());

        match result {
            Ok((conn_path, _active_conn_path)) => {
                tracing::info!(
                    "Connection to '{}' on interface '{}' initiated (connection: {})",
                    ssid,
                    interface,
                    conn_path
                );
            }
            Err(e) => {
                bail!(
                    "Failed to connect to '{}' on interface '{}': {} - check password or network security settings",
                    ssid,
                    interface,
                    e
                );
            }
        }

        // Wait for connection with timeout
        let start = tokio::time::Instant::now();
        let timeout = tokio::time::Duration::from_secs(timeout_secs as u64);

        loop {
            if start.elapsed() > timeout {
                bail!(
                    "Timeout waiting for connection to '{}' on interface '{}' after {} seconds - check signal strength and authentication",
                    ssid,
                    interface,
                    timeout_secs
                );
            }

            let state = self.get_device_state(interface).await?;
            match state {
                NmDeviceState::Activated => {
                    tracing::info!(
                        "Successfully connected to '{}' on interface '{}'",
                        ssid,
                        interface
                    );
                    return Ok(());
                }
                NmDeviceState::Failed => {
                    bail!(
                        "Connection to '{}' on interface '{}' failed - check password, security settings, or network availability",
                        ssid,
                        interface
                    );
                }
                NmDeviceState::NeedAuth => {
                    bail!(
                        "Connection to '{}' on interface '{}' requires authentication - check password",
                        ssid,
                        interface
                    );
                }
                _ => {
                    tracing::debug!(
                        "Waiting for connection (current state: {})...",
                        state.as_str()
                    );
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }

    /// List available WiFi networks
    pub async fn list_wifi_networks(&self, interface: &str) -> Result<Vec<AccessPoint>> {
        let device_path = self.get_device_path(interface).await?;

        let wireless_proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.NetworkManager",
            device_path,
            "org.freedesktop.NetworkManager.Device.Wireless",
        )
        .await
        .context("Failed to create wireless device proxy - interface may not be a WiFi device")?;

        // Request scan
        let mut scan_options: HashMap<String, zbus::zvariant::Value> = HashMap::new();
        scan_options.insert(
            "ssids".to_string(),
            zbus::zvariant::Value::new(Vec::<Vec<u8>>::new()),
        );

        let _: Result<(), _> = wireless_proxy
            .call_method("RequestScan", &(scan_options,))
            .await
            .and_then(|r| r.body().deserialize());

        // Wait a bit for scan to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Get access points
        let ap_paths: Vec<zbus::zvariant::OwnedObjectPath> = wireless_proxy
            .call_method("GetAccessPoints", &())
            .await
            .context("Failed to get access points")?
            .body()
            .deserialize()
            .context("Failed to parse access points")?;

        let mut access_points = Vec::new();
        for ap_path in ap_paths {
            let ap_proxy = zbus::Proxy::new(
                &self.connection,
                "org.freedesktop.NetworkManager",
                ap_path,
                "org.freedesktop.NetworkManager.AccessPoint",
            )
            .await?;

            let ssid_bytes: Vec<u8> = ap_proxy.get_property("Ssid").await.unwrap_or_default();
            let ssid = String::from_utf8_lossy(&ssid_bytes).to_string();

            if ssid.is_empty() {
                continue; // Skip hidden/empty SSIDs
            }

            let hw_address: String = ap_proxy.get_property("HwAddress").await.unwrap_or_default();
            let strength: u8 = ap_proxy.get_property("Strength").await.unwrap_or(0);
            let frequency: u32 = ap_proxy.get_property("Frequency").await.unwrap_or(0);
            let max_bitrate: u32 = ap_proxy.get_property("MaxBitrate").await.unwrap_or(0);

            let wpa_flags: u32 = ap_proxy.get_property("WpaFlags").await.unwrap_or(0);
            let rsn_flags: u32 = ap_proxy.get_property("RsnFlags").await.unwrap_or(0);

            let mut security = Vec::new();
            if wpa_flags != 0 {
                security.push("WPA".to_string());
            }
            if rsn_flags != 0 {
                security.push("WPA2/WPA3".to_string());
            }
            if security.is_empty() {
                security.push("Open".to_string());
            }

            access_points.push(AccessPoint {
                ssid,
                bssid: hw_address,
                signal_strength: strength,
                frequency,
                max_bitrate,
                security_flags: security,
            });
        }

        Ok(access_points)
    }
}

/// Set device managed state (convenience function)
pub async fn set_device_managed(interface: &str, managed: bool) -> Result<()> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client - is D-Bus available?")?;
    client.set_device_managed(interface, managed).await
}

/// Get device state (convenience function)
pub async fn get_device_state(interface: &str) -> Result<NmDeviceState> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client")?;
    client.get_device_state(interface).await
}

/// Disconnect device (convenience function)
pub async fn disconnect_device(interface: &str) -> Result<()> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client")?;
    client.disconnect_device(interface).await
}

/// Reconnect device (convenience function)
pub async fn reconnect_device(interface: &str) -> Result<()> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client")?;
    client.reconnect_device(interface).await
}

/// Connect to WiFi network (convenience function)
pub async fn connect_wifi(
    interface: &str,
    ssid: &str,
    password: Option<&str>,
    timeout_secs: u32,
) -> Result<()> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client")?;
    client
        .connect_wifi(interface, ssid, password, timeout_secs)
        .await
}

/// List WiFi networks (convenience function)
pub async fn list_wifi_networks(interface: &str) -> Result<Vec<AccessPoint>> {
    let client = NetworkManagerClient::new()
        .await
        .context("Failed to create NetworkManager client")?;
    client.list_wifi_networks(interface).await
}
