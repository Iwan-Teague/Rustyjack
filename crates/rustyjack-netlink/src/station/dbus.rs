use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use tracing::{debug, info, warn};
use zbus::names::BusName;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::error::{NetlinkError, Result};
use crate::station::backend::{ScanOutcome, StationBackend};
use crate::supplicant::{
    build_network_config, score_candidate, security_from_bss, BssCandidate, ScanEntry,
    StationConfig, StationOutcome, StationState,
};
use crate::wpa::{BssInfo, WpaState, WpaStatus};

const SUPPLICANT_BUS: &str = "fi.w1.wpa_supplicant1";
const SUPPLICANT_PATH: &str = "/fi/w1/wpa_supplicant1";
const SUPPLICANT_IFACE: &str = "fi.w1.wpa_supplicant1";
const IFACE_IFACE: &str = "fi.w1.wpa_supplicant1.Interface";
const BSS_IFACE: &str = "fi.w1.wpa_supplicant1.BSS";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";

struct DbusState {
    interface_path: Option<OwnedObjectPath>,
    network_path: Option<OwnedObjectPath>,
    last_status: WpaStatus,
}

pub struct WpaSupplicantDbusBackend {
    interface: String,
    runtime: Arc<tokio::runtime::Runtime>,
    state: Arc<Mutex<DbusState>>,
}

impl WpaSupplicantDbusBackend {
    pub fn new(interface: &str) -> Result<Self> {
        if interface.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "Interface cannot be empty".to_string(),
            ));
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| NetlinkError::Runtime {
                context: "wpa_supplicant dbus runtime".to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self {
            interface: interface.to_string(),
            runtime: Arc::new(runtime),
            state: Arc::new(Mutex::new(DbusState {
                interface_path: None,
                network_path: None,
                last_status: WpaStatus {
                    ssid: None,
                    bssid: None,
                    freq: None,
                    mode: Some("station".to_string()),
                    pairwise_cipher: None,
                    group_cipher: None,
                    key_mgmt: None,
                    wpa_state: WpaState::Disconnected,
                    ip_address: None,
                    address: None,
                },
            })),
        })
    }

    fn block_on<F>(&self, fut: F) -> Result<F::Output>
    where
        F: std::future::Future,
    {
        Ok(self.runtime.block_on(fut))
    }

    async fn system_bus(&self) -> Result<Connection> {
        Connection::system()
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("dbus system connect: {}", e)))
    }

    async fn ensure_supplicant(conn: &Connection) -> Result<()> {
        let proxy = zbus::fdo::DBusProxy::new(conn)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("dbus proxy: {}", e)))?;
        let bus = BusName::try_from(SUPPLICANT_BUS)
            .map_err(|e| NetlinkError::OperationFailed(format!("dbus bus name: {}", e)))?;
        let has_owner = proxy
            .name_has_owner(bus)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("dbus name check: {}", e)))?;
        if !has_owner {
            return Err(NetlinkError::OperationFailed(
                "wpa_supplicant D-Bus not available. Ensure rustyjack-wpa_supplicant@wlan0.service is enabled and started with -u.".to_string(),
            ));
        }
        Ok(())
    }

    async fn supplicant_proxy<'a>(conn: &'a Connection) -> Result<Proxy<'a>> {
        Proxy::new(conn, SUPPLICANT_BUS, SUPPLICANT_PATH, SUPPLICANT_IFACE)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("supplicant proxy: {}", e)))
    }

    async fn interface_proxy<'a>(
        conn: &'a Connection,
        path: &'a OwnedObjectPath,
    ) -> Result<Proxy<'a>> {
        Proxy::new(conn, SUPPLICANT_BUS, path.as_str(), IFACE_IFACE)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("interface proxy: {}", e)))
    }

    async fn properties_proxy<'a>(
        conn: &'a Connection,
        path: &'a OwnedObjectPath,
    ) -> Result<Proxy<'a>> {
        Proxy::new(conn, SUPPLICANT_BUS, path.as_str(), PROPERTIES_IFACE)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("properties proxy: {}", e)))
    }

    async fn bss_proxy<'a>(conn: &'a Connection, path: &'a OwnedObjectPath) -> Result<Proxy<'a>> {
        Proxy::new(conn, SUPPLICANT_BUS, path.as_str(), BSS_IFACE)
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("bss proxy: {}", e)))
    }

    fn is_interface_unknown(err: &zbus::Error) -> bool {
        match err {
            zbus::Error::MethodError(name, _, _) => name.as_str().ends_with("InterfaceUnknown"),
            _ => false,
        }
    }

    async fn get_or_create_interface(&self, conn: &Connection) -> Result<OwnedObjectPath> {
        let proxy = Self::supplicant_proxy(conn).await?;
        let iface = self.interface.clone();

        let path = match proxy.call_method("GetInterface", &(iface.as_str(),)).await {
            Ok(msg) => {
                let (path,): (OwnedObjectPath,) = msg.body().deserialize().map_err(|e| {
                    NetlinkError::OperationFailed(format!("GetInterface parse: {}", e))
                })?;
                path
            }
            Err(err) if Self::is_interface_unknown(&err) => {
                let mut args: HashMap<String, OwnedValue> = HashMap::new();
                args.insert("Ifname".to_string(), owned_value(iface.clone())?);
                args.insert("Driver".to_string(), owned_value("nl80211".to_string())?);
                let msg = proxy
                    .call_method("CreateInterface", &(args))
                    .await
                    .map_err(|e| {
                        NetlinkError::OperationFailed(format!("CreateInterface failed: {}", e))
                    })?;
                let (path,): (OwnedObjectPath,) = msg.body().deserialize().map_err(|e| {
                    NetlinkError::OperationFailed(format!("CreateInterface parse: {}", e))
                })?;
                path
            }
            Err(err) => {
                return Err(NetlinkError::OperationFailed(format!(
                    "GetInterface failed: {}",
                    err
                )))
            }
        };

        if let Ok(mut state) = self.state.lock() {
            state.interface_path = Some(path.clone());
        }

        Ok(path)
    }

    async fn scan_candidates(&self, cfg: &StationConfig) -> Result<ScanOutcome> {
        let conn = self.system_bus().await?;
        Self::ensure_supplicant(&conn).await?;
        let iface_path = self.get_or_create_interface(&conn).await?;
        let iface_proxy = Self::interface_proxy(&conn, &iface_path).await?;

        info!(
            "[WIFI] D-Bus scan for ssid={} on {}",
            cfg.ssid, self.interface
        );
        let mut args: HashMap<String, OwnedValue> = HashMap::new();
        args.insert("Type".to_string(), owned_value("active".to_string())?);
        if cfg.force_scan_ssid && !cfg.ssid.trim().is_empty() {
            args.insert(
                "SSID".to_string(),
                owned_value(cfg.ssid.as_bytes().to_vec())?,
            );
        }

        if let Err(e) = iface_proxy.call_method("Scan", &(args)).await {
            warn!("[WIFI] Scan request error: {}", e);
        }

        self.wait_for_scan_done(&iface_proxy, cfg.scan_timeout)
            .await?;

        let bss_paths: Vec<OwnedObjectPath> = iface_proxy
            .get_property("BSSs")
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("BSSs property: {}", e)))?;

        let mut entries: Vec<(ScanEntry, BssInfo)> = Vec::new();
        for bss_path in bss_paths {
            if let Ok((entry, info)) = self.read_bss_entry(&conn, &bss_path).await {
                entries.push((entry, info));
            }
        }

        if entries.is_empty() {
            warn!(
                "[WIFI] Scan results empty for ssid={} on {}",
                cfg.ssid, self.interface
            );
            return Ok(ScanOutcome {
                candidates: Vec::new(),
                used_scan_ssid: true,
            });
        }

        let mut matching: Vec<(ScanEntry, BssInfo)> = entries
            .iter()
            .cloned()
            .filter(|(entry, _)| entry.ssid == cfg.ssid)
            .collect();

        let mut used_scan_ssid = false;
        if matching.is_empty() {
            used_scan_ssid = true;
            matching = entries
                .iter()
                .cloned()
                .filter(|(entry, _)| entry.ssid.is_empty())
                .collect();
        }

        let mut candidates = Vec::new();
        for (entry, info) in matching {
            let security = security_from_bss(&info);
            if let Some(score) = score_candidate(cfg, &entry, &security) {
                candidates.push(BssCandidate {
                    bssid: entry.bssid,
                    frequency: entry.frequency,
                    signal_dbm: entry.signal_dbm,
                    security,
                    score,
                });
            }
        }

        Ok(ScanOutcome {
            candidates,
            used_scan_ssid,
        })
    }

    async fn wait_for_scan_done(&self, proxy: &Proxy<'_>, timeout: Duration) -> Result<()> {
        let mut stream = proxy
            .receive_signal("ScanDone")
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("ScanDone signal: {}", e)))?;

        let result = tokio::time::timeout(timeout, stream.next())
            .await
            .map_err(|_| NetlinkError::Timeout {
                operation: "wifi scan".to_string(),
                timeout_secs: timeout.as_secs(),
            })?;

        if let Some(msg) = result {
            let (success,): (bool,) = msg
                .body()
                .deserialize()
                .map_err(|e| NetlinkError::OperationFailed(format!("ScanDone parse: {}", e)))?;
            if success {
                return Ok(());
            }
            return Err(NetlinkError::Wpa("Scan failed".to_string()));
        }

        Err(NetlinkError::Timeout {
            operation: "wifi scan".to_string(),
            timeout_secs: timeout.as_secs(),
        })
    }

    async fn read_bss_entry(
        &self,
        conn: &Connection,
        path: &OwnedObjectPath,
    ) -> Result<(ScanEntry, BssInfo)> {
        let proxy = Self::bss_proxy(conn, path).await?;

        let ssid_bytes: Vec<u8> = proxy.get_property("SSID").await.unwrap_or_default();
        let ssid = String::from_utf8_lossy(&ssid_bytes).to_string();

        let bssid_bytes: Vec<u8> = proxy.get_property("BSSID").await.unwrap_or_default();
        let bssid = format_bssid(&bssid_bytes).ok_or_else(|| NetlinkError::ParseError {
            what: "BSSID".to_string(),
            reason: "invalid length".to_string(),
        })?;

        let frequency = proxy.get_property::<u32>("Frequency").await.ok();
        let signal_dbm = match proxy.get_property::<i16>("Signal").await {
            Ok(value) => Some(value as i32),
            Err(_) => proxy.get_property::<i32>("Signal").await.ok(),
        };

        let ies = proxy.get_property::<Vec<u8>>("IEs").await.ok();

        let entry = ScanEntry {
            bssid: bssid.clone(),
            frequency,
            signal_dbm,
            flags: String::new(),
            ssid: ssid.clone(),
        };

        let info = BssInfo {
            bssid: Some(bssid),
            freq: frequency,
            level: signal_dbm,
            flags: None,
            ssid: Some(ssid),
            ie: ies,
            beacon_ie: None,
        };

        Ok((entry, info))
    }

    async fn fetch_status(
        &self,
        conn: &Connection,
        iface_path: &OwnedObjectPath,
    ) -> Result<WpaStatus> {
        let iface_proxy = Self::interface_proxy(conn, iface_path).await?;
        let state: String = iface_proxy
            .get_property("State")
            .await
            .unwrap_or_else(|_| "DISCONNECTED".to_string());
        let wpa_state = WpaState::from_str(&state);

        let mut status = WpaStatus {
            ssid: None,
            bssid: None,
            freq: None,
            mode: Some("station".to_string()),
            pairwise_cipher: None,
            group_cipher: None,
            key_mgmt: None,
            wpa_state,
            ip_address: None,
            address: None,
        };

        if let Ok(current_bss) = iface_proxy
            .get_property::<OwnedObjectPath>("CurrentBSS")
            .await
        {
            if current_bss.as_str() != "/" {
                if let Ok((_entry, info)) = self.read_bss_entry(conn, &current_bss).await {
                    status.ssid = info.ssid;
                    status.bssid = info.bssid;
                    status.freq = info.freq;
                }
            }
        }

        Ok(status)
    }

    async fn wait_for_connection(
        &self,
        conn: &Connection,
        iface_path: &OwnedObjectPath,
        connect_timeout: Duration,
        stage_timeout: Duration,
    ) -> Result<WpaStatus> {
        let props_proxy = Self::properties_proxy(conn, iface_path).await?;
        let mut stream = props_proxy
            .receive_signal("PropertiesChanged")
            .await
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("PropertiesChanged signal: {}", e))
            })?;

        let start = Instant::now();
        let mut last_state = StationState::Idle;
        let mut stage_start = Instant::now();

        loop {
            if start.elapsed() >= connect_timeout {
                return Err(NetlinkError::Timeout {
                    operation: "wifi connect".to_string(),
                    timeout_secs: connect_timeout.as_secs(),
                });
            }

            let stage_remaining = stage_timeout
                .checked_sub(stage_start.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            let connect_remaining = connect_timeout
                .checked_sub(start.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            let wait_for = std::cmp::min(stage_remaining, connect_remaining);

            let msg = tokio::time::timeout(wait_for, stream.next()).await;
            match msg {
                Ok(Some(msg)) => {
                    let (iface_name, changed, _invalidated): (
                        String,
                        HashMap<String, OwnedValue>,
                        Vec<String>,
                    ) = msg.body().deserialize().map_err(|e| {
                        NetlinkError::OperationFailed(format!("PropertiesChanged parse: {}", e))
                    })?;
                    if iface_name != IFACE_IFACE {
                        continue;
                    }

                    if let Some(value) = changed.get("State") {
                        if let Ok(state) = <&str>::try_from(value) {
                            let wpa_state = WpaState::from_str(&state);
                            let station_state = StationState::from_wpa_state(wpa_state);
                            if station_state != last_state {
                                debug!(
                                    "[WIFI] Station state {} -> {}",
                                    format!("{:?}", last_state).to_lowercase(),
                                    format!("{:?}", station_state).to_lowercase()
                                );
                                last_state = station_state;
                                stage_start = Instant::now();
                            }
                            match station_state {
                                StationState::Completed => {
                                    return self.fetch_status(conn, iface_path).await;
                                }
                                StationState::Disconnected => {
                                    return Err(NetlinkError::Wpa(
                                        "Connection failed (disconnected)".to_string(),
                                    ))
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    if stage_start.elapsed() >= stage_timeout {
                        return Err(NetlinkError::Timeout {
                            operation: format!("wifi stage {:?}", last_state).to_lowercase(),
                            timeout_secs: stage_timeout.as_secs(),
                        });
                    }
                }
            }

            // Avoid tight looping if we get no state change signals
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Fallback: pull status once if we exit the signal loop.
        self.fetch_status(conn, iface_path).await
    }

    async fn remove_network(
        &self,
        conn: &Connection,
        iface_path: &OwnedObjectPath,
        network: &OwnedObjectPath,
    ) -> Result<()> {
        let iface_proxy = Self::interface_proxy(conn, iface_path).await?;
        iface_proxy
            .call_method("RemoveNetwork", &(network.clone(),))
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("RemoveNetwork: {}", e)))?;
        Ok(())
    }

    async fn disconnect_interface(
        &self,
        conn: &Connection,
        iface_path: &OwnedObjectPath,
    ) -> Result<()> {
        let iface_proxy = Self::interface_proxy(conn, iface_path).await?;
        iface_proxy
            .call_method("Disconnect", &())
            .await
            .map_err(|e| NetlinkError::OperationFailed(format!("Disconnect: {}", e)))?;
        Ok(())
    }
}

impl StationBackend for WpaSupplicantDbusBackend {
    fn ensure_ready(&self) -> Result<()> {
        self.block_on(async {
            let conn = self.system_bus().await?;
            Self::ensure_supplicant(&conn).await?;
            let _ = self.get_or_create_interface(&conn).await?;
            Ok(())
        })?
    }

    fn scan(&self, cfg: &StationConfig) -> Result<ScanOutcome> {
        self.block_on(self.scan_candidates(cfg))?
    }

    fn connect(
        &self,
        cfg: &StationConfig,
        candidate: Option<&BssCandidate>,
    ) -> Result<StationOutcome> {
        if cfg.ssid.trim().is_empty() {
            return Err(NetlinkError::InvalidInput(
                "SSID cannot be empty".to_string(),
            ));
        }

        self.block_on(async {
            let conn = self.system_bus().await?;
            Self::ensure_supplicant(&conn).await?;
            let iface_path = self.get_or_create_interface(&conn).await?;
            let iface_proxy = Self::interface_proxy(&conn, &iface_path).await?;

            let net_cfg = build_network_config(cfg, candidate, cfg.force_scan_ssid)?;
            let mut args: HashMap<String, OwnedValue> = HashMap::new();
            args.insert(
                "ssid".to_string(),
                owned_value(net_cfg.ssid.as_bytes().to_vec())?,
            );
            if let Some(psk) = net_cfg.psk.clone() {
                args.insert("psk".to_string(), owned_value(psk)?);
            }
            args.insert(
                "key_mgmt".to_string(),
                owned_value(net_cfg.key_mgmt.clone())?,
            );
            if net_cfg.scan_ssid {
                args.insert("scan_ssid".to_string(), owned_value(1u32)?);
            }
            if let Some(proto) = net_cfg.proto.clone() {
                args.insert("proto".to_string(), owned_value(proto)?);
            }
            if let Some(pairwise) = net_cfg.pairwise.clone() {
                args.insert("pairwise".to_string(), owned_value(pairwise)?);
            }
            if let Some(group) = net_cfg.group.clone() {
                args.insert("group".to_string(), owned_value(group)?);
            }

            let msg = iface_proxy
                .call_method("AddNetwork", &(args))
                .await
                .map_err(|e| NetlinkError::OperationFailed(format!("AddNetwork: {}", e)))?;
            let (network_path,): (OwnedObjectPath,) = msg
                .body()
                .deserialize()
                .map_err(|e| NetlinkError::OperationFailed(format!("AddNetwork parse: {}", e)))?;

            if let Ok(mut state) = self.state.lock() {
                state.network_path = Some(network_path.clone());
            }

            iface_proxy
                .call_method("SelectNetwork", &(network_path.clone(),))
                .await
                .map_err(|e| NetlinkError::OperationFailed(format!("SelectNetwork: {}", e)))?;

            match self
                .wait_for_connection(&conn, &iface_path, cfg.connect_timeout, cfg.stage_timeout)
                .await
            {
                Ok(status) => {
                    if let Ok(mut state) = self.state.lock() {
                        state.last_status = status.clone();
                    }
                    let selected_bssid = candidate
                        .map(|c| c.bssid.clone())
                        .or_else(|| status.bssid.clone());
                    let selected_freq = candidate.and_then(|c| c.frequency).or(status.freq);

                    Ok(StationOutcome {
                        status,
                        selected_bssid,
                        selected_freq,
                        attempts: 1,
                        used_scan_ssid: cfg.force_scan_ssid,
                        final_state: StationState::Completed,
                    })
                }
                Err(err) => {
                    let _ = self.disconnect_interface(&conn, &iface_path).await;
                    let _ = self.remove_network(&conn, &iface_path, &network_path).await;
                    Err(err)
                }
            }
        })?
    }

    fn disconnect(&self) -> Result<()> {
        self.block_on(async {
            let conn = self.system_bus().await?;
            let iface_path = self.get_or_create_interface(&conn).await?;
            if let Ok(mut state) = self.state.lock() {
                let _ = self.disconnect_interface(&conn, &iface_path).await;
                if let Some(ref network_path) = state.network_path.clone() {
                    let _ = self.remove_network(&conn, &iface_path, network_path).await;
                }
                state.network_path = None;
                state.last_status.wpa_state = WpaState::Disconnected;
            }
            Ok(())
        })?
    }

    fn status(&self) -> Result<WpaStatus> {
        self.block_on(async {
            let conn = self.system_bus().await?;
            Self::ensure_supplicant(&conn).await?;
            let iface_path = self.get_or_create_interface(&conn).await?;
            let status = self.fetch_status(&conn, &iface_path).await?;
            if let Ok(mut state) = self.state.lock() {
                state.last_status = status.clone();
            }
            Ok(status)
        })?
    }

    fn cleanup(&self) -> Result<()> {
        self.block_on(async {
            let conn = self.system_bus().await?;
            let iface_path = self.get_or_create_interface(&conn).await?;
            if let Ok(mut state) = self.state.lock() {
                if let Some(ref network_path) = state.network_path.clone() {
                    let _ = self.remove_network(&conn, &iface_path, network_path).await;
                }
                state.network_path = None;
            }
            Ok(())
        })?
    }
}

fn format_bssid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    Value<'static>: From<T>,
{
    let val = Value::from(value);
    OwnedValue::try_from(val)
        .map_err(|e| NetlinkError::OperationFailed(format!("dbus value encode: {}", e)))
}
