#[allow(dead_code)]
use crate::error::{NetlinkError, Result};
use tracing::{debug, info};
use neli::{
    attr::Attribute,
    consts::nl::{NlmF, NlmFFlags},
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::GenlBuffer,
};
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

// Re-export commonly used types from neli
use neli::consts::socket::NlFamily;

const NL80211_GENL_NAME: &str = "nl80211";
const NLMSG_ERR: u16 = 2; // NLMSG_ERROR
const NLMSG_DONE: u16 = 3; // NLMSG_DONE

// nl80211 commands
const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_SET_WIPHY: u8 = 2;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_SET_INTERFACE: u8 = 6;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_CMD_TRIGGER_SCAN: u8 = 33;

// nl80211 attributes
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_WIPHY_TX_POWER_SETTING: u16 = 58;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 59;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
const NL80211_ATTR_BSS: u16 = 47;

const NL80211_BAND_ATTR_FREQS: u16 = 1;
const NL80211_BAND_ATTR_RATES: u16 = 2;
const NL80211_BAND_ATTR_HT_MCS_SET: u16 = 3;
const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
const NL80211_BAND_ATTR_HT_AMPDU_FACTOR: u16 = 5;
const NL80211_BAND_ATTR_HT_AMPDU_DENSITY: u16 = 6;
const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
const NL80211_FREQUENCY_ATTR_RADAR: u16 = 4;
const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;
const NL80211_FREQUENCY_ATTR_DFS_STATE: u16 = 7;
const NL80211_BITRATE_ATTR_RATE: u16 = 1;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NL80211_BSS_BSSID: u16 = 1;
const NL80211_BSS_FREQUENCY: u16 = 2;
const NL80211_BSS_TSF: u16 = 3;
const NL80211_BSS_BEACON_INTERVAL: u16 = 4;
const NL80211_BSS_CAPABILITY: u16 = 5;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_SIGNAL_MBM: u16 = 7;
const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
const NL80211_BSS_STATUS: u16 = 9;
const NL80211_BSS_SEEN_MS_AGO: u16 = 10;

#[allow(dead_code)]
const NL80211_DFS_UNSET: u8 = 0;
#[allow(dead_code)]
const NL80211_DFS_USABLE: u8 = 1;
#[allow(dead_code)]
const NL80211_DFS_AVAILABLE: u8 = 2;
#[allow(dead_code)]
const NL80211_DFS_UNAVAILABLE: u8 = 3;

// Interface types
const NL80211_IFTYPE_ADHOC: u32 = 1;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_MONITOR: u32 = 6;
// Event command IDs (subset)
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_CMD_DEL_STATION: u8 = 20;
const NL80211_CMD_REG_CHANGE: u8 = 28;
const NL80211_IFTYPE_MESH_POINT: u32 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const NL80211_IFTYPE_P2P_GO: u32 = 9;

// TX power settings
const NL80211_TX_POWER_AUTOMATIC: u32 = 0;
const NL80211_TX_POWER_LIMITED: u32 = 1;
const NL80211_TX_POWER_FIXED: u32 = 2;

// Channel types
const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_CHAN_HT40MINUS: u32 = 2;
const NL80211_CHAN_HT40PLUS: u32 = 3;

/// Wireless interface mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    Adhoc,
    Station,
    AccessPoint,
    Monitor,
    MeshPoint,
    P2PClient,
    P2PGo,
}

impl InterfaceMode {
    fn to_nl80211(&self) -> u32 {
        match self {
            Self::Adhoc => NL80211_IFTYPE_ADHOC,
            Self::Station => NL80211_IFTYPE_STATION,
            Self::AccessPoint => NL80211_IFTYPE_AP,
            Self::Monitor => NL80211_IFTYPE_MONITOR,
            Self::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Self::P2PClient => NL80211_IFTYPE_P2P_CLIENT,
            Self::P2PGo => NL80211_IFTYPE_P2P_GO,
        }
    }

    fn from_nl80211(iftype: u32) -> Option<Self> {
        match iftype {
            NL80211_IFTYPE_ADHOC => Some(Self::Adhoc),
            NL80211_IFTYPE_STATION => Some(Self::Station),
            NL80211_IFTYPE_AP => Some(Self::AccessPoint),
            NL80211_IFTYPE_MONITOR => Some(Self::Monitor),
            NL80211_IFTYPE_MESH_POINT => Some(Self::MeshPoint),
            NL80211_IFTYPE_P2P_CLIENT => Some(Self::P2PClient),
            NL80211_IFTYPE_P2P_GO => Some(Self::P2PGo),
            _ => None,
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Adhoc => "adhoc",
            Self::Station => "managed",
            Self::AccessPoint => "ap",
            Self::Monitor => "monitor",
            Self::MeshPoint => "mesh",
            Self::P2PClient => "p2p-client",
            Self::P2PGo => "p2p-go",
        }
    }
}

/// Channel bandwidth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelWidth {
    NoHT,
    HT20,
    HT40Minus,
    HT40Plus,
}

impl ChannelWidth {
    fn to_nl80211(&self) -> u32 {
        match self {
            Self::NoHT => NL80211_CHAN_NO_HT,
            Self::HT20 => NL80211_CHAN_HT20,
            Self::HT40Minus => NL80211_CHAN_HT40MINUS,
            Self::HT40Plus => NL80211_CHAN_HT40PLUS,
        }
    }
}

/// TX power setting mode
#[derive(Debug, Clone, Copy)]
pub enum TxPowerSetting {
    Automatic,
    Limited(u32), // mBm
    Fixed(u32),   // mBm
}

/// Wireless interface information
#[derive(Debug, Clone)]
pub struct WirelessInfo {
    pub interface: String,
    pub ifindex: u32,
    pub wiphy: u32,
    pub mode: Option<InterfaceMode>,
    pub frequency: Option<u32>,
    pub channel: Option<u8>,
    pub txpower_mbm: Option<i32>,
}

/// Wi-Fi scan result entry
#[derive(Debug, Clone)]
pub struct WifiScanResult {
    pub bssid: [u8; 6],
    pub ssid: Option<String>,
    pub frequency: Option<u32>,
    pub signal_mbm: Option<i32>,
    pub seen_ms_ago: Option<u32>,
    pub capability: Option<u16>,
    pub beacon_interval: Option<u16>,
    pub ies: Option<Vec<u8>>,
}

/// PHY capabilities
#[derive(Debug, Clone)]
pub struct PhyCapabilities {
    pub wiphy: u32,
    pub name: String,
    pub supported_modes: Vec<InterfaceMode>,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    pub supports_station: bool,
    pub supported_bands: Vec<String>,
    pub band_info: Vec<BandInfo>,
}

#[derive(Debug, Clone)]
pub struct BandInfo {
    pub name: String,
    pub frequencies: Vec<FrequencyInfo>,
    /// Bitrates in 100 kbps units.
    pub rates: Vec<u32>,
    pub ht_capab: Option<u16>,
    pub ht_ampdu_factor: Option<u8>,
    pub ht_ampdu_density: Option<u8>,
    pub ht_mcs_set: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct FrequencyInfo {
    pub freq: u32,
    pub disabled: bool,
    pub no_ir: bool,
    pub radar: bool,
    pub dfs_state: Option<u8>,
    /// Max TX power in mBm (100 * dBm).
    pub max_tx_power: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct NlAttrSlice<'a> {
    nla_type: u16,
    payload: &'a [u8],
}

/// Wireless netlink manager
pub struct WirelessManager {
    socket: NlSocketHandle,
    family_id: u16,
    event_task: Option<std::thread::JoinHandle<()>>,
    event_stop: Arc<AtomicBool>,
}

impl Drop for WirelessManager {
    fn drop(&mut self) {
        self.event_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.event_task.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

fn set_recv_timeout(sock: &NlSocketHandle, timeout: Duration) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;

        let fd = sock.as_raw_fd();
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            debug!(
                "[WIFI] failed to set nl80211 recv timeout: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn spawn_event_logger(
    _family_id: u16,
    mut sock: NlSocketHandle,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    thread::spawn(move || {
        set_recv_timeout(&sock, Duration::from_millis(200));
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match sock.recv::<u16, Genlmsghdr<u8, u16>>() {
            Ok(Some(msg)) => {
                let nl_type = msg.nl_type;
                match msg.nl_payload {
                    NlPayload::Payload(genl) => {
                        let cmd = genl.cmd;
                        if cmd == NL80211_CMD_NEW_STATION || cmd == NL80211_CMD_DEL_STATION {
                            let attrs = genl.get_attr_handle();
                            let mut ifidx = None;
                            let mut mac = None;
                            for attr in attrs.iter() {
                                match attr.nla_type.nla_type {
                                    NL80211_ATTR_IFINDEX => {
                                        if let Ok(val) = attr.get_payload_as::<u32>() {
                                            ifidx = Some(val);
                                        }
                                    }
                                    NL80211_ATTR_MAC => {
                                        let bytes = attr.payload().as_ref();
                                        if bytes.len() == 6 {
                                            mac = Some([
                                                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                                                bytes[5],
                                            ]);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            if cmd == NL80211_CMD_NEW_STATION {
                                debug!(
                                    "[WIFI] nl80211 NEW_STATION ifindex={:?} mac={:02x?}",
                                    ifidx,
                                    mac.unwrap_or([0; 6])
                                );
                            } else {
                                debug!(
                                    "[WIFI] nl80211 DEL_STATION ifindex={:?} mac={:02x?}",
                                    ifidx,
                                    mac.unwrap_or([0; 6])
                                );
                            }
                        } else if cmd == NL80211_CMD_REG_CHANGE {
                            debug!(
                                "[WIFI] nl80211 REG_CHANGE nl_type={} flags={:?}",
                                nl_type, msg.nl_flags
                            );
                        } else {
                            debug!(
                                "[WIFI] nl80211 event cmd={} nl_type={} flags={:?}",
                                cmd, nl_type, msg.nl_flags
                            );
                        }
                    }
                    NlPayload::Err(err) => {
                        debug!(
                            "[WIFI] nl80211 event error nl_type={} code={}",
                            nl_type, err.error
                        );
                    }
                    _ => {
                        debug!("[WIFI] nl80211 event other nl_type={}", nl_type);
                    }
                }
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                debug!("[WIFI] nl80211 event recv error: {}", e);
                thread::sleep(Duration::from_millis(200));
            }
        }
        }
        debug!("[WIFI] nl80211 event logger stopped");
    })
}

impl WirelessManager {
    /// Create a new wireless manager
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Cannot create netlink socket (requires CAP_NET_ADMIN)
    /// - nl80211 generic netlink family not found (wireless drivers not loaded)
    pub fn new() -> Result<Self> {
        let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[]).map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to create nl80211 socket: {}", e))
        })?;

        let family_id = socket.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
            NetlinkError::OperationFailed(format!(
                "Failed to resolve nl80211 family (wireless drivers not loaded?): {}",
                e
            ))
        })?;

        // Separate socket for event subscription (logger) and one kept for future use
        let event_socket = NlSocketHandle::connect(NlFamily::Generic, None, &[]).map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to create nl80211 event socket: {}", e))
        })?;
        let _ = event_socket.add_mcast_membership(&[family_id as u32]);

        let logger_socket = NlSocketHandle::connect(NlFamily::Generic, None, &[]).map_err(|e| {
            NetlinkError::ConnectionFailed(format!("Failed to create nl80211 logger socket: {}", e))
        })?;
        let _ = logger_socket.add_mcast_membership(&[family_id as u32]);
        let event_stop = Arc::new(AtomicBool::new(false));
        let event_task = Some(spawn_event_logger(
            family_id,
            logger_socket,
            Arc::clone(&event_stop),
        ));

        Ok(Self {
            socket,
            family_id,
            event_task,
            event_stop,
        })
    }

    /// Get interface index from name
    fn get_ifindex(&self, interface: &str) -> Result<u32> {
        let interfaces =
            std::fs::read_to_string("/sys/class/net/".to_string() + interface + "/ifindex")
                .map_err(|e| NetlinkError::InterfaceNotFound {
                    name: format!("Interface '{}' not found: {}", interface, e),
                })?;

        interfaces.trim().parse::<u32>().map_err(|e| {
            NetlinkError::OperationFailed(format!(
                "Failed to parse ifindex for '{}': {}",
                interface, e
            ))
        })
    }

    /// Set interface mode (managed, monitor, ap, etc.)
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (e.g., "wlan0")
    /// * `mode` - Desired interface mode
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Permission denied (requires root)
    /// - Mode not supported by hardware
    /// - Interface is up (must be down to change mode)
    pub fn set_mode(&mut self, interface: &str, mode: InterfaceMode) -> Result<()> {
        let ifindex = self.get_ifindex(interface)?;
        debug!(
            "nl80211 set_mode iface={} ifindex={} mode={}",
            interface,
            ifindex,
            mode.to_string()
        );

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFTYPE, mode.to_nl80211()).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create iftype attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_INTERFACE, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send set_mode request: {}", e))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to receive set_mode response: {}", e))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed("No response received for set_mode".to_string())
            })?;

        if response.nl_type == NLMSG_ERR {
            match response.nl_payload {
                // NLMSG_ERR with error == 0 is the expected ACK
                NlPayload::Err(err) if err.error == 0 => return Ok(()),
                NlPayload::Ack(ack) if ack.error == 0 => return Ok(()),
                NlPayload::Err(err) => {
                    let errno = err.error.abs();
                    let io_err = io::Error::from_raw_os_error(errno);
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set interface '{}' to {} mode via nl80211: {} (errno {})",
                        interface,
                        mode.to_string(),
                        io_err,
                        errno
                    )));
                }
                NlPayload::Ack(ack) => {
                    let errno = ack.error.abs();
                    let io_err = io::Error::from_raw_os_error(errno);
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set interface '{}' to {} mode via nl80211: {} (errno {})",
                        interface,
                        mode.to_string(),
                        io_err,
                        errno
                    )));
                }
                other => {
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set interface '{}' to {} mode via nl80211 (unexpected payload {:?})",
                        interface,
                        mode.to_string(),
                        other
                    )));
                }
            }
        }

        info!(
            "nl80211 set_mode succeeded iface={} ifindex={} mode={}",
            interface,
            ifindex,
            mode.to_string()
        );
        Ok(())
    }

    /// Set channel
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name
    /// * `channel` - Channel number (1-14 for 2.4GHz, 36+ for 5GHz)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Permission denied
    /// - Channel not supported by hardware
    /// - Invalid channel number
    pub fn set_channel(&mut self, interface: &str, channel: u8) -> Result<()> {
        let frequency = Self::channel_to_frequency(channel).ok_or_else(|| {
            NetlinkError::OperationFailed(format!("Invalid channel number: {}", channel))
        })?;
        debug!(
            "nl80211 set_channel iface={} channel={} freq={}",
            interface, channel, frequency
        );

        self.set_frequency(interface, frequency, ChannelWidth::NoHT)
    }

    /// Set frequency
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name
    /// * `frequency` - Frequency in MHz
    /// * `width` - Channel bandwidth
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Permission denied
    /// - Frequency not supported
    pub fn set_frequency(
        &mut self,
        interface: &str,
        frequency: u32,
        width: ChannelWidth,
    ) -> Result<()> {
        let ifindex = self.get_ifindex(interface)?;
        debug!(
            "nl80211 set_frequency iface={} ifindex={} freq={} width={:?}",
            interface, ifindex, frequency, width
        );

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_WIPHY_FREQ, frequency).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create frequency attr: {}", e))
            })?,
        );
        attrs.push(
            Nlattr::new(
                false,
                false,
                NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                width.to_nl80211(),
            )
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create channel_type attr: {}", e))
            })?,
        );

        let mut attrs_buf = GenlBuffer::new();
        for attr in attrs {
            attrs_buf.push(attr);
        }
        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_WIPHY, 1, attrs_buf);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send set_frequency request: {}", e))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive set_frequency response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed("No response received for set_frequency".to_string())
            })?;

        if response.nl_type == NLMSG_ERR {
            match response.nl_payload {
                NlPayload::Err(err) if err.error == 0 => return Ok(()), // ACK
                NlPayload::Ack(ack) if ack.error == 0 => return Ok(()), // ACK
                NlPayload::Err(err) => {
                    let errno = err.error.abs();
                    let io_err = io::Error::from_raw_os_error(errno);
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set frequency {} MHz on interface '{}': {} (errno {})",
                        frequency, interface, io_err, errno
                    )));
                }
                NlPayload::Ack(ack) => {
                    let errno = ack.error.abs();
                    let io_err = io::Error::from_raw_os_error(errno);
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set frequency {} MHz on interface '{}': {} (errno {})",
                        frequency, interface, io_err, errno
                    )));
                }
                other => {
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to set frequency {} MHz on interface '{}': unexpected payload {:?}",
                        frequency, interface, other
                    )));
                }
            }
        }

        info!(
            "nl80211 set_frequency succeeded iface={} ifindex={} freq={} width={:?}",
            interface, ifindex, frequency, width
        );
        Ok(())
    }

    /// Set TX power
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name
    /// * `power` - TX power setting
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Permission denied
    /// - Power level exceeds hardware limits
    pub fn set_tx_power(&mut self, interface: &str, power: TxPowerSetting) -> Result<()> {
        let ifindex = self.get_ifindex(interface)?;

        let (setting_type, power_level) = match power {
            TxPowerSetting::Automatic => (NL80211_TX_POWER_AUTOMATIC, None),
            TxPowerSetting::Limited(mbm) => (NL80211_TX_POWER_LIMITED, Some(mbm)),
            TxPowerSetting::Fixed(mbm) => (NL80211_TX_POWER_FIXED, Some(mbm)),
        };

        let mut attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
            Nlattr::new(
                false,
                false,
                NL80211_ATTR_WIPHY_TX_POWER_SETTING,
                setting_type,
            )
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to create tx_power_setting attr: {}",
                    e
                ))
            })?,
        ];

        if let Some(level) = power_level {
            attrs.push(
                Nlattr::new(false, false, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, level).map_err(
                    |e| {
                        NetlinkError::OperationFailed(format!(
                            "Failed to create tx_power_level attr: {}",
                            e
                        ))
                    },
                )?,
            );
        }

        let mut attrs_buf = GenlBuffer::new();
        for attr in attrs {
            attrs_buf.push(attr);
        }
        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_WIPHY, 1, attrs_buf);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send set_tx_power request: {}", e))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive set_tx_power response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed("No response received for set_tx_power".to_string())
            })?;

        if response.nl_type == NLMSG_ERR {
            return Err(NetlinkError::OperationFailed(format!(
                "Failed to set TX power on interface '{}'. Power level may exceed hardware limits.",
                interface
            )));
        }

        Ok(())
    }

    /// Create virtual interface
    ///
    /// # Arguments
    ///
    /// * `phy_interface` - Physical interface to create virtual interface from
    /// * `new_name` - Name for the new interface
    /// * `mode` - Interface mode
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Physical interface not found
    /// - Permission denied
    /// - Interface name already exists
    /// - Mode not supported
    pub fn create_interface(
        &mut self,
        phy_interface: &str,
        new_name: &str,
        mode: InterfaceMode,
    ) -> Result<()> {
        let ifindex = self.get_ifindex(phy_interface)?;

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFNAME, new_name.as_bytes()).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifname attr: {}", e))
            })?,
        );
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFTYPE, mode.to_nl80211()).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create iftype attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_NEW_INTERFACE, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send create_interface request: {}", e))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive create_interface response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed(
                    "No response received for create_interface".to_string(),
                )
            })?;

        if response.nl_type == NLMSG_ERR {
            return Err(NetlinkError::OperationFailed(
                format!("Failed to create virtual interface '{}' from '{}'. Interface name may already exist or mode not supported.", 
                    new_name, phy_interface)
            ));
        }

        Ok(())
    }

    /// Delete virtual interface
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name to delete
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Permission denied
    /// - Cannot delete physical interface
    pub fn delete_interface(&mut self, interface: &str) -> Result<()> {
        let ifindex = self.get_ifindex(interface)?;

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_DEL_INTERFACE, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send delete_interface request: {}", e))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive delete_interface response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed(
                    "No response received for delete_interface".to_string(),
                )
            })?;

        if response.nl_type == NLMSG_ERR {
            return Err(NetlinkError::OperationFailed(
                format!("Failed to delete interface '{}'. Cannot delete physical interfaces, only virtual ones.", interface)
            ));
        }

        Ok(())
    }

    /// Get interface information
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name
    ///
    /// # Errors
    ///
    /// Returns error if interface not found or query fails
    pub fn get_interface_info(&mut self, interface: &str) -> Result<WirelessInfo> {
        let ifindex = self.get_ifindex(interface)?;

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_GET_INTERFACE, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!(
                "Failed to send get_interface_info request: {}",
                e
            ))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive get_interface_info response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed(
                    "No response received for get_interface_info".to_string(),
                )
            })?;

        let mut info = WirelessInfo {
            interface: interface.to_string(),
            ifindex,
            wiphy: 0,
            mode: None,
            frequency: None,
            channel: None,
            txpower_mbm: None,
        };

        if let NlPayload::Payload(genlhdr) = &response.nl_payload {
            let attrs = genlhdr.get_attr_handle();
            for attr in attrs.iter() {
                match attr.nla_type.nla_type {
                    NL80211_ATTR_WIPHY => {
                        // Nlattr has a payload field of type Buffer (Vec<u8>)
                        let payload = attr.nla_payload.as_ref();
                        if payload.len() >= 4 {
                            info.wiphy = u32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                        }
                    }
                    NL80211_ATTR_IFTYPE => {
                        let payload = attr.nla_payload.as_ref();
                        if payload.len() >= 4 {
                            let iftype = u32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            info.mode = InterfaceMode::from_nl80211(iftype);
                        }
                    }
                    NL80211_ATTR_WIPHY_FREQ => {
                        let payload = attr.nla_payload.as_ref();
                        if payload.len() >= 4 {
                            let freq = u32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            info.frequency = Some(freq);
                            info.channel = Self::frequency_to_channel(freq);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(info)
    }

    /// Trigger a Wi-Fi scan and return observed access points.
    pub fn scan_wifi(&mut self, interface: &str, timeout: Duration) -> Result<Vec<WifiScanResult>> {
        let ifindex = self.get_ifindex(interface)?;
        self.trigger_scan(ifindex)?;

        let start = std::time::Instant::now();
        loop {
            let results = self.get_scan_results(ifindex)?;
            if !results.is_empty() || start.elapsed() >= timeout {
                return Ok(results);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn trigger_scan(&mut self, ifindex: u32) -> Result<()> {
        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );

        let ssid_payload = Self::build_scan_ssids_payload();
        attrs.push(
            Nlattr::new(true, false, NL80211_ATTR_SCAN_SSIDS, ssid_payload).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create scan SSIDs attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_TRIGGER_SCAN, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send trigger scan request: {}", e))
        })?;

        set_recv_timeout(&self.socket, Duration::from_millis(800));
        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = match self.socket.recv() {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                return Err(NetlinkError::OperationFailed(
                    "No response received for trigger scan".to_string(),
                ))
            }
            Err(e) => {
                return Err(NetlinkError::OperationFailed(format!(
                    "Failed to receive trigger scan response: {}",
                    e
                )))
            }
        };

        if response.nl_type == NLMSG_ERR {
            let handle_error = |err_code: i32| -> Result<()> {
                if err_code == 0 {
                    return Ok(());
                }
                let errno = err_code.abs();
                if errno == libc::EBUSY {
                    debug!("[WIFI] Scan already in progress (EBUSY)");
                    return Ok(());
                }
                let io_err = io::Error::from_raw_os_error(errno);
                Err(NetlinkError::OperationFailed(format!(
                    "Trigger scan failed: {} (errno {})",
                    io_err, errno
                )))
            };

            match response.nl_payload {
                NlPayload::Err(err) => handle_error(err.error)?,
                NlPayload::Ack(ack) => handle_error(ack.error)?,
                other => {
                    return Err(NetlinkError::OperationFailed(format!(
                        "Trigger scan unexpected response: {:?}",
                        other
                    )));
                }
            }
        }

        Ok(())
    }

    fn get_scan_results(&mut self, ifindex: u32) -> Result<Vec<WifiScanResult>> {
        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_GET_SCAN, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to send get_scan request: {}", e))
        })?;

        set_recv_timeout(&self.socket, Duration::from_millis(800));

        let mut results = Vec::new();
        loop {
            let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = match self.socket.recv() {
                Ok(Some(msg)) => msg,
                Ok(None) => break,
                Err(e) => {
                    return Err(NetlinkError::OperationFailed(format!(
                        "Failed to receive scan results: {}",
                        e
                    )))
                }
            };

            if msg.nl_type == NLMSG_DONE {
                break;
            }

            if msg.nl_type == NLMSG_ERR {
                if let NlPayload::Err(err) = msg.nl_payload {
                    let errno = err.error.abs();
                    let io_err = io::Error::from_raw_os_error(errno);
                    return Err(NetlinkError::OperationFailed(format!(
                        "Scan results error: {} (errno {})",
                        io_err, errno
                    )));
                }
                break;
            }

            if let NlPayload::Payload(genl) = msg.nl_payload {
                let attrs = genl.get_attr_handle();
                for attr in attrs.iter() {
                    if attr.nla_type.nla_type != NL80211_ATTR_BSS {
                        continue;
                    }
                    if let Some(entry) = Self::parse_bss(attr.payload().as_ref()) {
                        results.push(entry);
                    }
                }
            }
        }

        Ok(results)
    }

    fn parse_bss(payload: &[u8]) -> Option<WifiScanResult> {
        let mut bssid: Option<[u8; 6]> = None;
        let mut frequency: Option<u32> = None;
        let mut signal_mbm: Option<i32> = None;
        let mut seen_ms_ago: Option<u32> = None;
        let mut capability: Option<u16> = None;
        let mut beacon_interval: Option<u16> = None;
        let mut ies: Option<&[u8]> = None;

        for attr in Self::parse_nested_attrs(payload) {
            match attr.nla_type {
                NL80211_BSS_BSSID => {
                    if attr.payload.len() == 6 {
                        bssid = Some([
                            attr.payload[0],
                            attr.payload[1],
                            attr.payload[2],
                            attr.payload[3],
                            attr.payload[4],
                            attr.payload[5],
                        ]);
                    }
                }
                NL80211_BSS_FREQUENCY => {
                    if attr.payload.len() >= 4 {
                        frequency = Some(u32::from_ne_bytes([
                            attr.payload[0],
                            attr.payload[1],
                            attr.payload[2],
                            attr.payload[3],
                        ]));
                    }
                }
                NL80211_BSS_SIGNAL_MBM => {
                    if attr.payload.len() >= 4 {
                        signal_mbm = Some(i32::from_ne_bytes([
                            attr.payload[0],
                            attr.payload[1],
                            attr.payload[2],
                            attr.payload[3],
                        ]));
                    }
                }
                NL80211_BSS_SEEN_MS_AGO => {
                    if attr.payload.len() >= 4 {
                        seen_ms_ago = Some(u32::from_ne_bytes([
                            attr.payload[0],
                            attr.payload[1],
                            attr.payload[2],
                            attr.payload[3],
                        ]));
                    }
                }
                NL80211_BSS_CAPABILITY => {
                    if attr.payload.len() >= 2 {
                        capability = Some(u16::from_ne_bytes([attr.payload[0], attr.payload[1]]));
                    }
                }
                NL80211_BSS_BEACON_INTERVAL => {
                    if attr.payload.len() >= 2 {
                        beacon_interval =
                            Some(u16::from_ne_bytes([attr.payload[0], attr.payload[1]]));
                    }
                }
                NL80211_BSS_INFORMATION_ELEMENTS => {
                    ies = Some(attr.payload);
                }
                _ => {}
            }
        }

        let bssid = bssid?;
        let ssid = ies.and_then(Self::parse_ssid_from_ies).filter(|s| !s.is_empty());

        Some(WifiScanResult {
            bssid,
            ssid,
            frequency,
            signal_mbm,
            seen_ms_ago,
            capability,
            beacon_interval,
            ies: ies.map(|bytes| bytes.to_vec()),
        })
    }

    fn parse_ssid_from_ies(payload: &[u8]) -> Option<String> {
        let mut offset = 0usize;
        while payload.len().saturating_sub(offset) >= 2 {
            let id = payload[offset];
            let len = payload[offset + 1] as usize;
            offset += 2;
            if payload.len().saturating_sub(offset) < len {
                break;
            }
            if id == 0 {
                let bytes = &payload[offset..offset + len];
                return Some(String::from_utf8_lossy(bytes).to_string());
            }
            offset = offset.saturating_add(len);
        }
        None
    }

    fn build_scan_ssids_payload() -> Vec<u8> {
        let len: u16 = 4;
        let nla_type: u16 = 0;
        let mut bytes = Vec::with_capacity(4);
        bytes.extend_from_slice(&len.to_ne_bytes());
        bytes.extend_from_slice(&nla_type.to_ne_bytes());
        bytes
    }

    /// Get PHY capabilities
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name to query PHY for
    ///
    /// # Errors
    ///
    /// Returns error if interface not found or query fails
    pub fn get_phy_capabilities(&mut self, interface: &str) -> Result<PhyCapabilities> {
        let info = self.get_interface_info(interface)?;

        let mut attrs = GenlBuffer::new();
        attrs.push(
            Nlattr::new(false, false, NL80211_ATTR_WIPHY, info.wiphy).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to create wiphy attr: {}", e))
            })?,
        );

        let genlhdr = Genlmsghdr::new(NL80211_CMD_GET_WIPHY, 1, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            NlmFFlags::new(&[NlmF::Request]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr).map_err(|e| {
            NetlinkError::OperationFailed(format!(
                "Failed to send get_phy_capabilities request: {}",
                e
            ))
        })?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self
            .socket
            .recv()
            .map_err(|e| {
                NetlinkError::OperationFailed(format!(
                    "Failed to receive get_phy_capabilities response: {}",
                    e
                ))
            })?
            .ok_or_else(|| {
                NetlinkError::OperationFailed(
                    "No response received for get_phy_capabilities".to_string(),
                )
            })?;

        let mut caps = PhyCapabilities {
            wiphy: info.wiphy,
            name: format!("phy{}", info.wiphy),
            supported_modes: Vec::new(),
            supports_monitor: false,
            supports_ap: false,
            supports_station: false,
            supported_bands: Vec::new(),
            band_info: Vec::new(),
        };

        let mut band_info = Vec::new();
        if let NlPayload::Payload(genlhdr) = &response.nl_payload {
            let attrs = genlhdr.get_attr_handle();
            for attr in attrs.iter() {
                match attr.nla_type.nla_type {
                    NL80211_ATTR_WIPHY_NAME => {
                        let payload = attr.nla_payload.as_ref();
                        if let Ok(name) = std::str::from_utf8(payload) {
                            caps.name = name.trim_end_matches('\0').to_string();
                        }
                    }
                    NL80211_ATTR_SUPPORTED_IFTYPES => {
                        // Best-effort: mark common modes as supported when the attribute is present.
                        caps.supports_monitor = true;
                        caps.supports_ap = true;
                        caps.supports_station = true;
                        for mode in [
                            InterfaceMode::AccessPoint,
                            InterfaceMode::Station,
                            InterfaceMode::Monitor,
                        ] {
                            if !caps.supported_modes.contains(&mode) {
                                caps.supported_modes.push(mode);
                            }
                        }
                    }
                    NL80211_ATTR_WIPHY_BANDS => {
                        for band_attr in Self::parse_nested_attrs(attr.payload().as_ref()) {
                            if let Some(info) =
                                Self::parse_band_info(band_attr.nla_type, band_attr.payload)
                            {
                                band_info.push(info);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if !band_info.is_empty() {
            let mut names: Vec<String> = band_info.iter().map(|b| b.name.clone()).collect();
            names.sort();
            names.dedup();
            caps.supported_bands = names;
            caps.band_info = band_info;
        }

        // If the kernel didn't enumerate any interface modes, fall back to the coarse flags.
        if caps.supported_modes.is_empty() {
            if caps.supports_ap {
                caps.supported_modes.push(InterfaceMode::AccessPoint);
            }
            if caps.supports_station {
                caps.supported_modes.push(InterfaceMode::Station);
            }
            if caps.supports_monitor {
                caps.supported_modes.push(InterfaceMode::Monitor);
            }
        }

        Ok(caps)
    }

    fn parse_nested_attrs<'a>(payload: &'a [u8]) -> Vec<NlAttrSlice<'a>> {
        let mut attrs = Vec::new();
        let mut offset = 0;
        while payload.len().saturating_sub(offset) >= 4 {
            let header = &payload[offset..offset + 4];
            let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
            let nla_type = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
            if len < 4 || offset + len > payload.len() {
                break;
            }
            let data = &payload[offset + 4..offset + len];
            attrs.push(NlAttrSlice {
                nla_type,
                payload: data,
            });
            let aligned = (len + 3) & !3;
            if aligned == 0 {
                break;
            }
            offset = offset.saturating_add(aligned);
        }
        attrs
    }

    fn parse_band_info(band_idx: u16, payload: &[u8]) -> Option<BandInfo> {
        let band_attrs = Self::parse_nested_attrs(payload);
        let mut freqs = Vec::new();
        let mut rates = Vec::new();
        let mut ht_capab = None;
        let mut ht_ampdu_factor = None;
        let mut ht_ampdu_density = None;
        let mut ht_mcs_set = None;
        for band_attr in band_attrs {
            match band_attr.nla_type {
                NL80211_BAND_ATTR_FREQS => freqs = Self::parse_band_frequencies(band_attr.payload),
                NL80211_BAND_ATTR_RATES => rates = Self::parse_band_rates(band_attr.payload),
                NL80211_BAND_ATTR_HT_CAPA => {
                    if band_attr.payload.len() >= 2 {
                        ht_capab = Some(u16::from_ne_bytes([
                            band_attr.payload[0],
                            band_attr.payload[1],
                        ]));
                    }
                }
                NL80211_BAND_ATTR_HT_AMPDU_FACTOR => {
                    ht_ampdu_factor = band_attr.payload.first().copied();
                }
                NL80211_BAND_ATTR_HT_AMPDU_DENSITY => {
                    ht_ampdu_density = band_attr.payload.first().copied();
                }
                NL80211_BAND_ATTR_HT_MCS_SET => {
                    if band_attr.payload.len() >= 16 {
                        ht_mcs_set = Some(band_attr.payload[..16].to_vec());
                    }
                }
                _ => {}
            }
        }
        freqs.sort_by_key(|f| f.freq);
        freqs.dedup_by_key(|f| f.freq);
        rates.sort_unstable();
        rates.dedup();
        if freqs.is_empty() && rates.is_empty() {
            return None;
        }
        let name = Self::band_name_from_freqs(&freqs, band_idx);
        Some(BandInfo {
            name,
            frequencies: freqs,
            rates,
            ht_capab,
            ht_ampdu_factor,
            ht_ampdu_density,
            ht_mcs_set,
        })
    }

    fn parse_band_frequencies(payload: &[u8]) -> Vec<FrequencyInfo> {
        let mut freqs = Vec::new();
        let entries = Self::parse_nested_attrs(payload);
        for entry in entries {
            let entry_attrs = Self::parse_nested_attrs(entry.payload);
            let mut freq = None;
            let mut info = FrequencyInfo {
                freq: 0,
                disabled: false,
                no_ir: false,
                radar: false,
                dfs_state: None,
                max_tx_power: None,
            };
            for attr in entry_attrs {
                match attr.nla_type {
                    NL80211_FREQUENCY_ATTR_FREQ => {
                        if attr.payload.len() >= 4 {
                            freq = Some(u32::from_ne_bytes([
                                attr.payload[0],
                                attr.payload[1],
                                attr.payload[2],
                                attr.payload[3],
                            ]));
                        }
                    }
                    NL80211_FREQUENCY_ATTR_DISABLED => {
                        info.disabled = true;
                    }
                    NL80211_FREQUENCY_ATTR_NO_IR => {
                        info.no_ir = true;
                    }
                    NL80211_FREQUENCY_ATTR_RADAR => {
                        info.radar = true;
                    }
                    NL80211_FREQUENCY_ATTR_DFS_STATE => {
                        if attr.payload.len() >= 4 {
                            let raw = u32::from_ne_bytes([
                                attr.payload[0],
                                attr.payload[1],
                                attr.payload[2],
                                attr.payload[3],
                            ]) as u8;
                            info.dfs_state = Some(raw);
                        } else if let Some(val) = attr.payload.first() {
                            info.dfs_state = Some(*val);
                        }
                    }
                    NL80211_FREQUENCY_ATTR_MAX_TX_POWER => {
                        if attr.payload.len() >= 4 {
                            info.max_tx_power = Some(u32::from_ne_bytes([
                                attr.payload[0],
                                attr.payload[1],
                                attr.payload[2],
                                attr.payload[3],
                            ]));
                        }
                    }
                    _ => {}
                }
            }
            if let Some(freq) = freq {
                info.freq = freq;
                freqs.push(info);
            }
        }
        freqs
    }

    fn parse_band_rates(payload: &[u8]) -> Vec<u32> {
        let mut rates = Vec::new();
        let entries = Self::parse_nested_attrs(payload);
        for entry in entries {
            let entry_attrs = Self::parse_nested_attrs(entry.payload);
            for attr in entry_attrs {
                if attr.nla_type == NL80211_BITRATE_ATTR_RATE && attr.payload.len() >= 4 {
                    rates.push(u32::from_ne_bytes([
                        attr.payload[0],
                        attr.payload[1],
                        attr.payload[2],
                        attr.payload[3],
                    ]));
                }
            }
        }
        rates
    }

    fn band_name_from_freqs(freqs: &[FrequencyInfo], band_idx: u16) -> String {
        if freqs.iter().any(|f| (2400..=2500).contains(&f.freq)) {
            "2.4GHz".to_string()
        } else if freqs.iter().any(|f| (4900..=6000).contains(&f.freq)) {
            "5GHz".to_string()
        } else {
            format!("band{}", band_idx)
        }
    }

    /// Convert channel number to frequency (MHz)
    pub fn channel_to_frequency(channel: u8) -> Option<u32> {
        match channel {
            // 2.4 GHz
            1 => Some(2412),
            2 => Some(2417),
            3 => Some(2422),
            4 => Some(2427),
            5 => Some(2432),
            6 => Some(2437),
            7 => Some(2442),
            8 => Some(2447),
            9 => Some(2452),
            10 => Some(2457),
            11 => Some(2462),
            12 => Some(2467),
            13 => Some(2472),
            14 => Some(2484),
            // 5 GHz
            36 => Some(5180),
            40 => Some(5200),
            44 => Some(5220),
            48 => Some(5240),
            52 => Some(5260),
            56 => Some(5280),
            60 => Some(5300),
            64 => Some(5320),
            100 => Some(5500),
            104 => Some(5520),
            108 => Some(5540),
            112 => Some(5560),
            116 => Some(5580),
            120 => Some(5600),
            124 => Some(5620),
            128 => Some(5640),
            132 => Some(5660),
            136 => Some(5680),
            140 => Some(5700),
            144 => Some(5720),
            149 => Some(5745),
            153 => Some(5765),
            157 => Some(5785),
            161 => Some(5805),
            165 => Some(5825),
            _ => None,
        }
    }

    /// Convert frequency (MHz) to channel number
    pub fn frequency_to_channel(freq: u32) -> Option<u8> {
        match freq {
            // 2.4 GHz
            2412 => Some(1),
            2417 => Some(2),
            2422 => Some(3),
            2427 => Some(4),
            2432 => Some(5),
            2437 => Some(6),
            2442 => Some(7),
            2447 => Some(8),
            2452 => Some(9),
            2457 => Some(10),
            2462 => Some(11),
            2467 => Some(12),
            2472 => Some(13),
            2484 => Some(14),
            // 5 GHz
            5180 => Some(36),
            5200 => Some(40),
            5220 => Some(44),
            5240 => Some(48),
            5260 => Some(52),
            5280 => Some(56),
            5300 => Some(60),
            5320 => Some(64),
            5500 => Some(100),
            5520 => Some(104),
            5540 => Some(108),
            5560 => Some(112),
            5580 => Some(116),
            5600 => Some(120),
            5620 => Some(124),
            5640 => Some(128),
            5660 => Some(132),
            5680 => Some(136),
            5700 => Some(140),
            5720 => Some(144),
            5745 => Some(149),
            5765 => Some(153),
            5785 => Some(157),
            5805 => Some(161),
            5825 => Some(165),
            _ => None,
        }
    }
}
