use crate::error::{NetlinkError, Result};
use neli::{
    consts::{nl::*, socket::*},
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::GenlBuffer,
};

// Re-export commonly used types from neli
use neli::consts::nl::{NlmF, Nlmsg};
use neli::consts::socket::NlFamily;

// Nlmsg type for error checking
const NlmsgErr: u16 = Nlmsg::Error as u16;

const NL80211_GENL_NAME: &str = "nl80211";

// nl80211 commands
const NL80211_CMD_GET_WIPHY: u8 = 1;
const NL80211_CMD_SET_WIPHY: u8 = 2;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_SET_INTERFACE: u8 = 6;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_SET_CHANNEL: u8 = 65;

// nl80211 attributes
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_WIPHY_TX_POWER_SETTING: u16 = 58;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 59;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;

// Interface types
const NL80211_IFTYPE_ADHOC: u32 = 1;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_AP_VLAN: u32 = 4;
const NL80211_IFTYPE_WDS: u32 = 5;
const NL80211_IFTYPE_MONITOR: u32 = 6;
const NL80211_IFTYPE_MESH_POINT: u32 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
const NL80211_IFTYPE_P2P_GO: u32 = 9;
const NL80211_IFTYPE_P2P_DEVICE: u32 = 10;
const NL80211_IFTYPE_OCB: u32 = 11;
const NL80211_IFTYPE_NAN: u32 = 12;

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

/// PHY capabilities
#[derive(Debug, Clone)]
pub struct PhyCapabilities {
    pub wiphy: u32,
    pub name: String,
    pub supported_modes: Vec<InterfaceMode>,
    pub supports_monitor: bool,
    pub supports_ap: bool,
    pub supports_station: bool,
}

/// Wireless netlink manager
pub struct WirelessManager {
    socket: NlSocketHandle,
    family_id: u16,
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
        let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])
            .map_err(|e| NetlinkError::ConnectionFailed(format!("Failed to create nl80211 socket: {}", e)))?;

        let family_id = socket
            .resolve_genl_family(NL80211_GENL_NAME)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to resolve nl80211 family (wireless drivers not loaded?): {}", e)))?;

        Ok(Self { socket, family_id })
    }

    /// Get interface index from name
    fn get_ifindex(&self, interface: &str) -> Result<u32> {
        let interfaces = std::fs::read_to_string("/sys/class/net/".to_string() + interface + "/ifindex")
            .map_err(|e| NetlinkError::InterfaceNotFound { 
                name: format!("Interface '{}' not found: {}", interface, e)
            })?;
        
        interfaces.trim().parse::<u32>()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to parse ifindex for '{}': {}", interface, e)))
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

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_IFTYPE, mode.to_nl80211())
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create iftype attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_INTERFACE, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST, NlmF::ACK],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send set_mode request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive set_mode response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for set_mode".to_string()))?;

        if response.nl_type == NlmsgErr {
            return Err(NetlinkError::OperationFailed(
                format!("Failed to set interface '{}' to {} mode. Interface must be down. Try: ip link set {} down", 
                    interface, mode.to_string(), interface)
            ));
        }

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
        let frequency = Self::channel_to_frequency(channel)
            .ok_or_else(|| NetlinkError::OperationFailed(format!("Invalid channel number: {}", channel)))?;
        
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
    pub fn set_frequency(&mut self, interface: &str, frequency: u32, width: ChannelWidth) -> Result<()> {
        let ifindex = self.get_ifindex(interface)?;

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_WIPHY_FREQ, frequency)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create frequency attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_WIPHY_CHANNEL_TYPE, width.to_nl80211())
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create channel_type attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_WIPHY, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST, NlmF::ACK],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send set_frequency request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive set_frequency response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for set_frequency".to_string()))?;

        if response.nl_type == NlmsgErr {
            return Err(NetlinkError::OperationFailed(
                format!("Failed to set frequency {} MHz on interface '{}'. Frequency may not be supported by hardware.", 
                    frequency, interface)
            ));
        }

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
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_WIPHY_TX_POWER_SETTING, setting_type)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create tx_power_setting attr: {}", e)))?,
        ];

        if let Some(level) = power_level {
            attrs.push(
                Nlattr::new(false, false, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, level)
                    .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create tx_power_level attr: {}", e)))?
            );
        }

        let genlhdr = Genlmsghdr::new(NL80211_CMD_SET_WIPHY, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST, NlmF::ACK],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send set_tx_power request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive set_tx_power response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for set_tx_power".to_string()))?;

        if response.nl_type == NlmsgErr {
            return Err(NetlinkError::OperationFailed(
                format!("Failed to set TX power on interface '{}'. Power level may exceed hardware limits.", interface)
            ));
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
    pub fn create_interface(&mut self, phy_interface: &str, new_name: &str, mode: InterfaceMode) -> Result<()> {
        let ifindex = self.get_ifindex(phy_interface)?;

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_IFNAME, new_name.as_bytes())
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifname attr: {}", e)))?,
            Nlattr::new(false, false, NL80211_ATTR_IFTYPE, mode.to_nl80211())
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create iftype attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_NEW_INTERFACE, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST, NlmF::ACK],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send create_interface request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive create_interface response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for create_interface".to_string()))?;

        if response.nl_type == NlmsgErr {
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

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_DEL_INTERFACE, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST, NlmF::ACK],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send delete_interface request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive delete_interface response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for delete_interface".to_string()))?;

        if response.nl_type == NlmsgErr {
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

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create ifindex attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_GET_INTERFACE, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send get_interface_info request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive get_interface_info response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for get_interface_info".to_string()))?;

        let mut info = WirelessInfo {
            interface: interface.to_string(),
            ifindex,
            wiphy: 0,
            mode: None,
            frequency: None,
            channel: None,
            txpower_mbm: None,
        };

        if let NlPayload::Payload(genlhdr) = response.nl_payload() {
            for attr in genlhdr.attrs.iter() {
                match attr.nla_type.nla_type() {
                    NL80211_ATTR_WIPHY => {
                        if let Ok(wiphy) = attr.get_payload_as::<u32>() {
                            info.wiphy = *wiphy;
                        }
                    }
                    NL80211_ATTR_IFTYPE => {
                        if let Ok(iftype) = attr.get_payload_as::<u32>() {
                            info.mode = InterfaceMode::from_nl80211(*iftype);
                        }
                    }
                    NL80211_ATTR_WIPHY_FREQ => {
                        if let Ok(freq) = attr.get_payload_as::<u32>() {
                            info.frequency = Some(*freq);
                            info.channel = Self::frequency_to_channel(*freq);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(info)
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

        let attrs = vec![
            Nlattr::new(false, false, NL80211_ATTR_WIPHY, info.wiphy)
                .map_err(|e| NetlinkError::OperationFailed(format!("Failed to create wiphy attr: {}", e)))?,
        ];

        let genlhdr = Genlmsghdr::new(NL80211_CMD_GET_WIPHY, 1, GenlBuffer::new_from_vec(attrs));
        let nlhdr = Nlmsghdr::new(
            None,
            self.family_id,
            &[NlmF::REQUEST],
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.socket.send(nlhdr)
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to send get_phy_capabilities request: {}", e)))?;

        let response: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = self.socket.recv()
            .map_err(|e| NetlinkError::OperationFailed(format!("Failed to receive get_phy_capabilities response: {}", e)))?
            .ok_or_else(|| NetlinkError::OperationFailed("No response received for get_phy_capabilities".to_string()))?;

        let mut caps = PhyCapabilities {
            wiphy: info.wiphy,
            name: format!("phy{}", info.wiphy),
            supported_modes: Vec::new(),
            supports_monitor: false,
            supports_ap: false,
            supports_station: false,
        };

        if let NlPayload::Payload(genlhdr) = response.nl_payload() {
            for attr in genlhdr.attrs.iter() {
                match attr.nla_type.nla_type() {
                    NL80211_ATTR_WIPHY_NAME => {
                        if let Ok(name) = std::str::from_utf8(attr.payload()) {
                            caps.name = name.trim_end_matches('\0').to_string();
                        }
                    }
                    NL80211_ATTR_SUPPORTED_IFTYPES => {
                        // Parse nested attributes for supported interface types
                        // This is simplified - real parsing would be more complex
                        caps.supports_monitor = true; // Assume support for now
                        caps.supports_ap = true;
                        caps.supports_station = true;
                    }
                    _ => {}
                }
            }
        }

        Ok(caps)
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
