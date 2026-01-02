use std::ffi::CString;

use neli::consts::nl::{NlmF, NlmFFlags};
use neli::consts::socket::NlFamily;
use neli::genl::Genlmsghdr;
use neli::nl::NlPayload;
use neli::nl::Nlmsghdr;
use neli::types::{Buffer, GenlBuffer};
use neli::socket::NlSocketHandle;

use crate::error::{NetlinkError, Result};
use libc;

use super::rsn::build_basic_rsn_ie;

const NL80211_GENL_NAME: &str = "nl80211";
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_CONNECT: u8 = 46;
const NL80211_CMD_DISCONNECT: u8 = 47;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_PRIVACY: u16 = 14;
const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 15;
const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 16;
const NL80211_ATTR_AKM_SUITES: u16 = 17;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WPA_VERSIONS: u16 = 48;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_IE: u16 = 59;

const WPA_VERSION_2: u32 = 2;
const CIPHER_SUITE_CCMP: u32 = 0x000f_ac_04;
const AKM_SUITE_PSK: u32 = 0x000f_ac_02;

pub fn connect(
    interface: &str,
    ssid: &str,
    bssid: Option<[u8; 6]>,
    frequency: Option<u32>,
) -> Result<()> {
    let ifindex = interface_index(interface)?;
    let (mut sock, family_id) = nl80211_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push(neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
        NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
    })?);
    attrs.push(neli::genl::Nlattr::new(false, false, NL80211_ATTR_SSID, ssid.as_bytes())
        .map_err(|e| NetlinkError::OperationFailed(format!("Failed to build SSID attr: {}", e)))?);
    if let Some(bssid) = bssid {
        attrs.push(neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &bssid[..]).map_err(
            |e| NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e)),
        )?);
    }
    if let Some(freq) = frequency {
        attrs.push(
            neli::genl::Nlattr::new(false, false, NL80211_ATTR_WIPHY_FREQ, freq).map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build frequency attr: {}", e))
            })?,
        );
    }

    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_PRIVACY, &[] as &[u8]).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build privacy attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_WPA_VERSIONS, WPA_VERSION_2)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build WPA versions attr: {}", e))
            })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_CIPHER_SUITE_GROUP, CIPHER_SUITE_CCMP)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build group cipher attr: {}", e))
            })?,
    );

    let pairwise = u32_list_bytes(&[CIPHER_SUITE_CCMP]);
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, pairwise)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build pairwise cipher attr: {}", e))
            })?,
    );
    let akm = u32_list_bytes(&[AKM_SUITE_PSK]);
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_AKM_SUITES, akm).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build AKM attr: {}", e))
        })?,
    );
    let rsn_ie = build_basic_rsn_ie();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IE, rsn_ie).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build RSN IE attr: {}", e))
        })?,
    );

    send_cmd(&mut sock, family_id, NL80211_CMD_CONNECT, attrs, "CONNECT")?;
    Ok(())
}

pub fn disconnect(interface: &str) -> Result<()> {
    let ifindex = interface_index(interface)?;
    let (mut sock, family_id) = nl80211_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push(neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
        NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
    })?);

    send_cmd(&mut sock, family_id, NL80211_CMD_DISCONNECT, attrs, "DISCONNECT")?;
    Ok(())
}

pub fn interface_index(interface: &str) -> Result<i32> {
    let cstr = CString::new(interface)
        .map_err(|_| NetlinkError::InvalidInput("Invalid interface name".to_string()))?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        return Err(NetlinkError::InterfaceIndexError {
            interface: interface.to_string(),
            reason: "if_nametoindex returned 0".to_string(),
        });
    }
    Ok(idx as i32)
}

pub fn interface_mac(interface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", interface);
    let data = std::fs::read_to_string(&path).map_err(|e| NetlinkError::MacAddressError {
        interface: interface.to_string(),
        reason: format!("{}", e),
    })?;
    parse_mac(&data)
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(NetlinkError::ParseError {
            what: "MAC address".to_string(),
            reason: format!("invalid format: {}", value.trim()),
        });
    }
    let mut mac = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16).map_err(|e| NetlinkError::ParseError {
            what: "MAC address".to_string(),
            reason: e.to_string(),
        })?;
    }
    Ok(mac)
}

fn nl80211_socket() -> Result<(NlSocketHandle, u16)> {
    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, &[]).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to open nl80211 socket: {}", e))
    })?;
    let family_id = sock.resolve_genl_family(NL80211_GENL_NAME).map_err(|e| {
        NetlinkError::ConnectionFailed(format!("Failed to resolve nl80211 family: {}", e))
    })?;
    Ok((sock, family_id))
}

fn send_cmd(
    sock: &mut NlSocketHandle,
    family_id: u16,
    cmd: u8,
    attrs: GenlBuffer<u16, Buffer>,
    label: &str,
) -> Result<()> {
    let genlhdr = Genlmsghdr::new(cmd, NL80211_GENL_VERSION, attrs);
    let nlhdr = Nlmsghdr::new(
        None,
        family_id,
        NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
        None,
        None,
        NlPayload::Payload(genlhdr),
    );
    sock.send(nlhdr).map_err(|e| {
        NetlinkError::OperationFailed(format!("Failed to send {}: {}", label, e))
    })?;
    Ok(())
}

fn u32_list_bytes(values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for value in values {
        bytes.extend_from_slice(&value.to_ne_bytes());
    }
    bytes
}
