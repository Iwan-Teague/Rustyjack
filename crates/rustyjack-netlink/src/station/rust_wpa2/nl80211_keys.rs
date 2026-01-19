use neli::consts::nl::{NlmF, NlmFFlags};
use neli::consts::socket::NlFamily;
use neli::genl::Genlmsghdr;
use neli::nl::NlPayload;
use neli::nl::Nlmsghdr;
use neli::types::{Buffer, GenlBuffer};
use neli::socket::NlSocketHandle;

use crate::error::{NetlinkError, Result};

const NL80211_GENL_NAME: &str = "nl80211";
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_NEW_KEY: u8 = 26;
const NL80211_CMD_SET_KEY: u8 = 28;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_KEY_DATA: u16 = 13;
const NL80211_ATTR_KEY_IDX: u16 = 10;
const NL80211_ATTR_KEY_CIPHER: u16 = 12;
const NL80211_ATTR_KEY_DEFAULT: u16 = 9;
const NL80211_ATTR_KEY_TYPE: u16 = 33;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_KEYTYPE_GROUP: u8 = 0;
const NL80211_KEYTYPE_PAIRWISE: u8 = 1;
const CIPHER_SUITE_CCMP: u32 = 0x000f_ac_04;

pub fn install_pairwise_key(ifindex: i32, bssid: [u8; 6], key: &[u8]) -> Result<()> {
    let (mut sock, family_id) = nl80211_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &bssid[..]).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_DATA, key).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build key data attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_CIPHER, CIPHER_SUITE_CCMP)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build cipher attr: {}", e))
            })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, 0u32).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build key idx attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key type attr: {}", e))
            })?,
    );

    send_cmd(&mut sock, family_id, NL80211_CMD_NEW_KEY, attrs, "NEW_KEY (pairwise)")?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, 0u32).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build key idx attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_MAC, &bssid[..]).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build MAC attr: {}", e))
        })?,
    );

    send_cmd(&mut sock, family_id, NL80211_CMD_SET_KEY, attrs, "SET_KEY (pairwise)")?;
    Ok(())
}

pub fn install_group_key(ifindex: i32, key_id: u8, key: &[u8]) -> Result<()> {
    let (mut sock, family_id) = nl80211_socket()?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_DATA, key).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build GTK key data attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_CIPHER, CIPHER_SUITE_CCMP)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build cipher attr: {}", e))
            })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, key_id as u32).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build key idx attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP)
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key type attr: {}", e))
            })?,
    );

    send_cmd(&mut sock, family_id, NL80211_CMD_NEW_KEY, attrs, "NEW_KEY (group)")?;

    let mut attrs = GenlBuffer::new();
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_IFINDEX, ifindex).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build ifindex attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_IDX, key_id as u32).map_err(|e| {
            NetlinkError::OperationFailed(format!("Failed to build key idx attr: {}", e))
        })?,
    );
    attrs.push(
        neli::genl::Nlattr::new(false, false, NL80211_ATTR_KEY_DEFAULT, &[] as &[u8])
            .map_err(|e| {
                NetlinkError::OperationFailed(format!("Failed to build key default attr: {}", e))
            })?,
    );

    send_cmd(&mut sock, family_id, NL80211_CMD_SET_KEY, attrs, "SET_KEY (group)")?;
    Ok(())
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
