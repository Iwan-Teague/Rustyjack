use crate::error::{NetlinkError, Result};

#[derive(Debug, Clone)]
pub struct RsnInfo {
    pub group_cipher: String,
    pub pairwise_ciphers: Vec<String>,
    pub akms: Vec<String>,
    pub caps: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ChosenRsnProfile {
    pub group_cipher: String,
    pub pairwise_cipher: String,
    pub akm: String,
}

pub fn build_basic_rsn_ie() -> Vec<u8> {
    let mut ie = Vec::new();
    ie.push(0x30);
    ie.push(0);
    ie.extend_from_slice(&0x0001u16.to_le_bytes());
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
    ie.extend_from_slice(&1u16.to_le_bytes());
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
    ie.extend_from_slice(&1u16.to_le_bytes());
    ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x02]);
    ie.extend_from_slice(&0u16.to_le_bytes());
    ie.extend_from_slice(&0u16.to_le_bytes());
    let len = ie.len() - 2;
    ie[1] = len as u8;
    ie
}

pub fn parse_rsn_ie(bytes: &[u8]) -> Result<RsnInfo> {
    let mut offset = 0usize;
    if bytes.len() >= 2 && bytes[0] == 0x30 {
        let len = bytes[1] as usize;
        if bytes.len() < len + 2 {
            return Err(NetlinkError::ParseError {
                what: "RSN IE".to_string(),
                reason: "length exceeds buffer".to_string(),
            });
        }
        offset = 2;
    }

    if bytes.len() < offset + 4 {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: "short RSN IE".to_string(),
        });
    }

    let version = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    if version != 1 {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: format!("unsupported RSN version {}", version),
        });
    }
    offset += 2;

    let group_cipher = parse_cipher(&bytes[offset..offset + 4])?;
    offset += 4;

    if bytes.len() < offset + 2 {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: "missing pairwise count".to_string(),
        });
    }
    let pairwise_count = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if bytes.len() < offset + 4 * pairwise_count {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: "pairwise list truncated".to_string(),
        });
    }
    let mut pairwise_ciphers = Vec::new();
    for _ in 0..pairwise_count {
        pairwise_ciphers.push(parse_cipher(&bytes[offset..offset + 4])?);
        offset += 4;
    }

    if bytes.len() < offset + 2 {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: "missing AKM count".to_string(),
        });
    }
    let akm_count = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;

    if bytes.len() < offset + 4 * akm_count {
        return Err(NetlinkError::ParseError {
            what: "RSN IE".to_string(),
            reason: "AKM list truncated".to_string(),
        });
    }
    let mut akms = Vec::new();
    for _ in 0..akm_count {
        akms.push(parse_akm(&bytes[offset..offset + 4])?);
        offset += 4;
    }

    let caps = if bytes.len() >= offset + 2 {
        Some(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
    } else {
        None
    };

    Ok(RsnInfo {
        group_cipher,
        pairwise_ciphers,
        akms,
        caps,
    })
}

pub fn choose_profile(rsn: &RsnInfo) -> Result<ChosenRsnProfile> {
    let group = rsn
        .pairwise_ciphers
        .iter()
        .find(|c| c.as_str() == "CCMP")
        .cloned()
        .unwrap_or_else(|| rsn.group_cipher.clone());
    let pairwise = rsn
        .pairwise_ciphers
        .iter()
        .find(|c| c.as_str() == "CCMP")
        .cloned()
        .ok_or_else(|| NetlinkError::OperationFailed("No CCMP pairwise cipher".to_string()))?;
    let akm = rsn
        .akms
        .iter()
        .find(|a| a.as_str() == "PSK")
        .cloned()
        .ok_or_else(|| NetlinkError::OperationFailed("No PSK AKM".to_string()))?;

    Ok(ChosenRsnProfile {
        group_cipher: group,
        pairwise_cipher: pairwise,
        akm,
    })
}

fn parse_cipher(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 4 {
        return Err(NetlinkError::ParseError {
            what: "RSN cipher".to_string(),
            reason: "short cipher".to_string(),
        });
    }
    if bytes[0..3] != [0x00, 0x0f, 0xac] {
        return Ok(format!(
            "UNKNOWN({:02x}{:02x}{:02x}:{:02x})",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ));
    }
    let cipher = match bytes[3] {
        0x04 => "CCMP",
        0x02 => "TKIP",
        other => return Ok(format!("OUI({:02x})", other)),
    };
    Ok(cipher.to_string())
}

fn parse_akm(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 4 {
        return Err(NetlinkError::ParseError {
            what: "RSN AKM".to_string(),
            reason: "short akm".to_string(),
        });
    }
    if bytes[0..3] != [0x00, 0x0f, 0xac] {
        return Ok(format!(
            "UNKNOWN({:02x}{:02x}{:02x}:{:02x})",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ));
    }
    let akm = match bytes[3] {
        0x02 => "PSK",
        0x01 => "802.1X",
        other => return Ok(format!("OUI({:02x})", other)),
    };
    Ok(akm.to_string())
}
