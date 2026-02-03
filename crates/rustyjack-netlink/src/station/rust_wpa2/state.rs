use aes::cipher::{BlockEncrypt, KeyInit};
use rand::{rngs::OsRng, RngCore};

use crate::error::{NetlinkError, Result};

use super::keys::{compute_mic, derive_ptk};
use super::l2::EapolSocket;
use super::nl80211_keys::{install_group_key, install_pairwise_key};
use super::rsn::build_basic_rsn_ie;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    Associated,
    Msg1,
    Msg2,
    Msg3,
    Msg4,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct HandshakeCtx {
    pub ssid: String,
    pub bssid: [u8; 6],
    pub sta: [u8; 6],
    pub pmk: [u8; 32],
    pub ifindex: i32,
    pub ptk: Option<[u8; 64]>,
    pub gtk: Option<Vec<u8>>,
}

pub fn run_handshake(
    ctx: &mut HandshakeCtx,
    sock: &EapolSocket,
    timeout: std::time::Duration,
) -> Result<()> {
    let m1 = wait_for_message(sock, timeout, |frame| {
        is_m1(frame) && (ctx.bssid == [0u8; 6] || frame.src == ctx.bssid)
    })?;
    if ctx.bssid == [0u8; 6] {
        ctx.bssid = m1.src;
    }
    let anonce = m1.nonce;

    let mut snonce = [0u8; 32];
    OsRng.fill_bytes(&mut snonce);
    let ptk = derive_ptk(&ctx.pmk, &ctx.bssid, &ctx.sta, &anonce, &snonce);
    ctx.ptk = Some(ptk);

    let m2 = build_m2(ctx, &snonce, m1.replay_counter)?;
    sock.send(&m2)?;

    let m3 = wait_for_message(sock, timeout, |frame| {
        is_m3(frame) && frame.src == ctx.bssid
    })?;
    verify_mic(&m3, &ptk)?;

    let (gtk_id, gtk) = extract_gtk(&m3, &ptk)?;
    install_pairwise_key(ctx.ifindex, ctx.bssid, &ptk[32..48])?;
    install_group_key(ctx.ifindex, gtk_id, &gtk)?;

    ctx.gtk = Some(gtk);

    let m4 = build_m4(ctx, m3.replay_counter)?;
    sock.send(&m4)?;

    Ok(())
}

const ETHERTYPE_EAPOL: u16 = 0x888e;
const EAPOL_TYPE_KEY: u8 = 3;
const WPA2_KEY_DESCRIPTOR: u8 = 2;
const WPA2_KEY_INFO_KEY_MIC: u16 = 1 << 8;
const WPA2_KEY_INFO_KEY_ACK: u16 = 1 << 7;
const WPA2_KEY_INFO_INSTALL: u16 = 1 << 6;
const WPA2_KEY_INFO_PAIRWISE: u16 = 1 << 3;
const WPA2_KEY_INFO_SECURE: u16 = 1 << 9;
const WPA2_KEY_INFO_VERSION: u16 = 2;

#[derive(Debug, Clone)]
struct ParsedEapolKey {
    src: [u8; 6],
    key_info: u16,
    replay_counter: u64,
    nonce: [u8; 32],
    mic: [u8; 16],
    key_data: Vec<u8>,
    frame: Vec<u8>,
}

fn wait_for_message<F>(
    sock: &EapolSocket,
    timeout: std::time::Duration,
    predicate: F,
) -> Result<ParsedEapolKey>
where
    F: Fn(&ParsedEapolKey) -> bool,
{
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 2048];
    loop {
        if start.elapsed() > timeout {
            return Err(NetlinkError::Timeout {
                operation: "WPA2 handshake".to_string(),
                timeout_secs: timeout.as_secs(),
            });
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        let len = match sock.recv(&mut buf, remaining) {
            Ok(len) => len,
            Err(NetlinkError::Timeout { .. }) => continue,
            Err(err) => return Err(err),
        };
        let frame = &buf[..len];
        let parsed = match parse_eapol_key(frame) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        if predicate(&parsed) {
            return Ok(parsed);
        }
    }
}

fn parse_eapol_key(frame: &[u8]) -> Result<ParsedEapolKey> {
    if frame.len() < 113 {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "frame too short".to_string(),
        });
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_EAPOL {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "not EAPOL".to_string(),
        });
    }
    if frame[15] != EAPOL_TYPE_KEY {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "not EAPOL-Key".to_string(),
        });
    }
    if frame[18] != WPA2_KEY_DESCRIPTOR {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "unsupported key descriptor".to_string(),
        });
    }

    let key_info = u16::from_be_bytes([frame[19], frame[20]]);
    let replay_counter = u64::from_be_bytes([
        frame[23], frame[24], frame[25], frame[26], frame[27], frame[28], frame[29], frame[30],
    ]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&frame[31..63]);

    let mut mic = [0u8; 16];
    mic.copy_from_slice(&frame[95..111]);

    let key_data_len = u16::from_be_bytes([frame[111], frame[112]]) as usize;
    let key_data_start = 113usize;
    let key_data_end = key_data_start.saturating_add(key_data_len);
    if frame.len() < key_data_end {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "key data truncated".to_string(),
        });
    }
    let key_data = frame[key_data_start..key_data_end].to_vec();

    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);

    Ok(ParsedEapolKey {
        src,
        key_info,
        replay_counter,
        nonce,
        mic,
        key_data,
        frame: frame.to_vec(),
    })
}

fn is_m1(frame: &ParsedEapolKey) -> bool {
    let mic_set = (frame.key_info & WPA2_KEY_INFO_KEY_MIC) != 0;
    let ack_set = (frame.key_info & WPA2_KEY_INFO_KEY_ACK) != 0;
    let pairwise = (frame.key_info & WPA2_KEY_INFO_PAIRWISE) != 0;
    ack_set && !mic_set && pairwise
}

fn is_m3(frame: &ParsedEapolKey) -> bool {
    let mic_set = (frame.key_info & WPA2_KEY_INFO_KEY_MIC) != 0;
    let ack_set = (frame.key_info & WPA2_KEY_INFO_KEY_ACK) != 0;
    let install_set = (frame.key_info & WPA2_KEY_INFO_INSTALL) != 0;
    let pairwise = (frame.key_info & WPA2_KEY_INFO_PAIRWISE) != 0;
    let secure_set = (frame.key_info & WPA2_KEY_INFO_SECURE) != 0;
    ack_set && mic_set && install_set && pairwise && secure_set
}

fn build_m2(ctx: &HandshakeCtx, snonce: &[u8; 32], replay_counter: u64) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ctx.bssid); // DA
    frame.extend_from_slice(&ctx.sta); // SA
    frame.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());

    frame.push(2);
    frame.push(EAPOL_TYPE_KEY);
    frame.extend_from_slice(&0u16.to_be_bytes());

    frame.push(WPA2_KEY_DESCRIPTOR);
    let key_info = WPA2_KEY_INFO_VERSION | WPA2_KEY_INFO_KEY_MIC | WPA2_KEY_INFO_PAIRWISE;
    frame.extend_from_slice(&key_info.to_be_bytes());
    frame.extend_from_slice(&16u16.to_be_bytes());
    frame.extend_from_slice(&replay_counter.to_be_bytes());
    frame.extend_from_slice(snonce);
    frame.extend_from_slice(&[0u8; 16]);
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&[0u8; 16]);

    let rsn = build_basic_rsn_ie();
    frame.extend_from_slice(&(rsn.len() as u16).to_be_bytes());
    frame.extend_from_slice(&rsn);

    let eapol_len = (frame.len() - 14 - 4) as u16;
    frame[16] = (eapol_len >> 8) as u8;
    frame[17] = (eapol_len & 0xff) as u8;

    let mut mic_frame = frame.clone();
    mic_frame[95..111].fill(0);
    let ptk = ctx
        .ptk
        .ok_or_else(|| NetlinkError::OperationFailed("PTK missing for M2".to_string()))?;
    let mic = compute_mic(&mic_frame[14..], &ptk[..16])?;
    frame[95..111].copy_from_slice(&mic);
    Ok(frame)
}

fn build_m4(ctx: &HandshakeCtx, replay_counter: u64) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ctx.bssid); // DA
    frame.extend_from_slice(&ctx.sta); // SA
    frame.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());

    frame.push(2);
    frame.push(EAPOL_TYPE_KEY);
    frame.extend_from_slice(&0u16.to_be_bytes());

    frame.push(WPA2_KEY_DESCRIPTOR);
    let key_info = WPA2_KEY_INFO_VERSION
        | WPA2_KEY_INFO_KEY_MIC
        | WPA2_KEY_INFO_PAIRWISE
        | WPA2_KEY_INFO_SECURE;
    frame.extend_from_slice(&key_info.to_be_bytes());
    frame.extend_from_slice(&16u16.to_be_bytes());
    frame.extend_from_slice(&replay_counter.to_be_bytes());
    frame.extend_from_slice(&[0u8; 32]);
    frame.extend_from_slice(&[0u8; 16]);
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&[0u8; 16]);
    frame.extend_from_slice(&0u16.to_be_bytes());

    let eapol_len = (frame.len() - 14 - 4) as u16;
    frame[16] = (eapol_len >> 8) as u8;
    frame[17] = (eapol_len & 0xff) as u8;

    let mut mic_frame = frame.clone();
    mic_frame[95..111].fill(0);
    let ptk = ctx
        .ptk
        .ok_or_else(|| NetlinkError::OperationFailed("PTK missing for M4".to_string()))?;
    let mic = compute_mic(&mic_frame[14..], &ptk[..16])?;
    frame[95..111].copy_from_slice(&mic);
    Ok(frame)
}

fn verify_mic(frame: &ParsedEapolKey, ptk: &[u8; 64]) -> Result<()> {
    let mut data = frame.frame.clone();
    if data.len() < 111 {
        return Err(NetlinkError::ParseError {
            what: "EAPOL".to_string(),
            reason: "frame too short for MIC".to_string(),
        });
    }
    data[95..111].fill(0);
    let calc = compute_mic(&data[14..], &ptk[..16])?;
    if calc != frame.mic {
        return Err(NetlinkError::OperationFailed(
            "EAPOL MIC validation failed".to_string(),
        ));
    }
    Ok(())
}

fn extract_gtk(frame: &ParsedEapolKey, ptk: &[u8; 64]) -> Result<(u8, Vec<u8>)> {
    if frame.key_data.is_empty() {
        return Err(NetlinkError::OperationFailed(
            "No key data in M3".to_string(),
        ));
    }

    let key_data = match parse_kde(&frame.key_data) {
        Some(kde) => kde,
        None => {
            let decrypted = unwrap_key_data(&frame.key_data, &ptk[16..32])?;
            parse_kde(&decrypted).ok_or_else(|| {
                NetlinkError::OperationFailed("Failed to parse GTK KDE".to_string())
            })?
        }
    };

    Ok(key_data)
}

fn parse_kde(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut idx = 0usize;
    while idx + 2 < data.len() {
        let id = data[idx];
        let len = data[idx + 1] as usize;
        let start = idx + 2;
        let end = start + len;
        if end > data.len() {
            return None;
        }
        if id == 0xdd && len >= 6 {
            let oui = &data[start..start + 3];
            let dtype = data[start + 3];
            if oui == [0x00, 0x0f, 0xac] && dtype == 0x01 && len >= 8 {
                let key_info = data[start + 4];
                let key_id = key_info & 0x03;
                let gtk = data[start + 6..end].to_vec();
                return Some((key_id, gtk));
            }
        }
        idx = end;
    }
    None
}

fn unwrap_key_data(encrypted: &[u8], kek: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 16 || encrypted.len() % 8 != 0 {
        return Err(NetlinkError::OperationFailed(
            "Invalid encrypted key data length".to_string(),
        ));
    }
    if kek.len() != 16 {
        return Err(NetlinkError::OperationFailed(
            "KEK must be 16 bytes".to_string(),
        ));
    }

    let n = encrypted.len() / 8 - 1;
    let mut a = u64::from_be_bytes(encrypted[0..8].try_into().unwrap());
    let mut r = Vec::with_capacity(n);
    for i in 0..n {
        let start = 8 + i * 8;
        let mut block = [0u8; 8];
        block.copy_from_slice(&encrypted[start..start + 8]);
        r.push(block);
    }

    let cipher = aes::Aes128::new_from_slice(kek)
        .map_err(|e| NetlinkError::OperationFailed(format!("AES init failed: {}", e)))?;

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let mut block = [0u8; 16];
            let a_xor = a ^ t;
            block[..8].copy_from_slice(&a_xor.to_be_bytes());
            block[8..].copy_from_slice(&r[i]);
            let mut ga = aes::cipher::generic_array::GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut ga);
            let out = ga.as_slice();
            a = u64::from_be_bytes(out[..8].try_into().unwrap());
            r[i].copy_from_slice(&out[8..16]);
        }
    }

    if a != 0xA6A6A6A6A6A6A6A6 {
        return Err(NetlinkError::OperationFailed(
            "Key unwrap integrity check failed".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(n * 8);
    for block in r {
        out.extend_from_slice(&block);
    }
    Ok(out)
}
