use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

use crate::error::{NetlinkError, Result};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub pmk: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct DeriveInputs {
    pub ssid: String,
    pub psk: String,
}

pub fn derive_key_material(inputs: &DeriveInputs) -> Result<KeyMaterial> {
    let pmk = derive_pmk(&inputs.psk, &inputs.ssid)?;
    Ok(KeyMaterial { pmk })
}

pub fn derive_pmk(passphrase: &str, ssid: &str) -> Result<[u8; 32]> {
    if passphrase.len() < 8 || passphrase.len() > 63 {
        return Err(NetlinkError::InvalidInput(
            "WPA2 passphrase must be 8-63 characters".to_string(),
        ));
    }

    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    Ok(pmk)
}

pub fn derive_ptk(
    pmk: &[u8; 32],
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 64] {
    let mut data = Vec::with_capacity(6 + 6 + 32 + 32);

    if bssid <= sta {
        data.extend_from_slice(bssid);
        data.extend_from_slice(sta);
    } else {
        data.extend_from_slice(sta);
        data.extend_from_slice(bssid);
    }

    if anonce <= snonce {
        data.extend_from_slice(anonce);
        data.extend_from_slice(snonce);
    } else {
        data.extend_from_slice(snonce);
        data.extend_from_slice(anonce);
    }

    let label = b"Pairwise key expansion";
    let mut ptk = [0u8; 64];
    let mut out = Vec::new();
    let mut counter = 0u8;
    while out.len() < 64 {
        let mut hmac = match HmacSha1::new_from_slice(pmk) {
            Ok(hmac) => hmac,
            Err(_) => {
                return ptk;
            }
        };
        hmac.update(label);
        hmac.update(&[0u8]);
        hmac.update(&data);
        hmac.update(&[counter]);
        out.extend_from_slice(&hmac.finalize().into_bytes());
        counter = counter.wrapping_add(1);
    }
    ptk.copy_from_slice(&out[..64]);
    ptk
}

pub fn compute_mic(frame: &[u8], kck: &[u8]) -> Result<[u8; 16]> {
    let mut h = HmacSha1::new_from_slice(kck)
        .map_err(|e| NetlinkError::OperationFailed(format!("HMAC init failed: {}", e)))?;
    h.update(frame);
    let digest = h.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}
