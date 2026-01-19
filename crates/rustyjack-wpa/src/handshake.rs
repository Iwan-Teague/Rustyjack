//! WPA handshake export types.

use serde::{Deserialize, Serialize};

/// Exported handshake data for cracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeExport {
    /// Access Point BSSID.
    pub bssid: [u8; 6],
    /// Client MAC address.
    pub client_mac: [u8; 6],
    /// ANonce from AP.
    pub anonce: [u8; 32],
    /// SNonce from client.
    pub snonce: [u8; 32],
    /// MIC from message 2.
    pub mic: [u8; 16],
    /// Raw EAPOL data from message 2.
    pub eapol_data: Vec<u8>,
}

impl HandshakeExport {
    /// Convert to hashcat format (22000).
    pub fn to_hashcat_22000(&self) -> String {
        let mic_hex: String = self.mic.iter().map(|b| format!("{:02x}", b)).collect();
        let bssid_hex: String = self.bssid.iter().map(|b| format!("{:02x}", b)).collect();
        let client_hex: String = self
            .client_mac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let anonce_hex: String = self.anonce.iter().map(|b| format!("{:02x}", b)).collect();
        let eapol_hex: String = self
            .eapol_data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        format!(
            "WPA*02*{}*{}*{}**{}*{}*02",
            mic_hex, bssid_hex, client_hex, anonce_hex, eapol_hex
        )
    }
}
