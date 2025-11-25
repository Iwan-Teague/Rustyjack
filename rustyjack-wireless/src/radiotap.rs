//! Radiotap header handling for packet injection
//!
//! Radiotap is the de-facto standard header prepended to 802.11 frames
//! when injecting or capturing in monitor mode.

use crate::error::{WirelessError, Result};
use byteorder::{LittleEndian, ByteOrder};

/// Radiotap header for injection
/// 
/// This is a minimal header that works with most drivers.
/// More complex headers can specify rate, channel, TX power, etc.
#[derive(Debug, Clone)]
pub struct RadiotapHeader {
    data: Vec<u8>,
}

impl RadiotapHeader {
    /// Minimal radiotap header (8 bytes)
    /// Works with most drivers for injection
    pub fn minimal() -> Self {
        // Radiotap header structure:
        // - Header revision: 0
        // - Header pad: 0
        // - Header length: 8 (little endian u16)
        // - Present flags: 0x00000000 (no fields present)
        Self {
            data: vec![
                0x00,       // Header revision
                0x00,       // Header pad
                0x08, 0x00, // Header length (8 bytes, LE)
                0x00, 0x00, 0x00, 0x00, // Present flags (none)
            ],
        }
    }
    
    /// Radiotap header with rate specification
    /// Useful for ensuring frames are sent at specific rates
    pub fn with_rate(rate: u8) -> Self {
        // Present flags: bit 2 = rate
        // Rate field is 1 byte, in 500kbps units (e.g., 2 = 1Mbps)
        Self {
            data: vec![
                0x00,       // Header revision
                0x00,       // Header pad
                0x09, 0x00, // Header length (9 bytes, LE)
                0x04, 0x00, 0x00, 0x00, // Present flags: rate
                rate,       // Rate value
            ],
        }
    }
    
    /// Radiotap header with TX flags for injection
    pub fn for_injection() -> Self {
        // Present flags: bit 15 = TX flags
        // TX flags: 0x0008 = NO_ACK (don't wait for acknowledgment)
        Self {
            data: vec![
                0x00,       // Header revision
                0x00,       // Header pad
                0x0A, 0x00, // Header length (10 bytes, LE)
                0x00, 0x80, 0x00, 0x00, // Present flags: TX flags (bit 15)
                0x08, 0x00, // TX flags: NO_ACK
            ],
        }
    }
    
    /// Radiotap header with channel and rate (more compatible)
    pub fn with_channel(channel: u8, rate: u8) -> Self {
        let freq = channel_to_frequency(channel);
        
        // Present flags: bit 2 (rate) | bit 3 (channel)
        Self {
            data: vec![
                0x00,       // Header revision
                0x00,       // Header pad
                0x0D, 0x00, // Header length (13 bytes, LE)
                0x0C, 0x00, 0x00, 0x00, // Present flags: rate + channel
                rate,       // Rate
                0x00,       // Padding for alignment
                (freq & 0xFF) as u8,        // Channel frequency low byte
                ((freq >> 8) & 0xFF) as u8, // Channel frequency high byte
                0xA0, 0x00, // Channel flags: 2GHz spectrum + CCK
            ],
        }
    }
    
    /// Get header length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if header is empty (shouldn't happen)
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    /// Parse radiotap header from captured packet
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(WirelessError::InvalidFrame("Radiotap header too short".into()));
        }
        
        // Check version
        if data[0] != 0 {
            return Err(WirelessError::InvalidFrame(
                format!("Unknown radiotap version: {}", data[0])
            ));
        }
        
        // Get header length
        let len = LittleEndian::read_u16(&data[2..4]) as usize;
        
        if data.len() < len {
            return Err(WirelessError::InvalidFrame(
                format!("Radiotap header length {} exceeds data length {}", len, data.len())
            ));
        }
        
        Ok((
            Self { data: data[..len].to_vec() },
            len,
        ))
    }
}

impl Default for RadiotapHeader {
    fn default() -> Self {
        Self::minimal()
    }
}

/// Radiotap present flags
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum RadiotapField {
    /// TSFT (timestamp)
    Tsft = 0,
    /// Flags
    Flags = 1,
    /// Data rate
    Rate = 2,
    /// Channel frequency and flags
    Channel = 3,
    /// FHSS hop set and pattern
    Fhss = 4,
    /// dBm antenna signal
    AntennaSignal = 5,
    /// dBm antenna noise
    AntennaNoise = 6,
    /// Lock quality
    LockQuality = 7,
    /// TX attenuation
    TxAttenuation = 8,
    /// TX attenuation (dB)
    TxAttenuationDb = 9,
    /// TX power (dBm)
    TxPower = 10,
    /// Antenna index
    Antenna = 11,
    /// dB antenna signal
    AntennaSignalDb = 12,
    /// dB antenna noise
    AntennaNoiseDb = 13,
    /// RX flags
    RxFlags = 14,
    /// TX flags
    TxFlags = 15,
    /// MCS (802.11n)
    Mcs = 19,
    /// A-MPDU status
    Ampdu = 20,
    /// VHT (802.11ac)
    Vht = 21,
}

/// TX flags for injection
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum TxFlag {
    /// Fail if not transmitted
    Fail = 0x0001,
    /// Use CTS-to-self protection
    CtsToSelf = 0x0002,
    /// Use RTS/CTS protection
    RtsCts = 0x0004,
    /// Don't expect acknowledgment
    NoAck = 0x0008,
    /// Don't retry if no ACK
    NoSeq = 0x0010,
}

/// Convert WiFi channel number to frequency in MHz
pub fn channel_to_frequency(channel: u8) -> u16 {
    match channel {
        // 2.4 GHz band
        1..=13 => 2407 + (channel as u16) * 5,
        14 => 2484,
        // 5 GHz band (US channels)
        36 | 40 | 44 | 48 => 5000 + (channel as u16) * 5,
        52 | 56 | 60 | 64 => 5000 + (channel as u16) * 5,
        100 | 104 | 108 | 112 | 116 | 120 | 124 | 128 | 132 | 136 | 140 | 144 => {
            5000 + (channel as u16) * 5
        }
        149 | 153 | 157 | 161 | 165 => 5000 + (channel as u16) * 5,
        _ => 2412, // Default to channel 1
    }
}

/// Convert frequency in MHz to WiFi channel number
pub fn frequency_to_channel(freq: u16) -> u8 {
    match freq {
        2412..=2472 => ((freq - 2407) / 5) as u8,
        2484 => 14,
        5180..=5240 => ((freq - 5000) / 5) as u8,
        5260..=5320 => ((freq - 5000) / 5) as u8,
        5500..=5720 => ((freq - 5000) / 5) as u8,
        5745..=5825 => ((freq - 5000) / 5) as u8,
        _ => 1,
    }
}

/// Parsed radiotap information from captured packet
#[derive(Debug, Clone, Default)]
pub struct RadiotapInfo {
    /// Signal strength in dBm
    pub signal_dbm: Option<i8>,
    /// Noise in dBm
    pub noise_dbm: Option<i8>,
    /// Data rate in 500kbps units
    pub rate: Option<u8>,
    /// Channel frequency in MHz
    pub frequency: Option<u16>,
    /// Channel number (derived from frequency)
    pub channel: Option<u8>,
    /// Antenna index
    pub antenna: Option<u8>,
}

impl RadiotapInfo {
    /// Parse radiotap fields from header
    pub fn parse(header: &RadiotapHeader) -> Self {
        let data = header.as_bytes();
        if data.len() < 8 {
            return Self::default();
        }
        
        let present = LittleEndian::read_u32(&data[4..8]);
        let mut info = Self::default();
        let mut offset = 8usize;
        
        // Parse fields in order based on present flags
        // This is simplified - full implementation would handle alignment
        
        if present & (1 << RadiotapField::Rate as u32) != 0 {
            if offset < data.len() {
                info.rate = Some(data[offset]);
                offset += 1;
            }
        }
        
        if present & (1 << RadiotapField::Channel as u32) != 0 {
            // Align to 2 bytes
            offset = (offset + 1) & !1;
            if offset + 2 <= data.len() {
                let freq = LittleEndian::read_u16(&data[offset..offset + 2]);
                info.frequency = Some(freq);
                info.channel = Some(frequency_to_channel(freq));
                offset += 4; // frequency + flags
            }
        }
        
        if present & (1 << RadiotapField::AntennaSignal as u32) != 0 {
            if offset < data.len() {
                info.signal_dbm = Some(data[offset] as i8);
                offset += 1;
            }
        }
        
        if present & (1 << RadiotapField::AntennaNoise as u32) != 0 {
            if offset < data.len() {
                info.noise_dbm = Some(data[offset] as i8);
                offset += 1;
            }
        }
        
        if present & (1 << RadiotapField::Antenna as u32) != 0 {
            if offset < data.len() {
                info.antenna = Some(data[offset]);
            }
        }
        
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_minimal_header() {
        let header = RadiotapHeader::minimal();
        assert_eq!(header.len(), 8);
        assert_eq!(header.as_bytes()[0], 0x00); // Version
        assert_eq!(header.as_bytes()[2], 0x08); // Length low byte
    }
    
    #[test]
    fn test_channel_frequency() {
        assert_eq!(channel_to_frequency(1), 2412);
        assert_eq!(channel_to_frequency(6), 2437);
        assert_eq!(channel_to_frequency(11), 2462);
        assert_eq!(channel_to_frequency(36), 5180);
    }
    
    #[test]
    fn test_frequency_channel() {
        assert_eq!(frequency_to_channel(2412), 1);
        assert_eq!(frequency_to_channel(2437), 6);
        assert_eq!(frequency_to_channel(5180), 36);
    }
}
