//! WiFi channel management
//!
//! Utilities for channel hopping and channel information.

use std::thread;
use std::time::Duration;

use crate::error::Result;
use crate::radiotap::channel_to_frequency;

/// WiFi channel information
#[derive(Debug, Clone, Copy)]
pub struct ChannelInfo {
    /// Channel number
    pub channel: u8,
    /// Frequency in MHz
    pub frequency: u16,
    /// Band (2.4GHz or 5GHz)
    pub band: WifiBand,
    /// Maximum transmit power (if known)
    pub max_power_dbm: Option<i8>,
}

impl ChannelInfo {
    /// Create channel info from channel number
    pub fn from_channel(channel: u8) -> Self {
        let frequency = channel_to_frequency(channel);
        let band = if channel <= 14 {
            WifiBand::Band2_4GHz
        } else {
            WifiBand::Band5GHz
        };

        Self {
            channel,
            frequency,
            band,
            max_power_dbm: None,
        }
    }

    /// Check if channel is in 2.4GHz band
    pub fn is_2_4ghz(&self) -> bool {
        self.band == WifiBand::Band2_4GHz
    }

    /// Check if channel is in 5GHz band
    pub fn is_5ghz(&self) -> bool {
        self.band == WifiBand::Band5GHz
    }
}

/// WiFi frequency band
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiBand {
    /// 2.4 GHz band (channels 1-14)
    Band2_4GHz,
    /// 5 GHz band (channels 36-165)
    Band5GHz,
}

/// Standard 2.4GHz channels (1-14)
pub const CHANNELS_2_4GHZ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Common 2.4GHz channels (non-overlapping)
pub const CHANNELS_2_4GHZ_COMMON: &[u8] = &[1, 6, 11];

/// US 5GHz channels
pub const CHANNELS_5GHZ_US: &[u8] = &[
    36, 40, 44, 48, // UNII-1
    52, 56, 60, 64, // UNII-2A (DFS)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, // UNII-2C (DFS)
    149, 153, 157, 161, 165, // UNII-3
];

/// All common channels (2.4 + 5 GHz)
pub fn all_channels() -> Vec<u8> {
    let mut channels = CHANNELS_2_4GHZ.to_vec();
    channels.extend_from_slice(CHANNELS_5GHZ_US);
    channels
}

/// Channel hopper for scanning
pub struct ChannelHopper {
    interface: String,
    channels: Vec<u8>,
    current_index: usize,
    dwell_time: Duration,
}

impl ChannelHopper {
    /// Create hopper for 2.4GHz channels
    pub fn new_2_4ghz(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            channels: CHANNELS_2_4GHZ_COMMON.to_vec(),
            current_index: 0,
            dwell_time: Duration::from_millis(200),
        }
    }

    /// Create hopper for all 2.4GHz channels
    pub fn new_2_4ghz_all(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            channels: CHANNELS_2_4GHZ.to_vec(),
            current_index: 0,
            dwell_time: Duration::from_millis(100),
        }
    }

    /// Create hopper for 5GHz channels
    pub fn new_5ghz(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            channels: CHANNELS_5GHZ_US.to_vec(),
            current_index: 0,
            dwell_time: Duration::from_millis(200),
        }
    }

    /// Create hopper for all channels
    pub fn new_all(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            channels: all_channels(),
            current_index: 0,
            dwell_time: Duration::from_millis(150),
        }
    }

    /// Create with custom channel list
    pub fn new_custom(interface: &str, channels: Vec<u8>) -> Self {
        Self {
            interface: interface.to_string(),
            channels,
            current_index: 0,
            dwell_time: Duration::from_millis(200),
        }
    }

    /// Set dwell time per channel
    pub fn set_dwell_time(&mut self, dwell: Duration) {
        self.dwell_time = dwell;
    }

    /// Get current channel
    pub fn current_channel(&self) -> u8 {
        self.channels[self.current_index]
    }

    /// Hop to next channel
    pub fn hop(&mut self) -> Result<u8> {
        self.current_index = (self.current_index + 1) % self.channels.len();
        let channel = self.channels[self.current_index];

        crate::nl80211::set_channel_iw(&self.interface, channel)?;

        Ok(channel)
    }

    /// Hop to next channel with dwell delay
    pub fn hop_with_dwell(&mut self) -> Result<u8> {
        thread::sleep(self.dwell_time);
        self.hop()
    }

    /// Hop to specific channel
    pub fn hop_to(&mut self, channel: u8) -> Result<()> {
        if let Some(idx) = self.channels.iter().position(|&c| c == channel) {
            self.current_index = idx;
        }
        crate::nl80211::set_channel_iw(&self.interface, channel)
    }

    /// Run hopping loop for duration
    pub fn run_for(&mut self, duration: Duration) -> Result<Vec<u8>> {
        let mut visited = Vec::new();
        let start = std::time::Instant::now();

        while start.elapsed() < duration {
            let channel = self.hop_with_dwell()?;
            visited.push(channel);
        }

        Ok(visited)
    }

    /// Get all channels in the hopper
    pub fn channels(&self) -> &[u8] {
        &self.channels
    }

    /// Get number of channels
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }
}

/// Simple channel scanner that tries each channel
pub struct ChannelScanner {
    hopper: ChannelHopper,
}

impl ChannelScanner {
    /// Create scanner for 2.4GHz
    pub fn new_2_4ghz(interface: &str) -> Self {
        Self {
            hopper: ChannelHopper::new_2_4ghz(interface),
        }
    }

    /// Create scanner for all channels
    pub fn new_all(interface: &str) -> Self {
        Self {
            hopper: ChannelHopper::new_all(interface),
        }
    }

    /// Scan all channels, executing callback on each
    pub fn scan<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(u8) -> bool, // Return false to stop scanning
    {
        for &channel in self.hopper.channels.clone().iter() {
            self.hopper.hop_to(channel)?;
            thread::sleep(self.hopper.dwell_time);

            if !callback(channel) {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_info() {
        let ch = ChannelInfo::from_channel(6);
        assert_eq!(ch.frequency, 2437);
        assert!(ch.is_2_4ghz());

        let ch5 = ChannelInfo::from_channel(36);
        assert!(ch5.is_5ghz());
    }

    #[test]
    fn test_channel_hopper() {
        let hopper = ChannelHopper::new_2_4ghz("wlan0");
        assert_eq!(hopper.channels(), CHANNELS_2_4GHZ_COMMON);
        assert_eq!(hopper.current_channel(), 1);
    }
}
