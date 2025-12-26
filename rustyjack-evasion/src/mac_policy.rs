//! MAC randomization policy engine
//!
//! Models behavior from common network managers:
//! - wpa_supplicant: pre-association vs association MAC policies
//! - NetworkManager: random vs stable per-connection MACs
//! - iwd: address randomization off/once/always
//! - systemd-networkd: random vs persistent per-interface MACs

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::error::{EvasionError, Result};
use crate::mac::{MacAddress, MacManager, MacState};
use crate::vendor::VendorOui;

/// Stage where a MAC policy is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacStage {
    /// Pre-association (scanning / probing).
    PreAssoc,
    /// Association (actual connection).
    Assoc,
}

/// MAC randomization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacMode {
    /// Do not change the MAC address.
    Off,
    /// Randomize every time policy is applied.
    Random,
    /// Randomize once per boot/session.
    RandomOnce,
    /// Stable random (deterministic) using a persistent secret.
    Stable,
}

/// Scope used for stable randomization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StableScope {
    /// Stable per SSID (NetworkManager / wpa_supplicant style).
    Ssid,
    /// Stable per interface (systemd-networkd style).
    Interface,
    /// Stable per SSID + interface (more specific).
    SsidAndInterface,
}

/// Vendor/OUI policy for generated MACs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VendorPolicy {
    /// Fully random locally administered MAC.
    None,
    /// Preserve current interface OUI (locally administered).
    PreserveCurrent,
    /// Use a specific vendor OUI (locally administered).
    VendorName(String),
}

/// MAC policy configuration persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacPolicyConfig {
    /// MAC mode for association (connection).
    pub assoc_mode: MacMode,
    /// MAC mode for pre-association (scan/probe).
    pub preassoc_mode: MacMode,
    /// Scope for stable randomization.
    pub stable_scope: StableScope,
    /// Vendor policy for generated MACs.
    pub vendor_policy: VendorPolicy,
    /// Lifetime in seconds for stable MAC rotation (wpa_supplicant-style).
    /// If None, stable MACs do not rotate.
    pub lifetime_secs: Option<u64>,
    /// SSID or interface exceptions where MAC should not change.
    pub exceptions: Vec<String>,
}

impl Default for MacPolicyConfig {
    fn default() -> Self {
        Self {
            assoc_mode: MacMode::Off,
            preassoc_mode: MacMode::Off,
            stable_scope: StableScope::Ssid,
            vendor_policy: VendorPolicy::PreserveCurrent,
            lifetime_secs: None,
            exceptions: Vec::new(),
        }
    }
}

impl MacPolicyConfig {
    /// Load policy from disk.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .map_err(|e| EvasionError::Config(format!("Failed to read {}: {}", path.display(), e)))?;
        serde_json::from_str(&raw)
            .map_err(|e| EvasionError::Config(format!("Failed to parse {}: {}", path.display(), e)))
    }

    /// Save policy to disk.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be written.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| EvasionError::Config(format!("Failed to serialize policy: {}", e)))?;
        fs::write(path, json)
            .map_err(|e| EvasionError::Config(format!("Failed to write {}: {}", path.display(), e)))
    }
}

/// MAC policy engine with stable secret and per-boot cache.
pub struct MacPolicyEngine {
    config: MacPolicyConfig,
    seed: [u8; 32],
    once_cache: HashMap<String, MacAddress>,
    manager: MacManager,
}

impl MacPolicyEngine {
    /// Initialize a policy engine with persistent seed.
    ///
    /// `root` is used to store/read the seed at `wifi/mac_seed`.
    pub fn new(root: &Path, config: MacPolicyConfig) -> Result<Self> {
        let seed_path = root.join("wifi").join("mac_seed");
        let seed = load_or_create_seed(&seed_path)?;
        let mut manager = MacManager::new()?;
        manager.set_auto_restore(false);
        Ok(Self {
            config,
            seed,
            once_cache: HashMap::new(),
            manager,
        })
    }

    /// Apply MAC policy for a specific stage.
    ///
    /// Returns `Ok(None)` if no change is needed.
    pub fn apply(
        &mut self,
        stage: MacStage,
        interface: &str,
        ssid: Option<&str>,
    ) -> Result<Option<MacState>> {
        if interface.trim().is_empty() {
            return Err(EvasionError::Config("interface cannot be empty".to_string()));
        }

        if self.is_exception(interface, ssid) {
            log::info!(
                "[MAC_POLICY] Skipping randomization for {} (exception match)",
                interface
            );
            return Ok(None);
        }

        let mode = match stage {
            MacStage::PreAssoc => self.config.preassoc_mode,
            MacStage::Assoc => self.config.assoc_mode,
        };

        if mode == MacMode::Off {
            return Ok(None);
        }

        let current = self.manager.get_mac(interface)?;
        let target = self.generate_mac(mode, interface, ssid, &current)?;

        if current == target {
            return Ok(None);
        }

        let state = self.manager.set_mac(interface, &target)?;
        log::info!(
            "[MAC_POLICY] {} {}: {} -> {}",
            match stage {
                MacStage::PreAssoc => "preassoc",
                MacStage::Assoc => "assoc",
            },
            interface,
            state.original_mac,
            state.current_mac
        );
        Ok(Some(state))
    }

    fn generate_mac(
        &mut self,
        mode: MacMode,
        interface: &str,
        ssid: Option<&str>,
        current: &MacAddress,
    ) -> Result<MacAddress> {
        let vendor_oui = self.vendor_oui(current)?;
        match mode {
            MacMode::Off => Ok(current.clone()),
            MacMode::Random => Ok(random_mac(vendor_oui)?),
            MacMode::RandomOnce => {
                let key = format!("once:{}", interface);
                if let Some(mac) = self.once_cache.get(&key) {
                    return Ok(mac.clone());
                }
                let mac = random_mac(vendor_oui)?;
                self.once_cache.insert(key, mac.clone());
                Ok(mac)
            }
            MacMode::Stable => Ok(stable_mac(
                &self.seed,
                self.config.stable_scope,
                interface,
                ssid,
                self.config.lifetime_secs,
                vendor_oui,
            )?),
        }
    }

    fn vendor_oui(&self, current: &MacAddress) -> Result<Option<[u8; 3]>> {
        match &self.config.vendor_policy {
            VendorPolicy::None => Ok(None),
            VendorPolicy::PreserveCurrent => Ok(Some(current.oui())),
            VendorPolicy::VendorName(name) => VendorOui::from_name(name)
                .map(|v| Some(v.oui))
                .ok_or_else(|| EvasionError::Config(format!("Unknown vendor: {}", name))),
        }
    }

    fn is_exception(&self, interface: &str, ssid: Option<&str>) -> bool {
        let iface_lc = interface.to_ascii_lowercase();
        let ssid_lc = ssid.unwrap_or("").to_ascii_lowercase();
        self.config.exceptions.iter().any(|item| {
            let entry = item.to_ascii_lowercase();
            if let Some(name) = entry.strip_prefix("iface:") {
                return name.trim() == iface_lc;
            }
            if let Some(name) = entry.strip_prefix("ssid:") {
                return name.trim() == ssid_lc;
            }
            entry == iface_lc || (!ssid_lc.is_empty() && entry == ssid_lc)
        })
    }
}

fn random_mac(vendor_oui: Option<[u8; 3]>) -> Result<MacAddress> {
    match vendor_oui {
        Some(oui) => MacAddress::random_with_oui(oui),
        None => MacAddress::random(),
    }
}

fn stable_mac(
    seed: &[u8; 32],
    scope: StableScope,
    interface: &str,
    ssid: Option<&str>,
    lifetime_secs: Option<u64>,
    vendor_oui: Option<[u8; 3]>,
) -> Result<MacAddress> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let epoch = lifetime_secs
        .filter(|secs| *secs > 0)
        .map(|secs| now / secs)
        .unwrap_or(0);

    let ssid = ssid.unwrap_or("");
    let context = match scope {
        StableScope::Ssid => {
            if ssid.is_empty() {
                format!("iface:{}:{}", interface, epoch)
            } else {
                format!("ssid:{}:{}", ssid, epoch)
            }
        }
        StableScope::Interface => format!("iface:{}:{}", interface, epoch),
        StableScope::SsidAndInterface => {
            if ssid.is_empty() {
                format!("iface:{}:{}", interface, epoch)
            } else {
                format!("ssid:{}|iface:{}:{}", ssid, interface, epoch)
            }
        }
    };

    let mut hasher = Hasher::new_keyed(seed);
    hasher.update(context.as_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    let mac = if let Some(oui) = vendor_oui {
        let mut out = [0u8; 6];
        out[0] = oui[0];
        out[1] = oui[1];
        out[2] = oui[2];
        out[3] = bytes[0];
        out[4] = bytes[1];
        out[5] = bytes[2];
        MacAddress::new(out)
    } else {
        MacAddress::new([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
    };

    let mut raw = *mac.as_bytes();
    raw[0] = (raw[0] | 0x02) & 0xFE;
    Ok(MacAddress::new(raw))
}

fn load_or_create_seed(path: &Path) -> Result<[u8; 32]> {
    if let Ok(data) = fs::read(path) {
        if data.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&data);
            return Ok(seed);
        }
        return Err(EvasionError::Config(format!(
            "Invalid MAC seed length in {}",
            path.display()
        )));
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| EvasionError::RngError(format!("Failed to create MAC seed: {}", e)))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(EvasionError::Io)?;
        std::io::Write::write_all(&mut file, &seed).map_err(EvasionError::Io)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, &seed).map_err(EvasionError::Io)?;
    }

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_mac_is_deterministic() {
        let seed = [0x11u8; 32];
        let mac1 = stable_mac(
            &seed,
            StableScope::Ssid,
            "wlan0",
            Some("testnet"),
            None,
            None,
        )
        .unwrap();
        let mac2 = stable_mac(
            &seed,
            StableScope::Ssid,
            "wlan0",
            Some("testnet"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(mac1, mac2);
    }
}
