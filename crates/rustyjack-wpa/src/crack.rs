//! Native WPA password cracker.
//!
//! Crack WPA/WPA2 handshakes directly on the device without external tools.
//! This is slow compared to GPU-based crackers but useful for:
//! - Quick dictionary attacks with small wordlists
//! - PIN/numeric password attempts
//! - Verification of captured handshakes
//!
//! ## Performance
//! On a Pi Zero 2 W, expect ~50-100 passwords/second.
//! For serious cracking, export to hashcat format and use a proper cracking rig.
//!
//! ## Supported attacks
//! - Dictionary attack (wordlist)
//! - Numeric PIN brute force (8 digits)
//! - Common patterns (Password1, etc.)

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Result, WpaError};
use crate::handshake::HandshakeExport;

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Cracker configuration.
#[derive(Debug, Clone)]
pub struct CrackerConfig {
    /// Number of threads to use.
    pub threads: usize,
    /// Report progress every N attempts.
    pub progress_interval: u64,
    /// Stop after this many attempts (0 = unlimited).
    pub max_attempts: u64,
    /// Yield to OS every N attempts to prevent thermal throttle (0 = no throttle).
    pub throttle_interval: u64,
}

impl Default for CrackerConfig {
    fn default() -> Self {
        Self {
            threads: 1, // Pi Zero 2 W has 4 cores but limited RAM.
            progress_interval: 1000,
            max_attempts: 0,
            throttle_interval: 50, // Yield every 50 attempts to prevent thermal issues on Pi.
        }
    }
}

/// Cracking progress callback.
pub type ProgressCallback = Box<dyn Fn(CrackProgress) + Send>;

/// Progress information.
#[derive(Debug, Clone)]
pub struct CrackProgress {
    /// Passwords attempted.
    pub attempts: u64,
    /// Current password being tried.
    pub current: String,
    /// Elapsed time.
    pub elapsed: Duration,
    /// Passwords per second.
    pub rate: f32,
    /// Estimated time remaining (if known).
    pub eta: Option<Duration>,
}

/// Crack result.
#[derive(Debug)]
pub enum CrackResult {
    /// Password found.
    Found(String),
    /// Exhausted wordlist/attempts.
    Exhausted { attempts: u64 },
    /// Stopped by user.
    Stopped { attempts: u64 },
}

/// WPA/WPA2 password cracker.
pub struct WpaCracker {
    handshake: HandshakeExport,
    ssid: String,
    config: CrackerConfig,
    stop_flag: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
}

impl WpaCracker {
    /// Create new cracker.
    pub fn new(handshake: HandshakeExport, ssid: &str) -> Self {
        Self {
            handshake,
            ssid: ssid.to_string(),
            config: CrackerConfig::default(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Set configuration.
    pub fn with_config(mut self, config: CrackerConfig) -> Self {
        self.config = config;
        self
    }

    /// Override the stop flag (used for external cancellation).
    pub fn with_stop_flag(mut self, stop_flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = stop_flag;
        self
    }

    /// Stop cracking.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Get a handle to signal stop from another thread.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop_flag.clone()
    }

    /// Get current attempt count.
    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// Crack using a password list with progress callback.
    pub fn crack_passwords_with_progress(
        &mut self,
        passwords: &[String],
        total: Option<u64>,
        mut on_progress: Option<&mut dyn FnMut(CrackProgress)>,
    ) -> Result<CrackResult> {
        let start = Instant::now();
        let total = total.unwrap_or(passwords.len() as u64);
        let progress_interval = self.config.progress_interval.max(1);
        let throttle = self.config.throttle_interval;

        for password in passwords {
            if self.stop_flag.load(Ordering::Relaxed) {
                return Ok(CrackResult::Stopped {
                    attempts: self.attempts(),
                });
            }

            let attempts = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            if self.try_password(password) {
                return Ok(CrackResult::Found(password.clone()));
            }

            // Thermal throttle: yield to OS periodically to prevent overheating.
            if throttle > 0 && attempts % throttle == 0 {
                std::thread::yield_now();
            }

            if let Some(ref mut cb) = on_progress {
                if attempts % progress_interval == 0 || attempts == total {
                    let elapsed = start.elapsed();
                    let rate = if elapsed.as_secs_f32() > 0.0 {
                        attempts as f32 / elapsed.as_secs_f32()
                    } else {
                        0.0
                    };
                    let eta = if rate > 0.0 && total > 0 {
                        let remaining = total.saturating_sub(attempts) as f32 / rate;
                        Some(Duration::from_secs_f32(remaining))
                    } else {
                        None
                    };
                    cb(CrackProgress {
                        attempts,
                        current: password.clone(),
                        elapsed,
                        rate,
                        eta,
                    });
                }
            }
        }

        Ok(CrackResult::Exhausted {
            attempts: self.attempts(),
        })
    }

    /// Crack using wordlist file.
    pub fn crack_wordlist(&mut self, wordlist_path: &Path) -> Result<CrackResult> {
        if !wordlist_path.exists() {
            return Err(WpaError::System(format!(
                "Wordlist not found: {:?}",
                wordlist_path
            )));
        }

        let file = File::open(wordlist_path)
            .map_err(|e| WpaError::System(format!("Failed to open wordlist: {}", e)))?;
        let reader = BufReader::new(file);

        tracing::info!("Starting wordlist attack with {:?}", wordlist_path);

        let start = Instant::now();
        let throttle = self.config.throttle_interval;

        for line in reader.lines() {
            if self.stop_flag.load(Ordering::Relaxed) {
                return Ok(CrackResult::Stopped {
                    attempts: self.attempts.load(Ordering::Relaxed),
                });
            }

            let password = match line {
                Ok(p) => p.trim().to_string(),
                Err(_) => continue,
            };

            // Skip invalid WPA passwords.
            if password.len() < 8 || password.len() > 63 {
                continue;
            }

            if self.try_password(&password) {
                tracing::info!("Password found: {}", password);
                return Ok(CrackResult::Found(password));
            }

            let attempts = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;

            // Thermal throttle: yield to OS periodically to prevent overheating.
            if throttle > 0 && attempts % throttle == 0 {
                std::thread::yield_now();
            }

            if attempts % self.config.progress_interval == 0 {
                let elapsed = start.elapsed();
                let rate = attempts as f32 / elapsed.as_secs_f32();
                tracing::info!(
                    "Progress: {} attempts, {:.1}/s, current: {}",
                    attempts,
                    rate,
                    password
                );
            }

            if self.config.max_attempts > 0 && attempts >= self.config.max_attempts {
                return Ok(CrackResult::Exhausted { attempts });
            }
        }

        Ok(CrackResult::Exhausted {
            attempts: self.attempts.load(Ordering::Relaxed),
        })
    }

    /// Crack using password list (in memory).
    pub fn crack_passwords(&mut self, passwords: &[String]) -> Result<CrackResult> {
        tracing::info!("Starting attack with {} passwords", passwords.len());

        let start = Instant::now();
        let throttle = self.config.throttle_interval;

        for password in passwords {
            if self.stop_flag.load(Ordering::Relaxed) {
                return Ok(CrackResult::Stopped {
                    attempts: self.attempts.load(Ordering::Relaxed),
                });
            }

            // Skip invalid WPA passwords.
            if password.len() < 8 || password.len() > 63 {
                continue;
            }

            if self.try_password(password) {
                return Ok(CrackResult::Found(password.clone()));
            }

            let attempts = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;

            // Thermal throttle: yield to OS periodically to prevent overheating.
            if throttle > 0 && attempts % throttle == 0 {
                std::thread::yield_now();
            }
        }

        tracing::info!(
            "Attack complete: {} attempts in {:.1}s",
            passwords.len(),
            start.elapsed().as_secs_f32()
        );

        Ok(CrackResult::Exhausted {
            attempts: self.attempts.load(Ordering::Relaxed),
        })
    }

    /// Try 8-digit PIN patterns.
    pub fn crack_pins(&mut self) -> Result<CrackResult> {
        tracing::info!("Starting 8-digit PIN attack (0-99999999)");

        let start = Instant::now();
        let throttle = self.config.throttle_interval;

        for i in 0..=99_999_999u32 {
            if self.stop_flag.load(Ordering::Relaxed) {
                return Ok(CrackResult::Stopped {
                    attempts: self.attempts.load(Ordering::Relaxed),
                });
            }

            let password = format!("{:08}", i);

            if self.try_password(&password) {
                return Ok(CrackResult::Found(password));
            }

            let attempts = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;

            // Thermal throttle: yield to OS periodically to prevent overheating.
            if throttle > 0 && attempts % throttle == 0 {
                std::thread::yield_now();
            }

            if attempts % self.config.progress_interval == 0 {
                let elapsed = start.elapsed();
                let rate = attempts as f32 / elapsed.as_secs_f32();
                let remaining = (100_000_000u64 - attempts) as f32 / rate;
                tracing::info!(
                    "PIN Progress: {} / 100000000, {:.1}/s, ETA: {:.0}s, current: {}",
                    attempts,
                    rate,
                    remaining,
                    password
                );
            }
        }

        Ok(CrackResult::Exhausted {
            attempts: self.attempts.load(Ordering::Relaxed),
        })
    }

    /// Try common password patterns.
    pub fn crack_common_patterns(&mut self) -> Result<CrackResult> {
        let mut patterns = Vec::new();

        // Common base words.
        let bases = [
            "password", "Password", "PASSWORD", "admin", "Admin", "ADMIN", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty", "login", "guest", "root",
            "changeme", "secret", "private",
        ];

        // Suffixes.
        let suffixes = [
            "", "1", "12", "123", "1234", "12345", "!", "@", "#", "$", "!!", "123!",
            "2024", "2023", "2022", "2021",
        ];

        // Generate combinations.
        for base in &bases {
            for suffix in &suffixes {
                let password = format!("{}{}", base, suffix);
                if password.len() >= 8 && password.len() <= 63 {
                    patterns.push(password);
                }
            }
        }

        // Add phone patterns (common WiFi passwords).
        for i in 0..=9999u32 {
            patterns.push(format!("1234{:04}", i)); // 12340000-12349999
            patterns.push(format!("0000{:04}", i)); // 00000000-00009999
        }

        tracing::info!(
            "Starting common patterns attack ({} patterns)",
            patterns.len()
        );
        self.crack_passwords(&patterns)
    }

    /// Try a single password.
    fn try_password(&self, password: &str) -> bool {
        // Calculate PMK from password + SSID using PBKDF2-SHA1.
        let pmk = self.calculate_pmk(password);

        // Calculate PTK from PMK.
        let ptk = self.calculate_ptk(&pmk);

        // Calculate MIC using PTK.
        let calculated_mic = self.calculate_mic(&ptk);

        // Compare with captured MIC.
        calculated_mic == self.handshake.mic
    }

    /// Calculate PMK using PBKDF2-SHA1.
    fn calculate_pmk(&self, password: &str) -> [u8; 32] {
        let mut pmk = [0u8; 32];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), self.ssid.as_bytes(), 4096, &mut pmk);
        pmk
    }

    /// Calculate PTK using PRF-512.
    fn calculate_ptk(&self, pmk: &[u8; 32]) -> [u8; 64] {
        // Sort MAC addresses (smaller first).
        let (mac1, mac2) = if self.handshake.client_mac < self.handshake.bssid {
            (self.handshake.client_mac, self.handshake.bssid)
        } else {
            (self.handshake.bssid, self.handshake.client_mac)
        };

        // Sort nonces (smaller first).
        let (nonce1, nonce2) = if self.handshake.snonce < self.handshake.anonce {
            (self.handshake.snonce, self.handshake.anonce)
        } else {
            (self.handshake.anonce, self.handshake.snonce)
        };

        // Build data for PRF.
        let mut data = Vec::with_capacity(76);
        data.extend_from_slice(&mac1); // 6 bytes
        data.extend_from_slice(&mac2); // 6 bytes
        data.extend_from_slice(&nonce1); // 32 bytes
        data.extend_from_slice(&nonce2); // 32 bytes

        // PRF-512 for CCMP (or 384 for TKIP, but we use 512 for KCK+KEK+TK).
        self.prf_512(pmk, b"Pairwise key expansion", &data)
    }

    /// PRF-512 function.
    fn prf_512(&self, key: &[u8], label: &[u8], data: &[u8]) -> [u8; 64] {
        let mut result = [0u8; 64];
        let mut counter = 0u8;
        let mut pos = 0;

        while pos < 64 {
            let mut hmac = HmacSha1::new_from_slice(key).expect("HMAC key size");
            hmac.update(label);
            hmac.update(&[0x00]);
            hmac.update(data);
            hmac.update(&[counter]);

            let output = hmac.finalize().into_bytes();
            let len = std::cmp::min(20, 64 - pos);
            result[pos..pos + len].copy_from_slice(&output[..len]);

            pos += 20;
            counter += 1;
        }

        result
    }

    /// Calculate MIC from PTK.
    fn calculate_mic(&self, ptk: &[u8; 64]) -> [u8; 16] {
        // KCK is first 16 bytes of PTK.
        let kck = &ptk[0..16];

        // Zero out MIC field in EAPOL data.
        let mut eapol = self.handshake.eapol_data.clone();
        if eapol.len() >= 85 {
            eapol[81..97].fill(0);
        }

        // Calculate MIC using HMAC-SHA1 (WPA) or AES-CMAC (WPA2).
        // For simplicity, we use HMAC-SHA1 which works for WPA.
        let mut hmac = HmacSha1::new_from_slice(kck).expect("HMAC key size");
        hmac.update(&eapol);
        let output = hmac.finalize().into_bytes();

        let mut mic = [0u8; 16];
        mic.copy_from_slice(&output[..16]);
        mic
    }
}

/// Generate common passwords for quick testing.
pub fn generate_common_passwords() -> Vec<String> {
    let mut passwords = Vec::new();

    // Top 100 most common passwords.
    let common = [
        "password",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty12",
        "qwertyui",
        "qwerty123",
        "password1",
        "password123",
        "iloveyou",
        "sunshine",
        "princess",
        "admin123",
        "welcome1",
        "monkey12",
        "dragon12",
        "master12",
        "letmein1",
        "trustno1",
        "baseball",
        "football",
        "superman",
        "batman12",
        "whatever",
    ];

    for p in common {
        if p.len() >= 8 {
            passwords.push(p.to_string());
        }
    }

    // Year patterns.
    for year in 2015..=2025 {
        passwords.push(format!("password{}", year));
        passwords.push(format!("Password{}", year));
        passwords.push(format!("{}{}", year, year));
    }

    passwords
}

/// Quick crack attempt - tries common passwords automatically.
/// Returns the password if found, None otherwise.
/// This is called automatically when a handshake is captured.
pub fn quick_crack(handshake: &HandshakeExport, ssid: &str) -> Option<String> {
    tracing::info!("Starting quick crack attempt for SSID: {}", ssid);

    let mut cracker = WpaCracker::new(handshake.clone(), ssid);
    let passwords = generate_common_passwords();

    // Also try SSID-based passwords.
    let mut ssid_passwords = generate_ssid_passwords(ssid);

    // Combine password lists.
    let mut all_passwords = passwords;
    all_passwords.append(&mut ssid_passwords);

    match cracker.crack_passwords(&all_passwords) {
        Ok(CrackResult::Found(password)) => {
            tracing::info!("Quick crack SUCCESS! Password: {}", password);
            Some(password)
        }
        Ok(CrackResult::Exhausted { attempts }) => {
            tracing::info!("Quick crack exhausted {} passwords, no match", attempts);
            None
        }
        Ok(CrackResult::Stopped { .. }) => None,
        Err(e) => {
            tracing::error!("Quick crack error: {}", e);
            None
        }
    }
}

/// Generate passwords based on SSID name.
pub fn generate_ssid_passwords(ssid: &str) -> Vec<String> {
    let mut passwords = Vec::new();
    let ssid_lower = ssid.to_lowercase();
    let ssid_clean: String = ssid.chars().filter(|c| c.is_alphanumeric()).collect();

    // SSID + common suffixes.
    let suffixes = [
        "", "1", "12", "123", "1234", "!", "!!", "123!", "wifi", "pass", "password",
    ];
    for suffix in suffixes {
        let p = format!("{}{}", ssid, suffix);
        if p.len() >= 8 && p.len() <= 63 {
            passwords.push(p);
        }
        let p = format!("{}{}", ssid_lower, suffix);
        if p.len() >= 8 && p.len() <= 63 {
            passwords.push(p);
        }
    }

    // Common patterns with SSID.
    if ssid.len() >= 4 {
        passwords.push(format!("{}1234", ssid_clean));
        passwords.push(format!("{}12345", ssid_clean));
        passwords.push(format!("{}{}", ssid_clean, ssid_clean));
    }

    // Phone number patterns (if SSID contains numbers).
    let digits: String = ssid.chars().filter(|c| c.is_numeric()).collect();
    if digits.len() >= 4 {
        passwords.push(format!("{}0000", digits));
        passwords.push(format!("{}1234", digits));
    }

    passwords
}

/// Auto-crack callback type for integration with capture.
pub type CrackCallback = Box<dyn Fn(&str) + Send>;

/// Crack result for UI display.
#[derive(Debug, Clone)]
pub struct QuickCrackResult {
    /// SSID that was cracked.
    pub ssid: String,
    /// BSSID of the AP.
    pub bssid: String,
    /// Password if found.
    pub password: Option<String>,
    /// Number of attempts made.
    pub attempts: u64,
    /// Time taken.
    pub duration: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_passwords() {
        let passwords = generate_common_passwords();
        assert!(!passwords.is_empty());
        assert!(passwords.iter().all(|p| p.len() >= 8));
    }

    #[test]
    fn test_ssid_passwords() {
        let passwords = generate_ssid_passwords("HomeNetwork");
        assert!(!passwords.is_empty());
        assert!(passwords.contains(&"HomeNetwork1234".to_string()));
    }

    // Note: Full cracking tests require actual handshake data.
}
