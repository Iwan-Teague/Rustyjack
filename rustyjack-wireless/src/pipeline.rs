//! Attack Pipeline Module
//! 
//! Automated attack sequences that chain multiple techniques
//! to achieve specific objectives with minimal user interaction.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

/// Pipeline objective - what the user wants to achieve
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PipelineObjective {
    /// Get the WiFi password for a specific network
    GetWifiPassword,
    /// Capture as many handshakes as possible from any network
    MassHandshakeCapture,
    /// Gather intelligence on nearby devices and networks
    ReconSweep,
    /// Deny service to a specific network
    DenyService,
    /// Capture credentials via fake AP
    CaptureCredentials,
    /// Full automated pentest
    FullPentest,
}

/// Pipeline stage
#[derive(Debug, Clone)]
pub enum PipelineStage {
    /// Initial reconnaissance
    Recon,
    /// Target selection (automatic or manual)
    TargetSelect,
    /// Preparation (monitor mode, MAC change, etc.)
    Prepare,
    /// Primary attack
    Attack,
    /// Capture/collection
    Capture,
    /// Cracking attempt
    Crack,
    /// Cleanup and restore
    Cleanup,
    /// Completed
    Complete,
    /// Failed with reason
    Failed(String),
}

/// Attack technique that can be used in a pipeline
#[derive(Debug, Clone)]
pub enum AttackTechnique {
    /// Passive scanning
    PassiveScan { duration_secs: u32 },
    /// Active WiFi scan
    ActiveScan { duration_secs: u32 },
    /// Probe request sniffing
    ProbeSniff { duration_secs: u32 },
    /// PMKID capture attempt (no deauth needed)
    PmkidCapture { target_bssid: String, duration_secs: u32 },
    /// Deauthentication attack
    Deauth { target_bssid: String, client: Option<String>, duration_secs: u32 },
    /// Evil Twin AP
    EvilTwin { ssid: String, channel: u8 },
    /// Karma attack
    Karma { duration_secs: u32 },
    /// Handshake capture (passive after deauth)
    HandshakeCapture { target_bssid: String, duration_secs: u32 },
    /// Quick password crack
    QuickCrack { handshake_file: PathBuf },
    /// Dictionary attack
    DictionaryCrack { handshake_file: PathBuf, wordlist: PathBuf },
    /// MAC randomization
    RandomizeMac,
    /// Restore original MAC
    RestoreMac,
    /// Set TX power
    SetTxPower { level: String },
}

/// Result of a single technique
#[derive(Debug, Clone)]
pub struct TechniqueResult {
    pub technique: String,
    pub success: bool,
    pub message: String,
    pub data: serde_json::Value,
    pub duration_secs: u32,
}

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// The objective we're trying to achieve
    pub objective: PipelineObjective,
    /// Target network SSID (if known)
    pub target_ssid: Option<String>,
    /// Target network BSSID (if known)
    pub target_bssid: Option<String>,
    /// Interface to use
    pub interface: String,
    /// Use stealth features (MAC randomization, low TX)
    pub stealth_mode: bool,
    /// Maximum time for entire pipeline (seconds)
    pub max_duration: u32,
    /// Output directory for captures
    pub output_dir: PathBuf,
    /// Path to wordlist for cracking
    pub wordlist: Option<PathBuf>,
    /// Automatically select strongest target if none specified
    pub auto_target: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            objective: PipelineObjective::GetWifiPassword,
            target_ssid: None,
            target_bssid: None,
            interface: "wlan0".to_string(),
            stealth_mode: true,
            max_duration: 600, // 10 minutes
            output_dir: PathBuf::from("/opt/rustyjack/loot/Wireless"),
            wordlist: None,
            auto_target: true,
        }
    }
}

/// Pipeline progress callback
pub type ProgressCallback = Box<dyn Fn(f32, &str, &PipelineStage) + Send>;

/// Overall pipeline result
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub objective: PipelineObjective,
    pub success: bool,
    pub message: String,
    pub stages_completed: Vec<String>,
    pub techniques_used: Vec<TechniqueResult>,
    pub target_ssid: Option<String>,
    pub target_bssid: Option<String>,
    pub password_found: Option<String>,
    pub handshake_file: Option<PathBuf>,
    pub credentials_captured: Vec<String>,
    pub total_duration_secs: u32,
}

/// Attack pipeline executor
pub struct AttackPipeline {
    config: PipelineConfig,
    running: Arc<AtomicBool>,
    current_stage: Arc<Mutex<PipelineStage>>,
    results: Arc<Mutex<Vec<TechniqueResult>>>,
}

impl AttackPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            current_stage: Arc::new(Mutex::new(PipelineStage::Recon)),
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Build the attack sequence for GetWifiPassword objective
    fn build_password_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        // 1. Stealth setup (if enabled)
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RandomizeMac);
            techniques.push(AttackTechnique::SetTxPower { level: "medium".to_string() });
        }
        
        // 2. Initial scan if no target specified
        if self.config.target_bssid.is_none() {
            techniques.push(AttackTechnique::ActiveScan { duration_secs: 15 });
        }
        
        // 3. PMKID attempt first (doesn't require connected clients)
        if let Some(ref bssid) = self.config.target_bssid {
            techniques.push(AttackTechnique::PmkidCapture {
                target_bssid: bssid.clone(),
                duration_secs: 30,
            });
        }
        
        // 4. Probe sniff to find connected clients
        techniques.push(AttackTechnique::ProbeSniff { duration_secs: 20 });
        
        // 5. Deauth attack to force handshake
        if let Some(ref bssid) = self.config.target_bssid {
            techniques.push(AttackTechnique::Deauth {
                target_bssid: bssid.clone(),
                client: None, // Broadcast
                duration_secs: 30,
            });
            
            // 6. Capture handshake after deauth
            techniques.push(AttackTechnique::HandshakeCapture {
                target_bssid: bssid.clone(),
                duration_secs: 60,
            });
        }
        
        // 7. Quick crack attempt
        techniques.push(AttackTechnique::QuickCrack {
            handshake_file: self.config.output_dir.join("handshake.cap"),
        });
        
        // 8. Dictionary attack if quick crack fails and wordlist available
        if let Some(ref wordlist) = self.config.wordlist {
            techniques.push(AttackTechnique::DictionaryCrack {
                handshake_file: self.config.output_dir.join("handshake.cap"),
                wordlist: wordlist.clone(),
            });
        }
        
        // 9. Cleanup
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RestoreMac);
        }
        
        techniques
    }
    
    /// Build pipeline for mass handshake capture
    fn build_mass_capture_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RandomizeMac);
        }
        
        // Scan for all networks
        techniques.push(AttackTechnique::ActiveScan { duration_secs: 30 });
        
        // Long probe sniff
        techniques.push(AttackTechnique::ProbeSniff { duration_secs: 60 });
        
        // PMKID capture (hop channels)
        techniques.push(AttackTechnique::PmkidCapture {
            target_bssid: "".to_string(), // All networks
            duration_secs: 120,
        });
        
        // Multiple deauth rounds (would be per-network in real impl)
        for _ in 0..3 {
            techniques.push(AttackTechnique::Deauth {
                target_bssid: "".to_string(), // Targets selected dynamically
                client: None,
                duration_secs: 30,
            });
            
            techniques.push(AttackTechnique::HandshakeCapture {
                target_bssid: "".to_string(),
                duration_secs: 30,
            });
        }
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RestoreMac);
        }
        
        techniques
    }
    
    /// Build pipeline for reconnaissance
    fn build_recon_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        // Stealth mode for recon
        techniques.push(AttackTechnique::RandomizeMac);
        techniques.push(AttackTechnique::SetTxPower { level: "stealth".to_string() });
        
        // Passive scan only (no transmission)
        techniques.push(AttackTechnique::PassiveScan { duration_secs: 60 });
        
        // Probe sniff (passive)
        techniques.push(AttackTechnique::ProbeSniff { duration_secs: 120 });
        
        // Restore
        techniques.push(AttackTechnique::RestoreMac);
        
        techniques
    }
    
    /// Build pipeline for denial of service
    fn build_dos_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RandomizeMac);
            techniques.push(AttackTechnique::SetTxPower { level: "max".to_string() });
        }
        
        // Scan if needed
        if self.config.target_bssid.is_none() {
            techniques.push(AttackTechnique::ActiveScan { duration_secs: 10 });
        }
        
        // Continuous deauth
        if let Some(ref bssid) = self.config.target_bssid {
            techniques.push(AttackTechnique::Deauth {
                target_bssid: bssid.clone(),
                client: None,
                duration_secs: self.config.max_duration,
            });
        }
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RestoreMac);
        }
        
        techniques
    }
    
    /// Build pipeline for credential capture
    fn build_credential_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RandomizeMac);
        }
        
        // Scan to find networks
        techniques.push(AttackTechnique::ActiveScan { duration_secs: 15 });
        
        // Probe sniff to see what devices want
        techniques.push(AttackTechnique::ProbeSniff { duration_secs: 30 });
        
        // Karma attack - respond to all probes
        techniques.push(AttackTechnique::Karma { duration_secs: 180 });
        
        // If target specified, also run evil twin
        if let Some(ref ssid) = self.config.target_ssid {
            techniques.push(AttackTechnique::EvilTwin {
                ssid: ssid.clone(),
                channel: 6,
            });
        }
        
        if self.config.stealth_mode {
            techniques.push(AttackTechnique::RestoreMac);
        }
        
        techniques
    }
    
    /// Build comprehensive pentest pipeline
    fn build_full_pentest_pipeline(&self) -> Vec<AttackTechnique> {
        let mut techniques = Vec::new();
        
        // Phase 1: Stealth setup
        techniques.push(AttackTechnique::RandomizeMac);
        techniques.push(AttackTechnique::SetTxPower { level: "low".to_string() });
        
        // Phase 2: Passive recon
        techniques.push(AttackTechnique::PassiveScan { duration_secs: 60 });
        techniques.push(AttackTechnique::ProbeSniff { duration_secs: 60 });
        
        // Phase 3: Active scanning
        techniques.push(AttackTechnique::SetTxPower { level: "medium".to_string() });
        techniques.push(AttackTechnique::ActiveScan { duration_secs: 30 });
        
        // Phase 4: PMKID collection
        techniques.push(AttackTechnique::PmkidCapture {
            target_bssid: "".to_string(),
            duration_secs: 90,
        });
        
        // Phase 5: Deauth and handshake
        techniques.push(AttackTechnique::SetTxPower { level: "high".to_string() });
        techniques.push(AttackTechnique::Deauth {
            target_bssid: "".to_string(),
            client: None,
            duration_secs: 60,
        });
        techniques.push(AttackTechnique::HandshakeCapture {
            target_bssid: "".to_string(),
            duration_secs: 60,
        });
        
        // Phase 6: Karma/Evil Twin
        techniques.push(AttackTechnique::Karma { duration_secs: 120 });
        
        // Phase 7: Cracking
        techniques.push(AttackTechnique::QuickCrack {
            handshake_file: self.config.output_dir.join("*.cap"),
        });
        
        // Cleanup
        techniques.push(AttackTechnique::RestoreMac);
        
        techniques
    }
    
    /// Get the technique sequence for the configured objective
    pub fn get_techniques(&self) -> Vec<AttackTechnique> {
        match self.config.objective {
            PipelineObjective::GetWifiPassword => self.build_password_pipeline(),
            PipelineObjective::MassHandshakeCapture => self.build_mass_capture_pipeline(),
            PipelineObjective::ReconSweep => self.build_recon_pipeline(),
            PipelineObjective::DenyService => self.build_dos_pipeline(),
            PipelineObjective::CaptureCredentials => self.build_credential_pipeline(),
            PipelineObjective::FullPentest => self.build_full_pentest_pipeline(),
        }
    }
    
    /// Get description of what the pipeline will do
    pub fn describe(&self) -> Vec<String> {
        let techniques = self.get_techniques();
        let mut steps = Vec::new();
        
        for (i, tech) in techniques.iter().enumerate() {
            let desc = match tech {
                AttackTechnique::PassiveScan { duration_secs } => 
                    format!("Passive scan ({} sec) - listen only", duration_secs),
                AttackTechnique::ActiveScan { duration_secs } =>
                    format!("Active scan ({} sec) - find networks", duration_secs),
                AttackTechnique::ProbeSniff { duration_secs } =>
                    format!("Sniff probes ({} sec) - find clients", duration_secs),
                AttackTechnique::PmkidCapture { duration_secs, .. } =>
                    format!("PMKID capture ({} sec) - no deauth needed", duration_secs),
                AttackTechnique::Deauth { duration_secs, .. } =>
                    format!("Deauth attack ({} sec) - force reconnect", duration_secs),
                AttackTechnique::EvilTwin { ssid, .. } =>
                    format!("Evil Twin AP - fake {}", ssid),
                AttackTechnique::Karma { duration_secs } =>
                    format!("Karma attack ({} sec) - catch all probes", duration_secs),
                AttackTechnique::HandshakeCapture { duration_secs, .. } =>
                    format!("Capture handshake ({} sec)", duration_secs),
                AttackTechnique::QuickCrack { .. } =>
                    "Quick crack - common passwords".to_string(),
                AttackTechnique::DictionaryCrack { .. } =>
                    "Dictionary attack".to_string(),
                AttackTechnique::RandomizeMac =>
                    "Randomize MAC - stealth".to_string(),
                AttackTechnique::RestoreMac =>
                    "Restore original MAC".to_string(),
                AttackTechnique::SetTxPower { level } =>
                    format!("Set TX power: {}", level),
            };
            steps.push(format!("{}. {}", i + 1, desc));
        }
        
        steps
    }
    
    /// Get current stage
    pub fn current_stage(&self) -> PipelineStage {
        self.current_stage.lock().unwrap().clone()
    }
    
    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    
    /// Stop the pipeline
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Pre-defined pipeline configurations
pub mod presets {
    use super::*;
    
    /// Quick password grab - fast attack sequence
    pub fn quick_password(interface: &str, target_ssid: Option<&str>, target_bssid: Option<&str>) -> PipelineConfig {
        PipelineConfig {
            objective: PipelineObjective::GetWifiPassword,
            target_ssid: target_ssid.map(String::from),
            target_bssid: target_bssid.map(String::from),
            interface: interface.to_string(),
            stealth_mode: true,
            max_duration: 300, // 5 minutes
            auto_target: target_bssid.is_none(),
            ..Default::default()
        }
    }
    
    /// Stealth recon - gather intel without detection
    pub fn stealth_recon(interface: &str) -> PipelineConfig {
        PipelineConfig {
            objective: PipelineObjective::ReconSweep,
            interface: interface.to_string(),
            stealth_mode: true,
            max_duration: 180,
            ..Default::default()
        }
    }
    
    /// Mass capture - grab everything possible
    pub fn mass_capture(interface: &str, duration: u32) -> PipelineConfig {
        PipelineConfig {
            objective: PipelineObjective::MassHandshakeCapture,
            interface: interface.to_string(),
            stealth_mode: false,
            max_duration: duration,
            ..Default::default()
        }
    }
    
    /// Credential harvesting - evil twin + karma
    pub fn credential_harvest(interface: &str, target_ssid: Option<&str>) -> PipelineConfig {
        PipelineConfig {
            objective: PipelineObjective::CaptureCredentials,
            target_ssid: target_ssid.map(String::from),
            interface: interface.to_string(),
            stealth_mode: true,
            max_duration: 600,
            ..Default::default()
        }
    }
    
    /// Full automated pentest
    pub fn full_pentest(interface: &str, wordlist: Option<PathBuf>) -> PipelineConfig {
        PipelineConfig {
            objective: PipelineObjective::FullPentest,
            interface: interface.to_string(),
            stealth_mode: true,
            max_duration: 1800, // 30 minutes
            wordlist,
            auto_target: true,
            ..Default::default()
        }
    }
}

/// Get pipeline name for display
pub fn pipeline_name(objective: PipelineObjective) -> &'static str {
    match objective {
        PipelineObjective::GetWifiPassword => "Get WiFi Password",
        PipelineObjective::MassHandshakeCapture => "Mass Handshake Capture",
        PipelineObjective::ReconSweep => "Stealth Recon",
        PipelineObjective::DenyService => "Deny Service (DoS)",
        PipelineObjective::CaptureCredentials => "Capture Credentials",
        PipelineObjective::FullPentest => "Full Pentest",
    }
}

/// Get pipeline description
pub fn pipeline_description(objective: PipelineObjective) -> &'static str {
    match objective {
        PipelineObjective::GetWifiPassword => 
            "Attempts all methods to obtain the WiFi password: PMKID, deauth+handshake, then crack",
        PipelineObjective::MassHandshakeCapture => 
            "Captures handshakes from all visible networks for later cracking",
        PipelineObjective::ReconSweep => 
            "Passive reconnaissance - maps all networks and devices without transmitting",
        PipelineObjective::DenyService => 
            "Continuous deauthentication to deny access to target network",
        PipelineObjective::CaptureCredentials => 
            "Evil Twin + Karma attacks to capture login credentials",
        PipelineObjective::FullPentest => 
            "Complete automated pentest - recon, attack, capture, and crack",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_pipeline_has_required_steps() {
        let config = presets::quick_password("wlan0", Some("TestNetwork"), Some("AA:BB:CC:DD:EE:FF"));
        let pipeline = AttackPipeline::new(config);
        let techniques = pipeline.get_techniques();
        
        // Should include MAC randomization
        assert!(techniques.iter().any(|t| matches!(t, AttackTechnique::RandomizeMac)));
        
        // Should include PMKID
        assert!(techniques.iter().any(|t| matches!(t, AttackTechnique::PmkidCapture { .. })));
        
        // Should include deauth
        assert!(techniques.iter().any(|t| matches!(t, AttackTechnique::Deauth { .. })));
        
        // Should include crack
        assert!(techniques.iter().any(|t| matches!(t, AttackTechnique::QuickCrack { .. })));
    }
    
    #[test]
    fn test_recon_pipeline_is_passive() {
        let config = presets::stealth_recon("wlan0");
        let pipeline = AttackPipeline::new(config);
        let techniques = pipeline.get_techniques();
        
        // Should not include active attacks
        assert!(!techniques.iter().any(|t| matches!(t, AttackTechnique::Deauth { .. })));
        assert!(!techniques.iter().any(|t| matches!(t, AttackTechnique::EvilTwin { .. })));
        
        // Should use stealth power
        assert!(techniques.iter().any(|t| matches!(t, 
            AttackTechnique::SetTxPower { level } if level == "stealth")));
    }
    
    #[test]
    fn test_describe_output() {
        let config = presets::quick_password("wlan0", None, None);
        let pipeline = AttackPipeline::new(config);
        let description = pipeline.describe();
        
        assert!(!description.is_empty());
        assert!(description[0].starts_with("1."));
    }
}
