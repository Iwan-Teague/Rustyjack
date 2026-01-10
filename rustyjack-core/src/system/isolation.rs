use anyhow::{bail, Context, Result};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::dns::DnsManager;
use super::ops::{ErrorEntry, IsolationOutcome, NetOps};
use super::preference::PreferenceManager;
use super::routing::RouteManager;

static ENFORCEMENT_LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
static HOTSPOT_EXCEPTION: OnceLock<StdMutex<Option<HotspotException>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct HotspotException {
    ap_interface: String,
    upstream_interface: String,
}

pub struct IsolationEngine {
    ops: Arc<dyn NetOps>,
    routes: RouteManager,
    dns: DnsManager,
    prefs: PreferenceManager,
    root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    Connectivity,
    Passive,
}

impl IsolationEngine {
    pub fn new(ops: Arc<dyn NetOps>, root: PathBuf) -> Self {
        let routes = RouteManager::new(Arc::clone(&ops));
        // Always use system resolv.conf - installer ensures it's writable
        let dns = DnsManager::new(PathBuf::from("/etc/resolv.conf"));
        let prefs = PreferenceManager::new(root.clone());

        Self {
            ops,
            routes,
            dns,
            prefs,
            root,
        }
    }

    pub fn enforce(&self) -> Result<IsolationOutcome> {
        self.enforce_with_mode(EnforcementMode::Connectivity)
    }

    pub fn enforce_passive(&self) -> Result<IsolationOutcome> {
        self.enforce_with_mode(EnforcementMode::Passive)
    }

    fn enforce_with_mode(&self, mode: EnforcementMode) -> Result<IsolationOutcome> {
        // Acquire global lock to prevent concurrent enforcement
        let lock = ENFORCEMENT_LOCK.get_or_init(|| StdMutex::new(()));
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        
        info!("Starting network isolation enforcement (lock acquired)");

        // Check for hotspot exception
        if let Some(exc) = get_hotspot_exception() {
            info!("Hotspot exception active: AP={}, upstream={}", exc.ap_interface, exc.upstream_interface);
            return self.enforce_with_hotspot(&exc);
        }

        let mut outcome = IsolationOutcome {
            allowed: Vec::new(),
            blocked: Vec::new(),
            errors: Vec::new(),
        };

        let interfaces = self
            .ops
            .list_interfaces()
            .context("failed to list interfaces")?;

        if interfaces.is_empty() {
            warn!("No network interfaces found");
            return Ok(outcome);
        }

        debug!(
            "Found {} interfaces: {:?}",
            interfaces.len(),
            interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()
        );

        let preferred = self.prefs.get_preferred()?;

        let active = self.select_active_interface(&interfaces, preferred.as_deref())?;

        if let Some(ref iface) = active {
            info!("Selected active interface: {}", iface);
            outcome.allowed.push(iface.clone());
        } else {
            info!("No active interface selected, blocking all");
        }

        for iface in &interfaces {
            if Some(&iface.name) != active.as_ref() {
                match self.block_interface(&iface.name) {
                    Ok(()) => {
                        outcome.blocked.push(iface.name.clone());
                    }
                    Err(e) => {
                        outcome.errors.push(ErrorEntry {
                            interface: iface.name.clone(),
                            message: format!("Failed to block: {}", e),
                        });
                    }
                }
            }
        }

        if let Some(ref iface) = active {
            match self.activate_interface(iface, mode) {
                Ok(()) => {
                    info!("Successfully activated interface: {}", iface);
                }
                Err(e) => {
                    outcome.errors.push(ErrorEntry {
                        interface: iface.clone(),
                        message: format!("Failed to activate: {}", e),
                    });
                    bail!("Failed to activate preferred interface: {}", e);
                }
            }
        }

        self.verify_enforcement(active.as_deref(), mode)?;

        info!(
            "Enforcement complete: allowed={:?}, blocked={:?}, errors={}",
            outcome.allowed,
            outcome.blocked,
            outcome.errors.len()
        );

        Ok(outcome)
    }

    fn enforce_with_hotspot(&self, exc: &HotspotException) -> Result<IsolationOutcome> {
        info!("Enforcing with hotspot exception: AP={}, upstream={}", exc.ap_interface, exc.upstream_interface);
        
        let mut outcome = IsolationOutcome {
            allowed: Vec::new(),
            blocked: Vec::new(),
            errors: Vec::new(),
        };

        let interfaces = self
            .ops
            .list_interfaces()
            .context("failed to list interfaces")?;

        if interfaces.is_empty() {
            warn!("No network interfaces found");
            return Ok(outcome);
        }

        // Verify both hotspot interfaces exist
        let has_ap = interfaces.iter().any(|i| i.name == exc.ap_interface);
        let has_upstream = interfaces.iter().any(|i| i.name == exc.upstream_interface);
        
        if !has_ap {
            bail!("Hotspot AP interface {} not found", exc.ap_interface);
        }
        if !has_upstream {
            bail!("Hotspot upstream interface {} not found", exc.upstream_interface);
        }

        // Block all interfaces except the two hotspot interfaces
        for iface in &interfaces {
            if iface.name != exc.ap_interface && iface.name != exc.upstream_interface {
                match self.block_interface(&iface.name) {
                    Ok(()) => {
                        outcome.blocked.push(iface.name.clone());
                    }
                    Err(e) => {
                        outcome.errors.push(ErrorEntry {
                            interface: iface.name.clone(),
                            message: format!("Failed to block: {}", e),
                        });
                    }
                }
            }
        }

        // Activate upstream interface (normal DHCP + routing)
        info!("Activating upstream interface: {}", exc.upstream_interface);
        match self.activate_interface(&exc.upstream_interface, EnforcementMode::Connectivity) {
            Ok(()) => {
                info!("Successfully activated upstream: {}", exc.upstream_interface);
                outcome.allowed.push(exc.upstream_interface.clone());
            }
            Err(e) => {
                outcome.errors.push(ErrorEntry {
                    interface: exc.upstream_interface.clone(),
                    message: format!("Failed to activate upstream: {}", e),
                });
                bail!("Failed to activate hotspot upstream interface: {}", e);
            }
        }

        // Activate AP interface (no DHCP, manual IP set by hotspot service)
        info!("Activating AP interface: {}", exc.ap_interface);
        match self.activate_ap_interface(&exc.ap_interface) {
            Ok(()) => {
                info!("Successfully activated AP: {}", exc.ap_interface);
                outcome.allowed.push(exc.ap_interface.clone());
            }
            Err(e) => {
                outcome.errors.push(ErrorEntry {
                    interface: exc.ap_interface.clone(),
                    message: format!("Failed to activate AP: {}", e),
                });
                bail!("Failed to activate hotspot AP interface: {}", e);
            }
        }

        info!(
            "Hotspot enforcement complete: allowed={:?}, blocked={:?}, errors={}",
            outcome.allowed,
            outcome.blocked,
            outcome.errors.len()
        );

        Ok(outcome)
    }

    fn activate_ap_interface(&self, iface: &str) -> Result<()> {
        info!("Activating AP interface: {} (no DHCP, manual config)", iface);
        
        // Check interface exists
        if !self.ops.interface_exists(iface) {
            bail!("Interface {} does not exist", iface);
        }

        // Bring interface up
        if let Err(e) = self.ops.bring_up(iface) {
            if !self.ops.interface_exists(iface) {
                bail!("Interface {} disappeared during activation", iface);
            }
            warn!("Interface {} may already be up: {}", iface, e);
        }

        // Unblock rfkill if wireless
        if self.ops.is_wireless(iface) {
            self.ops
                .set_rfkill_block(iface, false)
                .context("failed to unblock rfkill for AP")?;
        }

        // Set NetworkManager unmanaged
        self.ops
            .apply_nm_managed(iface, false)
            .context("failed to set NM unmanaged for AP")?;

        // Do NOT run DHCP - AP interface gets manual IP from hotspot service (10.20.30.1/24)
        info!("AP interface {} activated (manual IP, no DHCP)", iface);
        Ok(())
    }

    fn select_active_interface(
        &self,
        interfaces: &[super::ops::InterfaceSummary],
        preferred: Option<&str>,
    ) -> Result<Option<String>> {
        if let Some(pref) = preferred {
            if interfaces.iter().any(|i| i.name == pref) {
                return Ok(Some(pref.to_string()));
            }
            warn!("Preferred interface '{}' not found", pref);
        }

        for iface in interfaces {
            if iface.oper_state == "up" && !iface.is_wireless {
                info!("Auto-selected wired interface: {}", iface.name);
                return Ok(Some(iface.name.clone()));
            }
        }

        for iface in interfaces {
            if iface.oper_state == "up" && iface.is_wireless {
                info!("Auto-selected wireless interface: {}", iface.name);
                return Ok(Some(iface.name.clone()));
            }
        }

        warn!("No operational interfaces found");
        Ok(None)
    }

    fn activate_interface(&self, iface: &str, mode: EnforcementMode) -> Result<()> {
        info!("Activating interface: {} ({:?})", iface, mode);

        // Check interface exists before starting
        if !self.ops.interface_exists(iface) {
            bail!("Interface {} does not exist", iface);
        }

        if let Err(e) = self.ops.bring_up(iface) {
            // Check if interface disappeared
            if !self.ops.interface_exists(iface) {
                bail!("Interface {} disappeared during activation", iface);
            }
            warn!("Interface {} may already be up: {}", iface, e);
        }

        let is_wireless = self.ops.is_wireless(iface);

        if is_wireless {
            self.ops
                .set_rfkill_block(iface, false)
                .context("failed to unblock rfkill")?;

            if mode == EnforcementMode::Passive {
                self.ops
                    .apply_nm_managed(iface, false)
                    .context("failed to set NM unmanaged")?;
                info!("Interface {} activated (passive, no DHCP)", iface);
                return Ok(());
            }

            // For wireless interfaces, check if we're connected to an AP
            // If not, try to auto-connect using a saved profile
            if self.ops.get_ipv4_address(iface).ok().flatten().is_none() {
                info!("Wireless interface {} has no IP - checking for auto-connect profiles", iface);

                match self.try_auto_connect_wifi(iface) {
                    Ok(true) => {
                        info!("Auto-connected to WiFi network on {}", iface);
                        // WiFi connection includes DHCP, so we're done
                        return Ok(());
                    }
                    Ok(false) => {
                        info!("No auto-connect profile found for {}, will try DHCP anyway", iface);
                    }
                    Err(e) => {
                        warn!("Auto-connect failed for {}: {}", iface, e);
                        info!("Attempting DHCP anyway (may fail if not connected to AP)");
                    }
                }
            }
        }

        self.ops
            .apply_nm_managed(iface, false)
            .context("failed to set NM unmanaged")?;

        if mode == EnforcementMode::Passive {
            if !is_wireless {
                // Ethernet interface - retry DHCP acquisition with carrier detection
                // Carrier check first to fail fast if no cable (~1s vs 15-25s)

                // Pre-check: verify physical link/carrier is detected
                let carrier_detected = self.interface_has_carrier(iface);
                if !carrier_detected {
                    error!("No carrier detected on {} - cable not plugged in?", iface);
                    bail!("No carrier detected on {} - check cable connection", iface);
                }

                // Cable is plugged in - now retry DHCP in case of transient issues
                // (slow DHCP server, switch STP delays, etc.)
                const MAX_RETRIES: usize = 3;  // 3 retries × 5s = 15s total max
                const RETRY_DELAY_SECS: u64 = 5;

                let mut last_error = None;
                let mut lease_acquired = false;

                for attempt in 1..=MAX_RETRIES {
                    info!("Attempting DHCP for {} (attempt {}/{})", iface, attempt, MAX_RETRIES);

                    match self.ops.acquire_dhcp(iface, Duration::from_secs(30)) {
                        Ok(lease) => {
                            info!(
                                "DHCP successful for {} on attempt {}: ip={}, gateway={:?}",
                                iface, attempt, lease.ip, lease.gateway
                            );

                            if let Some(gw) = lease.gateway {
                                let metric = if is_wireless { 200 } else { 100 };
                                self.routes
                                    .set_default_route(iface, gw, metric)
                                    .context("failed to set default route")?;
                            } else {
                                warn!("No gateway in DHCP lease - link-local only");
                            }

                            if !lease.dns_servers.is_empty() {
                                self.dns
                                    .set_dns(&lease.dns_servers)
                                    .context("failed to set DNS")?;
                            } else {
                                warn!("No DNS in DHCP lease, using fallback");
                                self.dns
                                    .set_dns(&[
                                        Ipv4Addr::new(1, 1, 1, 1),
                                        Ipv4Addr::new(9, 9, 9, 9),
                                    ])
                                    .context("failed to set fallback DNS")?;
                            }

                            lease_acquired = true;
                            break;
                        }
                        Err(e) => {
                            last_error = Some(e);

                            if attempt < MAX_RETRIES {
                                warn!(
                                    "DHCP attempt {}/{} failed for {}: {}. Retrying in {}s...",
                                    attempt, MAX_RETRIES, iface, last_error.as_ref().unwrap(), RETRY_DELAY_SECS
                                );
                                std::thread::sleep(Duration::from_secs(RETRY_DELAY_SECS));
                            } else {
                                // All retries exhausted
                                error!(
                                    "DHCP failed for {} after {} attempts: {}",
                                    iface, MAX_RETRIES, last_error.as_ref().unwrap()
                                );
                            }
                        }
                    }
                }

                if !lease_acquired {
                    bail!(
                        "Failed to acquire DHCP lease for {} after {} attempts: {}",
                        iface,
                        MAX_RETRIES,
                        last_error.unwrap()
                    );
                }
            }
            info!("Interface {} activated (passive)", iface);
            return Ok(());
        }

        // Try DHCP with graceful fallback
        match self.ops.acquire_dhcp(iface, Duration::from_secs(30)) {
            Ok(lease) => {
                info!(
                    "DHCP lease acquired: ip={}, gateway={:?}",
                    lease.ip, lease.gateway
                );

                if let Some(gw) = lease.gateway {
                    let metric = if self.ops.is_wireless(iface) { 200 } else { 100 };
                    self.routes
                        .set_default_route(iface, gw, metric)
                        .context("failed to set default route")?;
                } else {
                    warn!("No gateway in DHCP lease - link-local only");
                }

                if !lease.dns_servers.is_empty() {
                    self.dns
                        .set_dns(&lease.dns_servers)
                        .context("failed to set DNS")?;
                } else {
                    warn!("No DNS in DHCP lease, using fallback");
                    self.dns
                        .set_dns(&[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)])
                        .context("failed to set fallback DNS")?;
                }
            }
            Err(e) => {
                warn!("DHCP failed for {}: {}", iface, e);
                warn!("Continuing with manual IP configuration (if present)");
                
                // Set fallback DNS even without DHCP
                self.dns
                    .set_dns(&[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)])
                    .context("failed to set fallback DNS")?;
                
                // Check if interface has manual IP - if not, this is a failure
                if self.ops.get_ipv4_address(iface).ok().flatten().is_none() {
                    bail!("DHCP failed and no manual IP configured");
                }
                
                info!("Interface has manual IP, continuing without DHCP");
            }
        }

        info!("Interface {} fully activated", iface);
        Ok(())
    }

    fn try_auto_connect_wifi(&self, iface: &str) -> Result<bool> {
        use crate::system::{list_wifi_profiles, load_wifi_profile, connect_wifi_network};

        // Load all profile records
        let profile_records = match list_wifi_profiles(&self.root) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to list WiFi profiles: {}", e);
                return Ok(false);
            }
        };

        if profile_records.is_empty() {
            debug!("No WiFi profiles found");
            return Ok(false);
        }

        // Filter to auto-connect profiles matching this interface
        let mut candidates: Vec<_> = profile_records
            .into_iter()
            .filter(|p| {
                p.auto_connect && (p.interface == iface || p.interface == "auto")
            })
            .collect();

        if candidates.is_empty() {
            info!("No auto-connect WiFi profiles found for {}", iface);
            return Ok(false);
        }

        // Sort by priority (highest first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        info!("Found {} auto-connect profile(s) for {}", candidates.len(), iface);

        // Try to connect to the highest priority profile
        let record = &candidates[0];
        info!("Attempting auto-connect to {} (priority {})", record.ssid, record.priority);

        // Load full profile to get password
        let full_profile = match load_wifi_profile(&self.root, &record.ssid) {
            Ok(Some(p)) => p.profile,
            Ok(None) => {
                warn!("Profile {} not found (may have been deleted)", record.ssid);
                return Ok(false);
            }
            Err(e) => {
                warn!("Failed to load profile {}: {}", record.ssid, e);
                return Err(e);
            }
        };

        match connect_wifi_network(iface, &full_profile.ssid, full_profile.password.as_deref()) {
            Ok(()) => {
                info!("Successfully auto-connected to {}", full_profile.ssid);
                Ok(true)
            }
            Err(e) => {
                warn!("Failed to auto-connect to {}: {}", full_profile.ssid, e);
                Err(e)
            }
        }
    }

    fn interface_has_carrier(&self, iface: &str) -> bool {
        // Check if physical link/carrier is detected on the interface
        // Returns true if carrier = 1 (cable plugged in) or if carrier file doesn't exist
        let carrier_path = format!("/sys/class/net/{}/carrier", iface);
        match fs::read_to_string(&carrier_path) {
            Ok(val) => {
                let carrier = val.trim();
                carrier == "1"  // 1 = carrier detected (cable plugged in)
            }
            Err(_) => {
                // If carrier file doesn't exist, assume interface might work
                // (some virtual/wireless interfaces don't have carrier detection)
                true
            }
        }
    }

    fn block_interface(&self, iface: &str) -> Result<()> {
        debug!("Blocking interface: {}", iface);

        // Delete all routes for this interface
        if let Err(e) = self.routes.delete_default_route(iface) {
            debug!("No default route to delete for {}: {}", iface, e);
        }

        // Release DHCP lease if any
        self.ops.release_dhcp(iface).ok();
        
        // Set NetworkManager unmanaged
        self.ops.apply_nm_managed(iface, false).ok();

        // CRITICAL: Bring interface DOWN to prevent any communication
        if let Err(e) = self.ops.bring_down(iface) {
            warn!("Failed to bring down {}: {}", iface, e);
        }
        
        // Block wireless if applicable
        if self.ops.is_wireless(iface) {
            if let Err(e) = self.ops.set_rfkill_block(iface, true) {
                warn!("Failed to rfkill block {}: {}", iface, e);
            }
        }

        info!("Interface {} fully blocked (DOWN, no routes)", iface);
        Ok(())
    }

    fn verify_enforcement(&self, expected_active: Option<&str>, mode: EnforcementMode) -> Result<()> {
        debug!("Verifying enforcement state");

        let current_route = self.routes.get_default_route()?;

        match (expected_active, current_route) {
            (Some(expected), Some(route)) => {
                if route.interface != expected {
                    bail!(
                        "Verification failed: expected {} but default route is via {}",
                        expected,
                        route.interface
                    );
                }
                debug!("Verified: default route via {}", expected);
            }
            (Some(expected), None) => {
                if mode == EnforcementMode::Connectivity {
                    bail!(
                        "Verification failed: expected {} but no default route",
                        expected
                    );
                }
                debug!("Verified: no default route for {} (passive mode)", expected);
            }
            (None, Some(route)) => {
                bail!(
                    "Verification failed: expected no routes but found route via {}",
                    route.interface
                );
            }
            (None, None) => {
                debug!("Verified: no default route (as expected)");
            }
        }

        let dns = self.dns.verify_dns()?;
        debug!("DNS servers: {:?}", dns);

        Ok(())
    }
}

/// Set the hotspot exception to allow two interfaces during hotspot operation
pub fn set_hotspot_exception(ap_interface: String, upstream_interface: String) -> Result<()> {
    let lock = HOTSPOT_EXCEPTION.get_or_init(|| StdMutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    
    if guard.is_some() {
        bail!("Hotspot exception already set - cannot run multiple hotspots");
    }
    
    *guard = Some(HotspotException {
        ap_interface: ap_interface.clone(),
        upstream_interface: upstream_interface.clone(),
    });
    
    info!("Set hotspot exception: AP={}, upstream={}", ap_interface, upstream_interface);
    Ok(())
}

/// Clear the hotspot exception to return to single-interface mode
pub fn clear_hotspot_exception() -> Result<()> {
    let lock = HOTSPOT_EXCEPTION.get_or_init(|| StdMutex::new(None));
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    
    if guard.is_none() {
        debug!("No hotspot exception to clear");
        return Ok(());
    }
    
    let exc = guard.take().unwrap();
    info!("Cleared hotspot exception: AP={}, upstream={}", exc.ap_interface, exc.upstream_interface);
    Ok(())
}

/// Get the current hotspot exception if set
fn get_hotspot_exception() -> Option<HotspotException> {
    let lock = HOTSPOT_EXCEPTION.get_or_init(|| StdMutex::new(None));
    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    guard.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::ops::tests::MockNetOps;
    use tempfile::TempDir;
    
    #[test]
    fn test_enforce_single_wired_interface() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        mock.add_interface("wlan0", true, "up");
        
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock.clone(), temp_dir.path().to_path_buf());
        
        let outcome = engine.enforce().unwrap();
        
        // Should prefer wired over wireless
        assert_eq!(outcome.allowed.len(), 1);
        assert_eq!(outcome.allowed[0], "eth0");
        assert_eq!(outcome.blocked.len(), 1);
        assert_eq!(outcome.blocked[0], "wlan0");
        assert_eq!(outcome.errors.len(), 0);
        
        // Verify eth0 was brought up
        assert!(mock.was_brought_up("eth0"));
        
        // Verify route was added
        let routes = mock.get_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].interface, "eth0");
    }
    
    #[test]
    fn test_enforce_no_interfaces() {
        let mock = Arc::new(MockNetOps::new());
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock, temp_dir.path().to_path_buf());
        
        let outcome = engine.enforce().unwrap();
        
        assert_eq!(outcome.allowed.len(), 0);
        assert_eq!(outcome.blocked.len(), 0);
    }
    
    #[test]
    fn test_enforce_respects_preference() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        mock.add_interface("wlan0", true, "up");
        
        let temp_dir = TempDir::new().unwrap();
        let prefs = PreferenceManager::new(temp_dir.path().to_path_buf());
        prefs.set_preferred("wlan0").unwrap();
        
        let engine = IsolationEngine::new(mock, temp_dir.path().to_path_buf());
        let outcome = engine.enforce().unwrap();
        
        // Should use wlan0 because it's preferred
        assert_eq!(outcome.allowed[0], "wlan0");
        assert_eq!(outcome.blocked[0], "eth0");
    }
    
    #[test]
    fn test_enforce_dhcp_failure() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        mock.set_dhcp_result("eth0", Err(anyhow::anyhow!("DHCP timeout")));
        
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock, temp_dir.path().to_path_buf());
        
        let result = engine.enforce();
        
        // Should fail because DHCP failed
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DHCP"));
    }

    #[test]
    fn test_enforce_passive_ignores_dhcp_failure() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        mock.set_dhcp_result("eth0", Err(anyhow::anyhow!("DHCP timeout")));

        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock.clone(), temp_dir.path().to_path_buf());

        let outcome = engine.enforce_passive().unwrap();

        assert_eq!(outcome.allowed, vec!["eth0".to_string()]);
        assert!(mock.get_routes().is_empty());
    }
    
    #[test]
    fn test_enforce_idempotent() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock.clone(), temp_dir.path().to_path_buf());
        
        // Call enforce twice
        let outcome1 = engine.enforce().unwrap();
        let outcome2 = engine.enforce().unwrap();
        
        // Results should be identical
        assert_eq!(outcome1.allowed, outcome2.allowed);
        assert_eq!(outcome1.blocked, outcome2.blocked);
    }
    
    #[test]
    fn test_enforce_wireless_only() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("wlan0", true, "up");
        
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock.clone(), temp_dir.path().to_path_buf());
        
        let outcome = engine.enforce().unwrap();
        
        // Should select wireless when no wired available
        assert_eq!(outcome.allowed.len(), 1);
        assert_eq!(outcome.allowed[0], "wlan0");
        assert_eq!(outcome.blocked.len(), 0);
    }
    
    #[test]
    fn test_enforce_multiple_interfaces() {
        let mock = Arc::new(MockNetOps::new());
        mock.add_interface("eth0", false, "up");
        mock.add_interface("eth1", false, "up");
        mock.add_interface("wlan0", true, "up");
        
        let temp_dir = TempDir::new().unwrap();
        let engine = IsolationEngine::new(mock.clone(), temp_dir.path().to_path_buf());
        
        let outcome = engine.enforce().unwrap();
        
        // Should select first wired interface
        assert_eq!(outcome.allowed.len(), 1);
        assert_eq!(outcome.blocked.len(), 2);
        assert!(outcome.allowed.contains(&"eth0".to_string()));
    }
}
