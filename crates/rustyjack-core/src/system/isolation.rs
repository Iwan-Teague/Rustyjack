use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::dns::DnsManager;
use super::ops::{ErrorEntry, IsolationOutcome, NetOps};
use super::isolation_policy::{IsolationMode, IsolationPolicyManager};
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

/// Enforcement mode determines what guarantees we make about the interface state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnforcementMode {
    /// Selection-only mode: Interface must reach admin-UP state
    /// Does NOT require carrier or DHCP success
    /// Used for hardware detection and initial interface selection
    Selection,
    /// Passive mode: Best-effort connectivity attempts for ethernet
    /// Non-fatal failures for carrier/DHCP (will warn but won't fail)
    /// For wireless: admin-UP only, no auto-connect
    Passive,
    /// Full connectivity: Requires both admin-UP and active connectivity
    Connectivity,
}

/// Result of DHCP acquisition attempt
#[derive(Debug, Clone)]
pub enum DhcpReport {
    NotAttempted,
    Succeeded { ip: Ipv4Addr, gateway: Option<Ipv4Addr> },
    Failed(String),
}

/// Detailed report of interface activation
#[derive(Debug, Clone)]
pub struct ActivationReport {
    pub interface: String,
    pub admin_up: bool,
    pub carrier: Option<bool>,
    pub ipv4: Option<Ipv4Addr>,
    pub dhcp: DhcpReport,
    pub notes: Vec<String>,
}

impl IsolationEngine {
    pub fn new(ops: Arc<dyn NetOps>, root: PathBuf) -> Self {
        let routes = RouteManager::new(Arc::clone(&ops));
        let dns = DnsManager::new(root.join("resolv.conf"));
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
        // enforce_passive uses Passive mode:
        // - For ethernet: attempts DHCP but failures are non-fatal
        // - For wireless: brings UP without auto-connect (user connects manually)
        self.enforce_with_mode(EnforcementMode::Passive)
    }

    fn enforce_explicit_allow_list(&self, allowed: &[String]) -> Result<IsolationOutcome> {
        let outcome = crate::system::apply_interface_isolation_with_ops_strict(
            Arc::clone(&self.ops),
            allowed,
        )?;
        if !outcome.errors.is_empty() {
            let error_msgs: Vec<String> = outcome
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.interface, e.message))
                .collect();
            bail!("Interface isolation errors: {}", error_msgs.join("; "));
        }
        Ok(outcome)
    }

    fn enforce_block_all(&self) -> Result<IsolationOutcome> {
        let outcome = crate::system::apply_interface_isolation_with_ops_block_all(
            Arc::clone(&self.ops),
        )?;
        if !outcome.errors.is_empty() {
            let error_msgs: Vec<String> = outcome
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.interface, e.message))
                .collect();
            bail!("Interface isolation errors: {}", error_msgs.join("; "));
        }
        Ok(outcome)
    }

    fn enforce_with_mode(&self, mode: EnforcementMode) -> Result<IsolationOutcome> {
        // Acquire global lock to prevent concurrent enforcement
        let lock = ENFORCEMENT_LOCK.get_or_init(|| StdMutex::new(()));
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        
        info!("Starting network isolation enforcement (lock acquired)");

        let policy_mgr = IsolationPolicyManager::new(self.root.clone());
        if let Some(policy) = policy_mgr.read()? {
            match policy.mode {
                IsolationMode::AllowList => {
                    info!(
                        target: "net",
                        session = %policy.session,
                        allow_list = ?policy.allowed,
                        "isolation_policy_allow_list"
                    );
                    return self.enforce_explicit_allow_list(&policy.allowed);
                }
                IsolationMode::BlockAll => {
                    info!(
                        target: "net",
                        session = %policy.session,
                        "isolation_policy_block_all"
                    );
                    return self.enforce_block_all();
                }
            }
        }

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

        let candidates: Vec<&super::ops::InterfaceSummary> =
            interfaces.iter().filter(|iface| iface.name != "lo").collect();

        if candidates.is_empty() {
            warn!("No interfaces found");
            return Ok(None);
        }

        if let Some(wired) = candidates.iter().find(|iface| !iface.is_wireless) {
            info!("Auto-selected wired interface: {}", wired.name);
            return Ok(Some(wired.name.clone()));
        }

        if let Some(wifi) = candidates.iter().find(|iface| iface.is_wireless) {
            info!("Auto-selected wireless interface: {}", wifi.name);
            return Ok(Some(wifi.name.clone()));
        }

        Ok(Some(candidates[0].name.clone()))
    }

    /// Activate an interface using a step-by-step pipeline.
    /// Each step is verified before proceeding to the next.
    /// Returns detailed error at the exact point of failure.
    fn activate_interface(&self, iface: &str, mode: EnforcementMode) -> Result<()> {
        info!("=== ACTIVATION PIPELINE START: {} ({:?}) ===", iface, mode);

        // ============================================================
        // STEP 1: Verify interface exists
        // ============================================================
        info!("[Step 1/6] Checking interface {} exists...", iface);
        if !self.ops.interface_exists(iface) {
            error!("[Step 1/6] FAILED: Interface {} does not exist in /sys/class/net", iface);
            bail!("Step 1 failed: Interface '{}' does not exist", iface);
        }
        info!("[Step 1/6] PASSED: Interface {} exists", iface);

        let is_wireless = self.ops.is_wireless(iface);
        info!("Interface type: {}", if is_wireless { "wireless" } else { "ethernet" });

        // ============================================================
        // STEP 3 (wireless only): Check if hardware rfkill blocked
        // ============================================================
        if is_wireless {
            info!("[Step 2/6] Checking if {} is hardware-blocked (rfkill)...", iface);
            match self.ops.is_rfkill_hard_blocked(iface) {
                Ok(true) => {
                    error!("[Step 2/6] FAILED: {} is HARDWARE blocked (physical switch)", iface);
                    error!("The wireless adapter has a physical kill switch that is ON.");
                    error!("This cannot be fixed via software. Check for a physical WiFi switch on the device.");
                    bail!("Step 2 failed: Interface '{}' is hardware-blocked by rfkill. Check physical WiFi switch.", iface);
                }
                Ok(false) => {
                    info!("[Step 2/6] PASSED: {} is not hardware-blocked", iface);
                }
                Err(e) => {
                    warn!("[Step 2/6] WARNING: Could not check rfkill status: {} (continuing)", e);
                }
            }
        } else {
            info!("[Step 2/6] SKIPPED: Not a wireless interface");
        }

        // ============================================================
        // STEP 4 (wireless only): Unblock rfkill and verify
        // ============================================================
        if is_wireless {
            info!("[Step 3/6] Unblocking rfkill for {}...", iface);

            // Execute unblock
            if let Err(e) = self.ops.set_rfkill_block(iface, false) {
                error!("[Step 3/6] FAILED: Could not unblock rfkill for {}: {}", iface, e);
                bail!("Step 3 failed: Cannot unblock rfkill for '{}': {}", iface, e);
            }

            // Verify unblock succeeded by checking state
            match self.ops.is_rfkill_blocked(iface) {
                Ok(true) => {
                    error!("[Step 3/6] FAILED: rfkill unblock command succeeded but {} is still blocked", iface);
                    error!("This usually means the device has a hardware kill switch that is ON.");
                    bail!("Step 3 failed: Interface '{}' is still rfkill-blocked after unblock command", iface);
                }
                Ok(false) => {
                    info!("[Step 3/6] PASSED: {} rfkill unblocked and verified", iface);
                }
                Err(e) => {
                    warn!("[Step 3/6] WARNING: Could not verify rfkill state: {} (continuing)", e);
                }
            }
        } else {
            info!("[Step 3/6] SKIPPED: Not a wireless interface");
        }

        // ============================================================
        // STEP 5: Execute bring_up command
        // ============================================================
        info!("[Step 4/6] Executing 'ip link set {} up'...", iface);
        if let Err(e) = self.ops.bring_up(iface) {
            // Check if interface still exists
            if !self.ops.interface_exists(iface) {
                error!("[Step 4/6] FAILED: Interface {} disappeared during bring_up", iface);
                bail!("Step 4 failed: Interface '{}' disappeared during activation", iface);
            }
            error!("[Step 4/6] FAILED: bring_up command failed for {}: {}", iface, e);
            bail!("Step 4 failed: Could not bring up '{}': {}", iface, e);
        }
        info!("[Step 4/6] PASSED: bring_up command executed", );

        // ============================================================
        // STEP 6: Verify interface is admin-UP (IFF_UP flag)
        // ============================================================
        info!("[Step 5/6] Verifying {} has IFF_UP flag set...", iface);
        match self.ops.admin_is_up(iface) {
            Ok(true) => {
                info!("[Step 5/6] PASSED: {} is admin-UP (IFF_UP=1)", iface);
            }
            Ok(false) => {
                error!("[Step 5/6] FAILED: {} is NOT admin-UP after bring_up command", iface);
                error!("The bring_up command succeeded but the interface did not come UP.");
                if is_wireless {
                    error!("For wireless: this usually means rfkill is still blocking.");
                    // Double-check rfkill
                    if let Ok(blocked) = self.ops.is_rfkill_blocked(iface) {
                        if blocked {
                            error!("CONFIRMED: rfkill is still blocking {}!", iface);
                        }
                    }
                }
                bail!("Step 5 failed: Interface '{}' did not come UP. IFF_UP flag is not set.", iface);
            }
            Err(e) => {
                error!("[Step 5/6] FAILED: Could not read interface flags for {}: {}", iface, e);
                bail!("Step 5 failed: Cannot verify interface '{}' state: {}", iface, e);
            }
        }

        info!("[Step 6/6] Interface {} is now admin-UP", iface);
        info!("=== ACTIVATION PIPELINE COMPLETE: {} ===", iface);

        // RC1: For Selection mode, we're done - interface is UP
        if mode == EnforcementMode::Selection {
            info!("Interface {} selected (Selection mode: admin-UP only)", iface);
            return Ok(());
        }

        // For wireless interfaces in Passive/Connectivity mode
        // (rfkill already handled above)
        if is_wireless {
            // RC3: Passive mode for wireless should NOT auto-connect
            // Only admin-UP, let user manually connect via UI
            if mode == EnforcementMode::Passive {
                info!("Interface {} activated in Passive mode (no auto-connect)", iface);
                return Ok(());
            }

            // For Connectivity mode wireless, attempt connection
            // (but this is not used in current UI flow)
            info!("Interface {} activated in Connectivity mode", iface);
            return Ok(());
        }

        // ============================================================
        // ETHERNET PASSIVE MODE: Check carrier and attempt DHCP
        // ============================================================
        if mode == EnforcementMode::Passive {
            info!("=== ETHERNET DHCP PIPELINE: {} ===", iface);

            // Step E1: Check carrier (cable plugged in)
            info!("[Ethernet Step 1/3] Checking carrier on {}...", iface);
            match self.ops.has_carrier(iface) {
                Ok(Some(true)) => {
                    info!("[Ethernet Step 1/3] PASSED: Carrier detected (cable connected)");
                }
                Ok(Some(false)) => {
                    warn!("[Ethernet Step 1/3] NO CARRIER: Ethernet cable not plugged in");
                    info!("Interface {} is UP but no cable detected. Plug in ethernet cable.", iface);
                    info!("=== ETHERNET PIPELINE COMPLETE (no carrier) ===");
                    return Ok(());
                }
                Ok(None) => {
                    warn!("[Ethernet Step 1/3] WARNING: Cannot determine carrier state (continuing)");
                }
                Err(e) => {
                    warn!("[Ethernet Step 1/3] WARNING: Error checking carrier: {} (continuing)", e);
                }
            }

            // Step E2: Attempt DHCP (single attempt, with timeout)
            info!("[Ethernet Step 2/3] Attempting DHCP on {}...", iface);
            match self.ops.acquire_dhcp(iface, Duration::from_secs(30)) {
                Ok(lease) => {
                    info!("[Ethernet Step 2/3] PASSED: DHCP lease acquired");
                    info!("  IP Address: {}/{}", lease.ip, lease.prefix_len);
                    info!("  Gateway: {:?}", lease.gateway);
                    info!("  DNS: {:?}", lease.dns_servers);

                    // Step E3: Configure routes and DNS
                    info!("[Ethernet Step 3/3] Configuring routes and DNS...");

                    if let Some(gw) = lease.gateway {
                        let metric = 100;
                        match self.routes.set_default_route(iface, gw, metric) {
                            Ok(_) => info!("  Default route set via {}", gw),
                            Err(e) => warn!("  Failed to set default route: {}", e),
                        }
                    } else {
                        warn!("  No gateway in DHCP lease - link-local only");
                    }

                    if !lease.dns_servers.is_empty() {
                        match self.dns.set_dns(&lease.dns_servers) {
                            Ok(_) => info!("  DNS configured: {:?}", lease.dns_servers),
                            Err(e) => warn!("  Failed to set DNS: {}", e),
                        }
                    } else {
                        warn!("  No DNS in DHCP lease, using fallback 1.1.1.1, 9.9.9.9");
                        let _ = self.dns.set_dns(&[
                            Ipv4Addr::new(1, 1, 1, 1),
                            Ipv4Addr::new(9, 9, 9, 9),
                        ]);
                    }

                    info!("[Ethernet Step 3/3] PASSED: Network configured");
                    info!("=== ETHERNET PIPELINE COMPLETE (connected) ===");
                    return Ok(());
                }
                Err(e) => {
                    warn!("[Ethernet Step 2/3] DHCP FAILED: {}", e);
                    info!("Interface {} is UP but DHCP failed. No network connectivity.", iface);
                    info!("Possible causes: No DHCP server, network issue, or cable problem.");
                    info!("=== ETHERNET PIPELINE COMPLETE (no DHCP) ===");
                    // In Passive mode, DHCP failure is not fatal - interface is still UP
                    return Ok(());
                }
            }
        }

        // Connectivity mode (full connection required)
        // Attempt DHCP and fail if unsuccessful
        match self.ops.acquire_dhcp(iface, Duration::from_secs(30)) {
            Ok(lease) => {
                info!(
                    "DHCP lease acquired: ip={}, gateway={:?}",
                    lease.ip, lease.gateway
                );

                if let Some(gw) = lease.gateway {
                    let metric = 100;
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
                bail!("Failed to acquire DHCP lease for {}: {}", iface, e);
            }
        }

        info!("Interface {} fully activated with connectivity", iface);
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


    fn block_interface(&self, iface: &str) -> Result<()> {
        debug!("Blocking interface: {}", iface);

        // Delete all routes for this interface
        if let Err(e) = self.routes.delete_default_route(iface) {
            debug!("No default route to delete for {}: {}", iface, e);
        }

        // Release DHCP lease if any
        self.ops.release_dhcp(iface).ok();
        
        // CRITICAL: Bring interface DOWN to prevent any communication
        let mut bring_down_ok = false;
        let mut last_err = None;
        for _ in 0..3 {
            match self.ops.bring_down(iface) {
                Ok(()) => {
                    bring_down_ok = true;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        if !bring_down_ok {
            if let Some(err) = last_err {
                return Err(err).with_context(|| {
                    format!("CRITICAL: failed to bring down {}", iface)
                });
            }
            bail!("CRITICAL: failed to bring down {}", iface);
        }
        if self.ops.admin_is_up(iface)? {
            bail!(
                "CRITICAL: {} remained admin-UP after bring_down retries",
                iface
            );
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
