//! Pure Rust implementation of iptables-like netfilter functionality
//!
//! This module provides a native Rust interface to Linux netfilter using the
//! nf_tables netlink API (nftables). It eliminates the need for the external
//! `iptables` binary while preserving the existing Rustyjack API.
//!
//! ## Supported Operations
//!
//! - NAT rules (MASQUERADE, DNAT, SNAT)
//! - Filtering rules (ACCEPT, DROP, REJECT)
//! - Mangle rules (TCPMSS)
//! - Flushing chains
//! - Rule insertion and deletion
//!
//! ## Logging
//!
//! Set `RUSTYJACK_NFTABLES_LOG=1` to enable packet logging for high-level
//! helper rules (masquerade/forward/DNAT/TCPMSS). Logs include a `[NFTABLE]`
//! prefix and appear in journalctl.
//!
//! ## Example
//!
//! ```no_run
//! use rustyjack_netlink::iptables::*;
//!
//! # async fn example() -> Result<(), IptablesError> {
//! let mgr = IptablesManager::new()?;
//!
//! // Enable NAT masquerading
//! mgr.add_masquerade("eth0").await?;
//!
//! // Allow forwarding
//! mgr.add_forward_accept("wlan0", "eth0").await?;
//!
//! // Redirect HTTP to captive portal
//! mgr.add_dnat("wlan0", 80, "192.168.4.1", 80).await?;
//! # Ok(())
//! # }
//! ```

#[allow(dead_code)]
use std::env;
use std::net::IpAddr;
use std::sync::Mutex;
use thiserror::Error;

use self::nf_tables::NfTablesManager;

#[cfg(target_os = "linux")]
#[path = "nf_tables.rs"]
mod nf_tables;

#[derive(Debug, Error)]
pub enum IptablesError {
    #[error("Failed to execute iptables command: {0}")]
    CommandFailed(String),

    #[error("Invalid IP address: {0}")]
    InvalidAddress(String),

    #[error("Invalid interface: {0}")]
    InvalidInterface(String),

    #[error("Invalid port: {0}")]
    InvalidPort(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("Chain not found: {0}")]
    ChainNotFound(String),

    #[error("Insufficient permissions (requires root/CAP_NET_ADMIN)")]
    PermissionDenied,

    #[error("Netfilter netlink error: {0}")]
    NetlinkError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IptablesError>;

/// Table types in netfilter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Filter,
    Nat,
    Mangle,
    Raw,
}

impl Table {
    fn as_str(&self) -> &str {
        match self {
            Table::Filter => "filter",
            Table::Nat => "nat",
            Table::Mangle => "mangle",
            Table::Raw => "raw",
        }
    }
}

/// Chain names
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chain {
    Input,
    Output,
    Forward,
    Prerouting,
    Postrouting,
    Custom(String),
}

impl Chain {
    fn as_str(&self) -> &str {
        match self {
            Chain::Input => "INPUT",
            Chain::Output => "OUTPUT",
            Chain::Forward => "FORWARD",
            Chain::Prerouting => "PREROUTING",
            Chain::Postrouting => "POSTROUTING",
            Chain::Custom(name) => name,
        }
    }
}

/// Target actions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Accept,
    Drop,
    Reject,
    Masquerade,
    Dnat { to: IpAddr, port: Option<u16> },
    Snat { to: IpAddr },
    TcpMss { mss: u16 },
}

impl Target {
    #[cfg(test)]
    fn as_str(&self) -> &str {
        match self {
            Target::Accept => "ACCEPT",
            Target::Drop => "DROP",
            Target::Reject => "REJECT",
            Target::Masquerade => "MASQUERADE",
            Target::Dnat { .. } => "DNAT",
            Target::Snat { .. } => "SNAT",
            Target::TcpMss { .. } => "TCPMSS",
        }
    }
}

/// Protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    All,
}

impl Protocol {
    #[cfg(test)]
    fn as_str(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::All => "all",
        }
    }
}

/// Iptables rule builder
#[derive(Debug, Clone)]
pub struct Rule {
    table: Table,
    chain: Chain,
    protocol: Option<Protocol>,
    in_interface: Option<String>,
    out_interface: Option<String>,
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    state: Option<String>,
    target: Target,
    counter: bool,
    log_prefix: Option<String>,
    log_level: Option<u32>,
}

impl Rule {
    pub fn new(table: Table, chain: Chain, target: Target) -> Self {
        Self {
            table,
            chain,
            protocol: None,
            in_interface: None,
            out_interface: None,
            source: None,
            destination: None,
            src_port: None,
            dst_port: None,
            state: None,
            target,
            counter: false,
            log_prefix: None,
            log_level: None,
        }
    }

    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub fn in_interface(mut self, iface: &str) -> Self {
        self.in_interface = Some(iface.to_string());
        self
    }

    pub fn out_interface(mut self, iface: &str) -> Self {
        self.out_interface = Some(iface.to_string());
        self
    }

    pub fn source(mut self, addr: IpAddr) -> Self {
        self.source = Some(addr);
        self
    }

    pub fn destination(mut self, addr: IpAddr) -> Self {
        self.destination = Some(addr);
        self
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub fn connection_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn counter(mut self) -> Self {
        self.counter = true;
        self
    }

    pub fn log_prefix(mut self, prefix: &str) -> Self {
        self.log_prefix = Some(prefix.to_string());
        self
    }

    pub fn log_level(mut self, level: u32) -> Self {
        self.log_level = Some(level);
        self
    }

    #[cfg(test)]
    fn to_args(&self, action: &str) -> Vec<String> {
        let mut args = vec![
            "-t".to_string(),
            self.table.as_str().to_string(),
            action.to_string(),
            self.chain.as_str().to_string(),
        ];

        if let Some(proto) = &self.protocol {
            args.push("-p".to_string());
            args.push(proto.as_str().to_string());
        }

        if let Some(iface) = &self.in_interface {
            args.push("-i".to_string());
            args.push(iface.clone());
        }

        if let Some(iface) = &self.out_interface {
            args.push("-o".to_string());
            args.push(iface.clone());
        }

        if let Some(src) = &self.source {
            args.push("-s".to_string());
            args.push(src.to_string());
        }

        if let Some(dst) = &self.destination {
            args.push("-d".to_string());
            args.push(dst.to_string());
        }

        if let Some(port) = self.src_port {
            args.push("--sport".to_string());
            args.push(port.to_string());
        }

        if let Some(port) = self.dst_port {
            args.push("--dport".to_string());
            args.push(port.to_string());
        }

        if let Some(state) = &self.state {
            args.push("-m".to_string());
            args.push("state".to_string());
            args.push("--state".to_string());
            args.push(state.clone());
        }

        args.push("-j".to_string());
        args.push(self.target.as_str().to_string());

        match &self.target {
            Target::Dnat { to, port } => {
                args.push("--to-destination".to_string());
                if let Some(p) = port {
                    args.push(format!("{}:{}", to, p));
                } else {
                    args.push(to.to_string());
                }
            }
            Target::Snat { to } => {
                args.push("--to-source".to_string());
                args.push(to.to_string());
            }
            Target::TcpMss { mss } => {
                args.push("--set-mss".to_string());
                args.push(mss.to_string());
            }
            _ => {}
        }

        args
    }
}

/// Iptables manager for netfilter operations
pub struct IptablesManager {
    backend: Mutex<NfTablesManager>,
}

const NFT_LOG_ENV: &str = "RUSTYJACK_NFTABLES_LOG";
const NFT_LOG_PREFIX: &str = "[NFTABLE]";

impl IptablesManager {
    /// Create a new iptables manager
    ///
    /// # Errors
    ///
    /// Returns `IptablesError::PermissionDenied` if not running as root
    pub fn new() -> Result<Self> {
        let has_privileges = unsafe { libc::geteuid() } == 0;

        if !has_privileges {
            log::error!("Iptables operations require root privileges (CAP_NET_ADMIN)");
            return Err(IptablesError::PermissionDenied);
        }

        let backend = NfTablesManager::new().map_err(|e| {
            log::error!("Failed to initialize nf_tables backend: {}", e);
            e
        })?;

        log::debug!("IptablesManager initialized with nf_tables backend");
        Ok(Self {
            backend: Mutex::new(backend),
        })
    }

    fn with_backend<T>(&self, action: impl FnOnce(&mut NfTablesManager) -> Result<T>) -> Result<T> {
        let mut backend = self.backend.lock().map_err(|_| {
            IptablesError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "nf_tables backend lock poisoned",
            ))
        })?;
        action(&mut backend)
    }

    fn logging_enabled() -> bool {
        env::var(NFT_LOG_ENV)
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    }

    fn with_visibility(rule: Rule, context: &str) -> Rule {
        let mut rule = rule.counter();
        if Self::logging_enabled() {
            let prefix = format!("{NFT_LOG_PREFIX} {context}");
            log::info!("{NFT_LOG_PREFIX} packet logging enabled for {}", context);
            rule = rule.log_prefix(&prefix);
        }
        rule
    }

    /// Add a rule
    pub fn add_rule(&self, rule: &Rule) -> Result<()> {
        self.with_backend(|backend| backend.add_rule(rule))
    }

    /// Delete a rule
    pub fn delete_rule(&self, rule: &Rule) -> Result<()> {
        self.with_backend(|backend| backend.delete_rule(rule))
    }

    /// Flush all rules in a chain
    pub fn flush_chain(&self, table: Table, chain: Chain) -> Result<()> {
        self.with_backend(|backend| backend.flush_chain(table, chain))
    }

    /// Flush all rules in a table
    pub fn flush_table(&self, table: Table) -> Result<()> {
        self.with_backend(|backend| backend.flush_table(table))
    }

    /// Add NAT masquerading for an interface
    ///
    /// This enables NAT for outgoing traffic on the specified interface.
    ///
    /// # Arguments
    ///
    /// * `interface` - Output interface name (e.g., "eth0")
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rustyjack_netlink::iptables::*;
    /// # async fn example() -> Result<()> {
    /// let mgr = IptablesManager::new()?;
    /// mgr.add_masquerade("eth0")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_masquerade(&self, interface: &str) -> Result<()> {
        log::info!("Adding MASQUERADE rule for interface {}", interface);

        let rule = Self::with_visibility(
            Rule::new(Table::Nat, Chain::Postrouting, Target::Masquerade)
                .out_interface(interface),
            &format!("masquerade out={}", interface),
        );

        self.add_rule(&rule)
    }

    /// Remove NAT masquerading for an interface
    pub fn delete_masquerade(&self, interface: &str) -> Result<()> {
        log::info!("Removing MASQUERADE rule for interface {}", interface);

        let rule =
            Rule::new(Table::Nat, Chain::Postrouting, Target::Masquerade).out_interface(interface);

        self.delete_rule(&rule)
    }

    /// Add a forward rule to accept traffic between interfaces
    ///
    /// # Arguments
    ///
    /// * `in_iface` - Input interface
    /// * `out_iface` - Output interface
    pub fn add_forward_accept(&self, in_iface: &str, out_iface: &str) -> Result<()> {
        log::info!(
            "Adding FORWARD ACCEPT rule from {} to {}",
            in_iface,
            out_iface
        );

        let rule = Self::with_visibility(
            Rule::new(Table::Filter, Chain::Forward, Target::Accept)
                .in_interface(in_iface)
                .out_interface(out_iface),
            &format!("forward accept {}->{}", in_iface, out_iface),
        );

        self.add_rule(&rule)
    }

    /// Remove a forward rule
    pub fn delete_forward_accept(&self, in_iface: &str, out_iface: &str) -> Result<()> {
        log::info!(
            "Removing FORWARD ACCEPT rule from {} to {}",
            in_iface,
            out_iface
        );

        let rule = Rule::new(Table::Filter, Chain::Forward, Target::Accept)
            .in_interface(in_iface)
            .out_interface(out_iface);

        self.delete_rule(&rule)
    }

    /// Add a stateful forward rule for established connections
    ///
    /// This allows return traffic for established connections.
    pub fn add_forward_established(&self, in_iface: &str, out_iface: &str) -> Result<()> {
        log::info!(
            "Adding FORWARD ESTABLISHED rule from {} to {}",
            in_iface,
            out_iface
        );

        let rule = Self::with_visibility(
            Rule::new(Table::Filter, Chain::Forward, Target::Accept)
                .in_interface(in_iface)
                .out_interface(out_iface)
                .connection_state("RELATED,ESTABLISHED"),
            &format!("forward established {}->{}", in_iface, out_iface),
        );

        self.add_rule(&rule)
    }

    /// Remove a stateful forward rule
    pub fn delete_forward_established(&self, in_iface: &str, out_iface: &str) -> Result<()> {
        log::info!(
            "Removing FORWARD ESTABLISHED rule from {} to {}",
            in_iface,
            out_iface
        );

        let rule = Rule::new(Table::Filter, Chain::Forward, Target::Accept)
            .in_interface(in_iface)
            .out_interface(out_iface)
            .connection_state("RELATED,ESTABLISHED");

        self.delete_rule(&rule)
    }

    /// Add DNAT rule to redirect traffic to a different destination
    ///
    /// # Arguments
    ///
    /// * `in_iface` - Input interface to match
    /// * `dst_port` - Destination port to match
    /// * `to_addr` - New destination address
    /// * `to_port` - New destination port
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rustyjack_netlink::iptables::*;
    /// # async fn example() -> Result<()> {
    /// let mgr = IptablesManager::new()?;
    /// // Redirect HTTP to captive portal
    /// mgr.add_dnat("wlan0", 80, "192.168.4.1", 80)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_dnat(
        &self,
        in_iface: &str,
        dst_port: u16,
        to_addr: &str,
        to_port: u16,
    ) -> Result<()> {
        log::info!(
            "Adding DNAT rule: {}:{} -> {}:{} on {}",
            dst_port,
            to_addr,
            to_port,
            in_iface,
            dst_port
        );

        let addr: IpAddr = to_addr
            .parse()
            .map_err(|_| IptablesError::InvalidAddress(to_addr.to_string()))?;

        let rule = Self::with_visibility(
            Rule::new(
                Table::Nat,
                Chain::Prerouting,
                Target::Dnat {
                    to: addr,
                    port: Some(to_port),
                },
            )
            .in_interface(in_iface)
            .protocol(Protocol::Tcp)
            .dst_port(dst_port),
            &format!("dnat {}:{}->{}:{}", in_iface, dst_port, to_addr, to_port),
        );

        self.add_rule(&rule)
    }

    /// Remove DNAT rule
    pub fn delete_dnat(
        &self,
        in_iface: &str,
        dst_port: u16,
        to_addr: &str,
        to_port: u16,
    ) -> Result<()> {
        log::info!(
            "Removing DNAT rule: {}:{} on {}",
            to_addr,
            to_port,
            in_iface
        );

        let addr: IpAddr = to_addr
            .parse()
            .map_err(|_| IptablesError::InvalidAddress(to_addr.to_string()))?;

        let rule = Rule::new(
            Table::Nat,
            Chain::Prerouting,
            Target::Dnat {
                to: addr,
                port: Some(to_port),
            },
        )
        .in_interface(in_iface)
        .protocol(Protocol::Tcp)
        .dst_port(dst_port);

        self.delete_rule(&rule)
    }

    /// Enable TCP MSS clamping for packet fragmentation
    ///
    /// This sets the maximum segment size for TCP packets to force fragmentation.
    ///
    /// # Arguments
    ///
    /// * `mss` - Maximum segment size in bytes (typically 500-1460)
    pub fn add_tcp_mss(&self, mss: u16) -> Result<()> {
        log::info!("Adding TCP MSS rule: {} bytes", mss);

        let rule = Self::with_visibility(
            Rule::new(Table::Mangle, Chain::Output, Target::TcpMss { mss }),
            &format!("tcp mss {}", mss),
        );
        self.add_rule(&rule)
    }

    /// Remove TCP MSS clamping
    pub fn delete_tcp_mss(&self, mss: u16) -> Result<()> {
        log::info!("Removing TCP MSS rule: {} bytes", mss);

        let rule = Rule::new(Table::Mangle, Chain::Output, Target::TcpMss { mss });
        self.delete_rule(&rule)
    }

    /// Set up complete NAT configuration for hotspot/AP mode
    ///
    /// This configures masquerading and forwarding rules for a typical
    /// access point setup where clients connect to `ap_iface` and are
    /// forwarded to the internet via `upstream_iface`.
    ///
    /// # Arguments
    ///
    /// * `ap_iface` - AP/hotspot interface (e.g., "wlan0")
    /// * `upstream_iface` - Internet-connected interface (e.g., "eth0")
    pub fn setup_nat_forwarding(&self, ap_iface: &str, upstream_iface: &str) -> Result<()> {
        log::info!(
            "Setting up NAT forwarding: {} -> {}",
            ap_iface,
            upstream_iface
        );

        self.add_masquerade(upstream_iface)?;
        self.add_forward_established(upstream_iface, ap_iface)?;
        self.add_forward_accept(ap_iface, upstream_iface)?;

        log::info!("NAT forwarding configured successfully");
        Ok(())
    }

    /// Tear down NAT configuration
    pub fn teardown_nat_forwarding(&self, ap_iface: &str, upstream_iface: &str) -> Result<()> {
        log::info!(
            "Tearing down NAT forwarding: {} -> {}",
            ap_iface,
            upstream_iface
        );

        let _ = self.delete_masquerade(upstream_iface);
        let _ = self.delete_forward_established(upstream_iface, ap_iface);
        let _ = self.delete_forward_accept(ap_iface, upstream_iface);

        log::info!("NAT forwarding torn down");
        Ok(())
    }

    /// Set up captive portal redirection
    ///
    /// Redirects all HTTP/HTTPS traffic to a local captive portal.
    ///
    /// # Arguments
    ///
    /// * `ap_iface` - AP interface
    /// * `portal_addr` - Portal IP address (e.g., "192.168.4.1")
    /// * `portal_port` - Portal HTTP port (typically 80)
    pub fn setup_captive_portal(
        &self,
        ap_iface: &str,
        portal_addr: &str,
        portal_port: u16,
    ) -> Result<()> {
        log::info!(
            "Setting up captive portal on {} -> {}:{}",
            ap_iface,
            portal_addr,
            portal_port
        );

        self.flush_table(Table::Nat)?;
        self.flush_table(Table::Filter)?;

        self.add_dnat(ap_iface, 80, portal_addr, portal_port)?;
        self.add_dnat(ap_iface, 443, portal_addr, portal_port)?;
        self.add_forward_accept(ap_iface, ap_iface)?;

        log::info!("Captive portal configured successfully");
        Ok(())
    }

    /// Tear down captive portal configuration
    pub fn teardown_captive_portal(
        &self,
        ap_iface: &str,
        portal_addr: &str,
        portal_port: u16,
    ) -> Result<()> {
        log::info!("Tearing down captive portal");

        let _ = self.delete_dnat(ap_iface, 80, portal_addr, portal_port);
        let _ = self.delete_dnat(ap_iface, 443, portal_addr, portal_port);
        let _ = self.delete_forward_accept(ap_iface, ap_iface);

        log::info!("Captive portal torn down");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_builder() {
        let rule =
            Rule::new(Table::Nat, Chain::Postrouting, Target::Masquerade).out_interface("eth0");

        let args = rule.to_args("-A");
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"nat".to_string()));
        assert!(args.contains(&"-A".to_string()));
        assert!(args.contains(&"POSTROUTING".to_string()));
        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"eth0".to_string()));
        assert!(args.contains(&"-j".to_string()));
        assert!(args.contains(&"MASQUERADE".to_string()));
    }

    #[test]
    fn test_dnat_rule() {
        let rule = Rule::new(
            Table::Nat,
            Chain::Prerouting,
            Target::Dnat {
                to: "192.168.1.1".parse().unwrap(),
                port: Some(8080),
            },
        )
        .in_interface("wlan0")
        .protocol(Protocol::Tcp)
        .dst_port(80);

        let args = rule.to_args("-A");
        assert!(args.contains(&"DNAT".to_string()));
        assert!(args.contains(&"--to-destination".to_string()));
        assert!(args.contains(&"192.168.1.1:8080".to_string()));
    }
}
