//! Network interface management via rtnetlink.
//!
//! Provides direct kernel interface for configuring network interfaces without calling `ip` command.
//! All operations are async and use netlink sockets for communication with the kernel.

use crate::error::{NetlinkError, Result};
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Handle};
use std::net::IpAddr;

/// Manager for network interface operations (bring up/down, addresses, MAC queries).
///
/// Uses rtnetlink for direct kernel communication. Each manager maintains its own
/// netlink connection spawned as a background tokio task.
pub struct InterfaceManager {
    handle: Handle,
}

impl InterfaceManager {
    /// Create a new interface manager.
    ///
    /// # Errors
    ///
    /// Returns error if netlink connection cannot be established.
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| NetlinkError::runtime("creating netlink connection for interface management", e.to_string()))?;
        
        tokio::spawn(connection);
        
        Ok(Self { handle })
    }

    /// Get the kernel index for a network interface by name.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (e.g., "eth0", "wlan0"). Must be non-empty and valid.
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `InterfaceIndexError` - Failed to query interface
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// let mgr = InterfaceManager::new()?;
    /// let index = mgr.get_interface_index("eth0").await?;
    /// println!("eth0 index: {}", index);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_interface_index(&self, name: &str) -> Result<u32> {
        if name.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();
        
        if let Some(link) = links.try_next().await
            .map_err(|e| NetlinkError::InterfaceIndexError {
                interface: name.to_string(),
                reason: e.to_string(),
            })? 
        {
            Ok(link.header.index)
        } else {
            Err(NetlinkError::InterfaceNotFound { name: name.to_string() })
        }
    }

    /// Bring a network interface up (set IFF_UP flag).
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name. Must exist and be non-empty.
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `SetStateError` - Failed to set interface state (insufficient permissions, etc.)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// set_interface_up("eth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_interface_up(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        let index = self.get_interface_index(name).await?;
        
        self.handle
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .map_err(|e| NetlinkError::SetStateError {
                interface: name.to_string(),
                desired_state: "UP".to_string(),
                reason: e.to_string(),
            })?;
        
        log::info!("Interface {} set to UP", name);
        Ok(())
    }

    /// Bring a network interface down (clear IFF_UP flag).
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name. Must exist and be non-empty.
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `SetStateError` - Failed to set interface state
    pub async fn set_interface_down(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        let index = self.get_interface_index(name).await?;
        
        self.handle
            .link()
            .set(index)
            .down()
            .execute()
            .await
            .map_err(|e| NetlinkError::SetStateError {
                interface: name.to_string(),
                desired_state: "DOWN".to_string(),
                reason: e.to_string(),
            })?;
        
        log::info!("Interface {} set to DOWN", name);
        Ok(())
    }

    /// Add an IP address to an interface.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist)
    /// * `addr` - IPv4 or IPv6 address to add
    /// * `prefix_len` - Network prefix length (0-32 for IPv4, 0-128 for IPv6)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `AddAddressError` - Invalid prefix length or address already exists
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// let addr = "192.168.1.100".parse()?;
    /// add_address("eth0", addr, 24).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_address(&self, interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        if interface.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        
        match addr {
            IpAddr::V4(_) if prefix_len > 32 => {
                return Err(NetlinkError::AddAddressError {
                    address: addr.to_string(),
                    prefix: prefix_len,
                    interface: interface.to_string(),
                    reason: format!("Invalid IPv4 prefix length: {} (must be 0-32)", prefix_len),
                });
            }
            IpAddr::V6(_) if prefix_len > 128 => {
                return Err(NetlinkError::AddAddressError {
                    address: addr.to_string(),
                    prefix: prefix_len,
                    interface: interface.to_string(),
                    reason: format!("Invalid IPv6 prefix length: {} (must be 0-128)", prefix_len),
                });
            }
            _ => {}
        }
        let index = self.get_interface_index(interface).await?;
        
        self.handle
            .address()
            .add(index, addr, prefix_len)
            .execute()
            .await
            .map_err(|e| NetlinkError::AddAddressError {
                address: addr.to_string(),
                prefix: prefix_len,
                interface: interface.to_string(),
                reason: e.to_string(),
            })?;
        
        log::info!("Added address {}/{} to {}", addr, prefix_len, interface);
        Ok(())
    }

    /// Remove an IP address from an interface.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist)
    /// * `addr` - IPv4 or IPv6 address to remove
    /// * `prefix_len` - Network prefix length (must match the address as added)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `DeleteAddressError` - Address not found or invalid prefix length
    pub async fn delete_address(&self, interface: &str, addr: IpAddr, prefix_len: u8) -> Result<()> {
        if interface.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        
        match addr {
            IpAddr::V4(_) if prefix_len > 32 => {
                return Err(NetlinkError::DeleteAddressError {
                    address: addr.to_string(),
                    interface: interface.to_string(),
                    reason: format!("Invalid IPv4 prefix length: {} (must be 0-32)", prefix_len),
                });
            }
            IpAddr::V6(_) if prefix_len > 128 => {
                return Err(NetlinkError::DeleteAddressError {
                    address: addr.to_string(),
                    interface: interface.to_string(),
                    reason: format!("Invalid IPv6 prefix length: {} (must be 0-128)", prefix_len),
                });
            }
            _ => {}
        }
        let index = self.get_interface_index(interface).await?;
        
        self.handle
            .address()
            .del(index, addr, prefix_len)
            .execute()
            .await
            .map_err(|e| NetlinkError::DeleteAddressError {
                address: addr.to_string(),
                interface: interface.to_string(),
                reason: e.to_string(),
            })?;
        
        log::info!("Deleted address {}/{} from {}", addr, prefix_len, interface);
        Ok(())
    }

    /// Remove all IP addresses from an interface.
    ///
    /// Iterates over all addresses and removes them. Useful for DHCP release or interface reset.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `Runtime` - Failed to enumerate addresses
    pub async fn flush_addresses(&self, interface: &str) -> Result<()> {
        if interface.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        let index = self.get_interface_index(interface).await?;
        
        let mut addrs = self.handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        
        while let Some(addr) = addrs.try_next().await
            .map_err(|e| NetlinkError::ListAddressesError {
                interface: interface.to_string(),
                reason: e.to_string(),
            })? 
        {
            for nla in addr.attributes {
                if let rtnetlink::packet::address::AddressAttribute::Address(ip) = nla {
                    let _ = self.handle
                        .address()
                        .del(index, ip, addr.header.prefix_len)
                        .execute()
                        .await;
                }
            }
        }
        
        log::info!("Flushed all addresses from {}", interface);
        Ok(())
    }

    /// List all network interfaces with their status and addresses.
    ///
    /// Returns detailed information including MAC address, up/running state, and all assigned IPs.
    ///
    /// # Errors
    ///
    /// * `ListLinksError` - Failed to enumerate interfaces
    /// * `Runtime` - Failed to query interface details
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// for iface in list_interfaces().await? {
    ///     println!("{}: {} ({})", iface.name, 
    ///         if iface.is_up { "UP" } else { "DOWN" },
    ///         iface.mac.unwrap_or_else(|| "no MAC".to_string()));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let mut links = self.handle.link().get().execute();
        let mut interfaces = Vec::new();
        
        while let Some(link) = links.try_next().await
            .map_err(|e| NetlinkError::runtime("listing network interfaces", e.to_string()))? 
        {
            let mut name = String::new();
            let mut mac = None;
            let index = link.header.index;
            let flags = link.header.flags;
            let is_up = (flags & libc::IFF_UP as u32) != 0;
            let is_running = (flags & libc::IFF_RUNNING as u32) != 0;
            
            for nla in link.attributes {
                match nla {
                    rtnetlink::packet::link::LinkAttribute::IfName(n) => name = n,
                    rtnetlink::packet::link::LinkAttribute::Address(addr) => {
                        if addr.len() == 6 {
                            mac = Some(format!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                            ));
                        }
                    }
                    _ => {}
                }
            }
            
            let addresses = self.get_interface_addresses(index).await?;
            
            interfaces.push(InterfaceInfo {
                name,
                index,
                mac,
                addresses,
                is_up,
                is_running,
            });
        }
        
        Ok(interfaces)
    }

    async fn get_interface_addresses(&self, index: u32) -> Result<Vec<AddressInfo>> {
        let mut addrs = self.handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        
        let mut addresses = Vec::new();
        
        while let Some(addr) = addrs.try_next().await
            .map_err(|e| NetlinkError::runtime(format!("listing addresses for interface index {}", index), e.to_string()))? 
        {
            for nla in addr.attributes {
                if let rtnetlink::packet::address::AddressAttribute::Address(ip) = nla {
                    addresses.push(AddressInfo {
                        address: ip,
                        prefix_len: addr.header.prefix_len,
                    });
                }
            }
        }
        
        Ok(addresses)
    }

    /// Get the MAC address of an interface as a colon-separated string.
    ///
    /// # Arguments
    ///
    /// * `interface` - Interface name (must exist and have a MAC address)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist or has no MAC address
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// let mgr = InterfaceManager::new()?;
    /// let mac = mgr.get_mac_address("eth0").await?;
    /// println!("eth0 MAC: {}", mac);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_mac_address(&self, interface: &str) -> Result<String> {
        if interface.is_empty() {
            return Err(NetlinkError::InterfaceNotFound("Interface name cannot be empty".to_string()));
        }

        let mut links = self.handle.link().get().match_name(interface.to_string()).execute();
        
        if let Some(link) = links.try_next().await
            .map_err(|e| NetlinkError::InterfaceIndexError(format!("Failed to query interface: {}", e)))? 
        {
            for nla in link.attributes {
                if let rtnetlink::packet::link::LinkAttribute::Address(addr) = nla {
                    if addr.len() == 6 {
                        return Ok(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                        ));
                    }
                }
            }
        }
        
        Err(NetlinkError::InterfaceNotFound(format!("Interface {} not found or has no MAC address", interface)))
    }
}

/// Network interface information.
///
/// Contains all details about a network interface including its addresses, MAC, and state flags.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// Kernel interface index
    pub index: u32,
    /// MAC address in colon-separated format (e.g., "aa:bb:cc:dd:ee:ff"), if available
    pub mac: Option<String>,
    /// All assigned IP addresses
    pub addresses: Vec<AddressInfo>,
    /// Interface is administratively up (IFF_UP flag)
    pub is_up: bool,
    /// Interface has carrier and is operationally up (IFF_RUNNING flag)
    pub is_running: bool,
}

/// IP address assigned to an interface.
#[derive(Debug, Clone)]
pub struct AddressInfo {
    /// IPv4 or IPv6 address
    pub address: IpAddr,
    /// Network prefix length (e.g., 24 for /24, 64 for /64)
    pub prefix_len: u8,
}
