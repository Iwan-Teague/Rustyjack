//! Routing table management via rtnetlink.
//!
//! Provides direct kernel interface for managing routing tables without calling `ip route` command.
//! Supports adding/deleting default routes and querying the routing table.

use crate::error::{NetlinkError, Result};
use futures::stream::TryStreamExt;
use netlink_packet_route::route::RouteAttribute;
use rtnetlink::{new_connection, Handle};
use std::net::IpAddr;

/// Manager for routing table operations.
///
/// Uses rtnetlink for direct kernel communication. Each manager maintains its own
/// netlink connection spawned as a background tokio task.
pub struct RouteManager {
    handle: Handle,
}

impl RouteManager {
    /// Create a new route manager.
    ///
    /// # Errors
    ///
    /// Returns error if netlink connection cannot be established.
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| NetlinkError::runtime("creating netlink connection for route management", e.to_string()))?;
        
        tokio::spawn(connection);
        
        Ok(Self { handle })
    }

    /// Add a default route via the specified gateway.
    ///
    /// # Arguments
    ///
    /// * `gateway` - Gateway IP address (IPv4 or IPv6)
    /// * `interface` - Outgoing interface name (must exist)
    ///
    /// # Errors
    ///
    /// * `InterfaceNotFound` - Interface does not exist
    /// * `AddRouteError` - Route already exists or invalid gateway
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// let gateway = "192.168.1.1".parse()?;
    /// add_default_route(gateway, "eth0").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add_default_route(&self, gateway: IpAddr, interface: &str) -> Result<()> {
        if interface.is_empty() {
            return Err(NetlinkError::InvalidArgument {
                parameter: "interface name".to_string(),
                value: "".to_string(),
                reason: "Interface name cannot be empty".to_string(),
            });
        }
        let index = self.get_interface_index(interface).await?;
        
        match gateway {
            IpAddr::V4(gw) => {
                self.handle.route().add()
                    .v4()
                    .gateway(gw)
                    .output_interface(index)
                    .execute()
                    .await
                    .map_err(|e| NetlinkError::AddRouteError {
                        destination: "default".to_string(),
                        gateway: gateway.to_string(),
                        interface: interface.to_string(),
                        reason: e.to_string(),
                    })?;
            }
            IpAddr::V6(gw) => {
                self.handle.route().add()
                    .v6()
                    .gateway(gw)
                    .output_interface(index)
                    .execute()
                    .await
                    .map_err(|e| NetlinkError::AddRouteError {
                        destination: "default".to_string(),
                        gateway: gateway.to_string(),
                        interface: interface.to_string(),
                        reason: e.to_string(),
                    })?;
            }
        }
        
        log::info!("Added default route via {} on {}", gateway, interface);
        Ok(())
    }

    /// Delete all default routes.
    ///
    /// Removes all IPv4 default routes (0.0.0.0/0). Useful for reconfiguring networking or DHCP renewal.
    ///
    /// # Errors
    ///
    /// * `DeleteRouteError` - Failed to delete route (insufficient permissions, etc.)
    /// * `Runtime` - Failed to enumerate routes
    pub async fn delete_default_route(&self) -> Result<()> {
        let mut routes = self.handle.route().get(rtnetlink::IpVersion::V4).execute();
        
        while let Some(route) = routes.try_next().await
            .map_err(|e| NetlinkError::ListRoutesError { reason: e.to_string() })? 
        {
            let mut is_default = false;
            let mut gateway = None;
            let mut oif = None;
            
            for nla in &route.attributes {
                match nla {
                    RouteAttribute::Destination(dst) => {
                        // Check if all octets are zero (default route)
                        if let Some(ip) = route_address_to_ipaddr(dst) {
                            match ip {
                                IpAddr::V4(v4) => {
                                    is_default = v4.octets().iter().all(|&b| b == 0);
                                }
                                IpAddr::V6(v6) => {
                                    is_default = v6.octets().iter().all(|&b| b == 0);
                                }
                            }
                        }
                    }
                    RouteAttribute::Gateway(gw) => {
                        gateway = route_address_to_ipaddr(gw);
                    }
                    RouteAttribute::Oif(idx) => {
                        oif = Some(*idx);
                    }
                    _ => {}
                }
            }
            
            if is_default {
                let mut del = self.handle.route().del(route.clone());
                del.message_mut().header = route.header;
                
                del.execute()
                    .await
                    .map_err(|e| NetlinkError::DeleteRouteError {
                        destination: "default".to_string(),
                        interface: format!("{:?}", oif),
                        reason: e.to_string(),
                    })?;
                
                log::info!("Deleted default route via {:?} on interface {:?}", gateway, oif);
            }
        }
        
        Ok(())
    }

    /// List all IPv4 routes in the routing table.
    ///
    /// Returns detailed route information including destination, gateway, and output interface.
    ///
    /// # Errors
    ///
    /// * `Runtime` - Failed to enumerate routes
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rustyjack_netlink::*;
    /// # async fn example() -> Result<()> {
    /// for route in list_routes().await? {
    ///     println!("Destination: {:?}/{}, Gateway: {:?}",
    ///         route.destination, route.prefix_len, route.gateway);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_routes(&self) -> Result<Vec<RouteInfo>> {
        let mut routes_v4 = self.handle.route().get(rtnetlink::IpVersion::V4).execute();
        let mut route_list = Vec::new();
        
        while let Some(route) = routes_v4.try_next().await
            .map_err(|e| NetlinkError::ListRoutesError { reason: e.to_string() })? 
        {
            let mut destination = None;
            let mut gateway = None;
            let mut oif = None;
            let prefix_len = route.header.destination_prefix_length;
            
            for nla in route.attributes {
                match nla {
                    RouteAttribute::Destination(dst) => {
                        destination = route_address_to_ipaddr(&dst);
                    }
                    RouteAttribute::Gateway(gw) => {
                        gateway = route_address_to_ipaddr(&gw);
                    }
                    RouteAttribute::Oif(idx) => {
                        oif = Some(idx);
                    }
                    _ => {}
                }
            }
            
            if destination.is_some() || gateway.is_some() {
                route_list.push(RouteInfo {
                    destination,
                    prefix_len,
                    gateway,
                    interface_index: oif,
                });
            }
        }
        
        Ok(route_list)
    }

    async fn get_interface_index(&self, name: &str) -> Result<u32> {
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
}

/// Convert RouteAddress to IpAddr
fn route_address_to_ipaddr(addr: &netlink_packet_route::route::RouteAddress) -> Option<IpAddr> {
    use netlink_packet_route::route::RouteAddress;
    match addr {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

/// Routing table entry information.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Destination network (None for default route 0.0.0.0/0)
    pub destination: Option<IpAddr>,
    /// Network prefix length
    pub prefix_len: u8,
    /// Gateway IP address, if any
    pub gateway: Option<IpAddr>,
    /// Output interface index, if specified
    pub interface_index: Option<u32>,
}

