use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{debug, info};

use super::ops::{NetOps, RouteEntry};

pub struct RouteManager {
    ops: Arc<dyn NetOps>,
}

impl RouteManager {
    pub fn new(ops: Arc<dyn NetOps>) -> Self {
        Self { ops }
    }

    pub fn set_default_route(&self, iface: &str, gateway: Ipv4Addr, metric: u32) -> Result<()> {
        info!(
            "Setting default route: via {} gw {} metric {}",
            iface, gateway, metric
        );

        let existing = self.ops.list_routes().context("failed to list routes")?;

        for route in existing {
            if route.destination.is_none() {
                debug!("Removing existing default route via {}", route.interface);
                self.ops
                    .delete_default_route(&route.interface)
                    .context("failed to delete existing default route")?;
            }
        }

        self.ops
            .add_default_route(iface, gateway, metric)
            .context("failed to add default route")?;

        let verification = self.get_default_route()?;
        match verification {
            Some(route) if route.interface == iface && route.gateway == gateway => {
                info!("Default route successfully set and verified");
                Ok(())
            }
            Some(route) => {
                bail!(
                    "Route verification failed: expected {}, got {}",
                    iface,
                    route.interface
                );
            }
            None => {
                bail!("Route verification failed: no default route found after adding");
            }
        }
    }

    pub fn delete_default_route(&self, iface: &str) -> Result<()> {
        debug!("Deleting default routes for: {}", iface);
        self.ops.delete_default_route(iface)
    }

    pub fn get_default_route(&self) -> Result<Option<RouteEntry>> {
        let routes = self.ops.list_routes().context("failed to list routes")?;

        Ok(routes.into_iter().find(|r| r.destination.is_none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::ops::tests::MockNetOps;

    #[test]
    fn test_set_default_route() {
        let mock = Arc::new(MockNetOps::new());
        let manager = RouteManager::new(mock.clone());

        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        manager.set_default_route("eth0", gateway, 100).unwrap();

        let routes = mock.get_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].interface, "eth0");
        assert_eq!(routes[0].gateway, gateway);
        assert_eq!(routes[0].metric, 100);
    }

    #[test]
    fn test_get_default_route() {
        let mock = Arc::new(MockNetOps::new());
        let manager = RouteManager::new(mock.clone());

        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        manager.set_default_route("eth0", gateway, 100).unwrap();

        let route = manager.get_default_route().unwrap();
        assert!(route.is_some());
        let route = route.unwrap();
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.gateway, gateway);
    }

    #[test]
    fn test_delete_default_route() {
        let mock = Arc::new(MockNetOps::new());
        let manager = RouteManager::new(mock.clone());

        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        manager.set_default_route("eth0", gateway, 100).unwrap();
        manager.delete_default_route("eth0").unwrap();

        let routes = mock.get_routes();
        assert_eq!(routes.len(), 0);
    }

    #[test]
    fn test_replace_default_route() {
        let mock = Arc::new(MockNetOps::new());
        let manager = RouteManager::new(mock.clone());

        // Add first route
        let gateway1 = Ipv4Addr::new(192, 168, 1, 1);
        manager.set_default_route("eth0", gateway1, 100).unwrap();

        // Replace with second route
        let gateway2 = Ipv4Addr::new(10, 0, 0, 1);
        manager.set_default_route("wlan0", gateway2, 200).unwrap();

        // Should only have the second route
        let routes = mock.get_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].interface, "wlan0");
        assert_eq!(routes[0].gateway, gateway2);
    }
}
