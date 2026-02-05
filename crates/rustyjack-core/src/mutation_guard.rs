//! RAII-based network mutation guard for safe cleanup
//!
//! This module provides a transaction/rollback framework for network mutations.
//! Operations that mutate system networking state (nftables rules, sysctl settings,
//! interface modes) should use `NetworkMutationGuard` to ensure cleanup on
//! error, cancellation, or panic.
//!
//! # Example
//!
//! ```ignore
//! use rustyjack_core::mutation_guard::NetworkMutationGuard;
//!
//! fn setup_nat(ap_iface: &str, upstream_iface: &str) -> anyhow::Result<()> {
//!     let mut guard = NetworkMutationGuard::new("NAT Setup");
//!
//!     // Setup step 1: enable IP forwarding
//!     enable_ip_forwarding(true)?;
//!     guard.register_rollback(|| {
//!         let _ = enable_ip_forwarding(false);
//!         Ok(())
//!     });
//!
//!     // Setup step 2: add masquerade rule
//!     add_masquerade(upstream_iface)?;
//!     let upstream = upstream_iface.to_string();
//!     guard.register_rollback(move || {
//!         let _ = delete_masquerade(&upstream);
//!         Ok(())
//!     });
//!
//!     // If we get here without errors, commit the transaction
//!     guard.commit();
//!     Ok(())
//! }
//! ```
//!
//! If an error occurs or the function returns early, the guard's `Drop` impl
//! will execute all registered rollback actions in reverse order.

use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::{error, info, warn};

/// A guard that ensures network mutations are rolled back on error/cancel
///
/// When dropped without calling `commit()`, all registered rollback actions
/// are executed in reverse order (LIFO).
pub struct NetworkMutationGuard {
    /// Human-readable name for this transaction (for logging)
    name: String,
    /// Stack of rollback closures, executed in reverse order on drop
    rollback_stack: Vec<RollbackAction>,
    /// Whether the transaction was committed successfully
    committed: bool,
}

/// A rollback action that can be executed on cleanup
type RollbackAction = Box<dyn FnOnce() -> anyhow::Result<()> + Send + 'static>;

impl NetworkMutationGuard {
    /// Create a new mutation guard with a descriptive name
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        info!(name = %name, "Starting network mutation transaction");
        Self {
            name,
            rollback_stack: Vec::new(),
            committed: false,
        }
    }

    /// Register a rollback action to be executed if the guard is dropped without commit
    ///
    /// Actions are executed in reverse order (LIFO) - the last registered action
    /// runs first during rollback.
    pub fn register_rollback<F>(&mut self, action: F)
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        self.rollback_stack.push(Box::new(action));
    }

    /// Register a simple rollback action that ignores errors
    ///
    /// Convenience method for registering actions that may fail but whose
    /// failures should be logged rather than propagated.
    pub fn register_rollback_ignore_errors<F>(&mut self, description: &'static str, action: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.rollback_stack.push(Box::new(move || {
            action();
            info!(action = %description, "Rollback action completed");
            Ok(())
        }));
    }

    /// Commit the transaction, preventing rollback on drop
    ///
    /// Call this after all operations succeed to indicate the transaction
    /// should not be rolled back.
    pub fn commit(mut self) {
        info!(name = %self.name, "Network mutation transaction committed");
        self.committed = true;
    }

    /// Explicitly trigger rollback without dropping the guard
    ///
    /// Useful for testing or when you want to handle rollback errors.
    /// Returns a vector of any errors that occurred during rollback.
    pub fn rollback(&mut self) -> Vec<anyhow::Error> {
        let mut errors = Vec::new();

        if self.committed {
            warn!(name = %self.name, "Rollback called on committed transaction");
            return errors;
        }

        info!(
            name = %self.name,
            actions = self.rollback_stack.len(),
            "Rolling back network mutations"
        );

        // Execute rollback actions in reverse order
        while let Some(action) = self.rollback_stack.pop() {
            match catch_unwind(AssertUnwindSafe(action)) {
                Ok(Ok(())) => {
                    // Action succeeded
                }
                Ok(Err(e)) => {
                    error!(name = %self.name, error = %e, "Rollback action failed");
                    errors.push(e);
                }
                Err(panic_payload) => {
                    let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    error!(name = %self.name, panic = %panic_msg, "Rollback action panicked");
                    errors.push(anyhow::anyhow!("Rollback action panicked: {}", panic_msg));
                }
            }
        }

        if errors.is_empty() {
            info!(name = %self.name, "Rollback completed successfully");
        } else {
            warn!(
                name = %self.name,
                error_count = errors.len(),
                "Rollback completed with errors"
            );
        }

        errors
    }

    /// Check if the transaction has been committed
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Get the number of pending rollback actions
    pub fn pending_actions(&self) -> usize {
        self.rollback_stack.len()
    }
}

impl Drop for NetworkMutationGuard {
    fn drop(&mut self) {
        if !self.committed && !self.rollback_stack.is_empty() {
            warn!(
                name = %self.name,
                "Network mutation guard dropped without commit - executing rollback"
            );
            let errors = self.rollback();
            if !errors.is_empty() {
                error!(
                    name = %self.name,
                    error_count = errors.len(),
                    "Rollback completed with {} errors",
                    errors.len()
                );
            }
        }
    }
}

/// Convenience trait for wrapping operations with automatic rollback registration
pub trait WithRollback<T> {
    /// Execute an operation and register its rollback action
    fn with_rollback<F, R>(
        self,
        guard: &mut NetworkMutationGuard,
        rollback_action: F,
    ) -> anyhow::Result<T>
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
        R: FnOnce() -> anyhow::Result<()> + Send + 'static;
}

impl<T> WithRollback<T> for anyhow::Result<T> {
    fn with_rollback<F, R>(
        self,
        guard: &mut NetworkMutationGuard,
        rollback_action: F,
    ) -> anyhow::Result<T>
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
        R: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        match self {
            Ok(value) => {
                guard.register_rollback(rollback_action);
                Ok(value)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_guard_rollback_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        {
            let mut guard = NetworkMutationGuard::new("test");
            guard.register_rollback(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            // Drop without commit
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_guard_no_rollback_on_commit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        {
            let mut guard = NetworkMutationGuard::new("test");
            guard.register_rollback(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            guard.commit();
        }

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_rollback_order_is_lifo() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let order1 = order.clone();
        let order2 = order.clone();
        let order3 = order.clone();

        {
            let mut guard = NetworkMutationGuard::new("test");
            guard.register_rollback(move || {
                order1.lock().unwrap().push(1);
                Ok(())
            });
            guard.register_rollback(move || {
                order2.lock().unwrap().push(2);
                Ok(())
            });
            guard.register_rollback(move || {
                order3.lock().unwrap().push(3);
                Ok(())
            });
            // Drop without commit
        }

        let final_order = order.lock().unwrap();
        assert_eq!(*final_order, vec![3, 2, 1]); // LIFO order
    }

    #[test]
    fn test_rollback_continues_after_error() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter1 = counter.clone();
        let counter2 = counter.clone();

        {
            let mut guard = NetworkMutationGuard::new("test");
            guard.register_rollback(move || {
                counter1.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            guard.register_rollback(move || {
                anyhow::bail!("Intentional error");
            });
            guard.register_rollback(move || {
                counter2.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            // Drop without commit
        }

        // Both successful actions should have run despite the error in the middle
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
