//! Error types for rustyjack-wireless

use std::fmt;
use thiserror::Error;

/// Result type alias for wireless operations
pub type Result<T> = std::result::Result<T, WirelessError>;

/// Main error type for wireless operations
#[derive(Error, Debug)]
pub enum WirelessError {
    /// Interface not found or invalid
    #[error("Interface error: {0}")]
    Interface(String),

    /// Monitor mode operation failed
    #[error("Monitor mode error: {0}")]
    MonitorMode(String),

    /// Channel setting failed
    #[error("Channel error: {0}")]
    Channel(String),

    /// Packet injection failed
    #[error("Injection error: {0}")]
    Injection(String),

    /// Packet capture failed
    #[error("Capture error: {0}")]
    Capture(String),

    /// Socket operation failed
    #[error("Socket error: {0}")]
    Socket(String),

    /// Netlink communication failed
    #[error("Netlink error: {0}")]
    Netlink(String),

    /// Insufficient privileges
    #[error("Permission denied: {0}")]
    Permission(String),

    /// Invalid MAC address
    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),

    /// Invalid frame format
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    /// Timeout occurred
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Operation cancelled
    #[error("Operation cancelled")]
    Cancelled,

    /// System/OS error
    #[error("System error: {0}")]
    System(String),

    /// IO error wrapper
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Driver or hardware doesn't support operation
    #[error("Unsupported: {0}")]
    Unsupported(String),
}

impl WirelessError {
    /// Create an interface error
    pub fn interface(msg: impl Into<String>) -> Self {
        Self::Interface(msg.into())
    }

    /// Create a permission error
    pub fn permission(msg: impl Into<String>) -> Self {
        Self::Permission(msg.into())
    }

    /// Create a socket error
    pub fn socket(msg: impl Into<String>) -> Self {
        Self::Socket(msg.into())
    }

    /// Create a netlink error  
    pub fn netlink(msg: impl Into<String>) -> Self {
        Self::Netlink(msg.into())
    }

    /// Check if this is a permission error
    pub fn is_permission_error(&self) -> bool {
        matches!(self, Self::Permission(_))
    }

    /// Check if this is a timeout
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

impl From<nix::Error> for WirelessError {
    fn from(err: nix::Error) -> Self {
        match err {
            nix::Error::EPERM | nix::Error::EACCES => {
                Self::Permission(format!("Operation not permitted: {}", err))
            }
            nix::Error::ENODEV | nix::Error::ENOENT => {
                Self::Interface(format!("Interface not found: {}", err))
            }
            nix::Error::EBUSY => Self::Interface(format!("Interface busy: {}", err)),
            nix::Error::EOPNOTSUPP => {
                Self::Unsupported(format!("Operation not supported: {}", err))
            }
            _ => Self::System(format!("System error: {}", err)),
        }
    }
}

/// Injection-specific error details
#[derive(Debug, Clone)]
pub struct InjectionError {
    /// Number of packets attempted
    pub attempted: u32,
    /// Number of packets that failed
    pub failed: u32,
    /// Last error message
    pub last_error: String,
}

impl fmt::Display for InjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Injection failed: {}/{} packets failed - {}",
            self.failed, self.attempted, self.last_error
        )
    }
}
