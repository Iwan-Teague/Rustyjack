//! Error types for the evasion library
//!
//! This module defines the error types used throughout the library,
//! following Rust best practices with `thiserror` for derive macros.

use std::fmt;
use thiserror::Error;

/// Result type alias using [`EvasionError`]
pub type Result<T> = std::result::Result<T, EvasionError>;

/// Errors that can occur during evasion operations
#[derive(Error, Debug)]
pub enum EvasionError {
    /// Interface does not exist
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    /// Interface is not a wireless interface
    #[error("Not a wireless interface: {0}")]
    NotWireless(String),

    /// Invalid MAC address format
    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),

    /// Permission denied (need root or CAP_NET_ADMIN)
    #[error("Permission denied: {0}. Run as root or with CAP_NET_ADMIN")]
    PermissionDenied(String),

    /// Interface operation failed
    #[error("Interface operation failed: {0}")]
    InterfaceError(String),

    /// TX power setting failed
    #[error("TX power error: {0}")]
    TxPowerError(String),

    /// State restoration failed
    #[error("State restoration failed: {0}")]
    RestoreError(String),

    /// System command execution failed
    #[error("System error: {0}")]
    System(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// The interface is not in the expected state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Feature not supported on this system/driver
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Random number generation failed
    #[error("RNG error: {0}")]
    RngError(String),
}

impl EvasionError {
    /// Check if this error is recoverable
    ///
    /// Some errors (like permission denied) cannot be recovered from
    /// without user intervention, while others (like temporary failures)
    /// might succeed on retry.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            EvasionError::InterfaceError(_) | EvasionError::System(_)
        )
    }

    /// Check if this error is a permission error
    #[must_use]
    pub fn is_permission_error(&self) -> bool {
        matches!(self, EvasionError::PermissionDenied(_))
    }

    /// Create a permission denied error
    #[must_use]
    pub fn permission_denied(operation: impl Into<String>) -> Self {
        EvasionError::PermissionDenied(operation.into())
    }

    /// Create an interface not found error
    #[must_use]
    pub fn interface_not_found(name: impl Into<String>) -> Self {
        EvasionError::InterfaceNotFound(name.into())
    }
}

/// Error context wrapper for adding additional information to errors
pub struct ErrorContext {
    error: EvasionError,
    context: String,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.error)
    }
}

impl fmt::Debug for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorContext")
            .field("context", &self.context)
            .field("error", &self.error)
            .finish()
    }
}

impl std::error::Error for ErrorContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Extension trait for adding context to errors
pub trait ResultExt<T> {
    /// Add context to an error
    fn context(self, ctx: impl Into<String>) -> std::result::Result<T, ErrorContext>;
}

impl<T> ResultExt<T> for Result<T> {
    fn context(self, ctx: impl Into<String>) -> std::result::Result<T, ErrorContext> {
        self.map_err(|e| ErrorContext {
            error: e,
            context: ctx.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = EvasionError::InterfaceNotFound("wlan0".into());
        assert!(err.to_string().contains("wlan0"));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(EvasionError::InterfaceError("test".into()).is_recoverable());
        assert!(!EvasionError::PermissionDenied("test".into()).is_recoverable());
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let evasion_err: EvasionError = io_err.into();
        assert!(matches!(evasion_err, EvasionError::Io(_)));
    }
}
