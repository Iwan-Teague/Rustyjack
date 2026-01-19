//! Error types for WPA cracking utilities.

use thiserror::Error;

/// Result type alias for WPA operations.
pub type Result<T> = std::result::Result<T, WpaError>;

/// Error type for WPA operations.
#[derive(Error, Debug)]
pub enum WpaError {
    /// System/OS error.
    #[error("System error: {0}")]
    System(String),
}
