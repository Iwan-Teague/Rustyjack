use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonError {
    pub code: ErrorCode,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
    pub source: Option<String>,
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Primary message
        write!(f, "{}", self.message)?;

        // Add detail if present (for verbose output)
        if let Some(ref detail) = self.detail {
            if !detail.is_empty() && detail != &self.message {
                write!(f, " ({})", detail)?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for DaemonError {}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    BadRequest = 1,
    IncompatibleProtocol = 2,
    Unauthorized = 3,
    Forbidden = 4,
    NotFound = 5,
    Busy = 6,
    Timeout = 7,
    Cancelled = 8,
    Io = 9,
    Netlink = 10,
    MountFailed = 11,
    WifiFailed = 12,
    UpdateFailed = 13,
    CleanupFailed = 14,
    NotImplemented = 15,
    Internal = 16,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ErrorCode::BadRequest => "bad request",
            ErrorCode::IncompatibleProtocol => "protocol error",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not found",
            ErrorCode::Busy => "busy",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::Io => "I/O error",
            ErrorCode::Netlink => "netlink error",
            ErrorCode::MountFailed => "mount failed",
            ErrorCode::WifiFailed => "wifi failed",
            ErrorCode::UpdateFailed => "update failed",
            ErrorCode::CleanupFailed => "cleanup failed",
            ErrorCode::NotImplemented => "not implemented",
            ErrorCode::Internal => "internal error",
        };
        write!(f, "{}", label)
    }
}

impl DaemonError {
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
            retryable,
            source: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}
