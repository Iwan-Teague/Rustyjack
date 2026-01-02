use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonError {
    pub code: ErrorCode,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
    pub source: Option<String>,
}

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
