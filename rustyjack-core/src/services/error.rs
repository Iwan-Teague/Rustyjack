use std::fmt;

use rustyjack_ipc::{DaemonError, ErrorCode};

#[derive(Debug)]
pub enum ServiceError {
    InvalidInput(String),
    Io(std::io::Error),
    Netlink(String),
    External(String),
    Internal(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            ServiceError::Io(err) => write!(f, "io error: {err}"),
            ServiceError::Netlink(msg) => write!(f, "netlink error: {msg}"),
            ServiceError::External(msg) => write!(f, "external error: {msg}"),
            ServiceError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<std::io::Error> for ServiceError {
    fn from(err: std::io::Error) -> Self {
        ServiceError::Io(err)
    }
}

impl ServiceError {
    pub fn to_daemon_error(&self) -> DaemonError {
        match self {
            ServiceError::InvalidInput(msg) => {
                DaemonError::new(ErrorCode::BadRequest, msg, false)
            }
            ServiceError::Io(err) => DaemonError::new(ErrorCode::Io, err.to_string(), false),
            ServiceError::Netlink(msg) => DaemonError::new(ErrorCode::Netlink, msg, false),
            ServiceError::External(msg) => DaemonError::new(ErrorCode::Internal, msg, false),
            ServiceError::Internal(msg) => DaemonError::new(ErrorCode::Internal, msg, false),
        }
    }
}
