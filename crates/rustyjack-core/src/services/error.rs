use std::fmt;

use rustyjack_ipc::{DaemonError, ErrorCode};

#[derive(Debug)]
pub enum ServiceError {
    InvalidInput(String),
    Io(std::io::Error),
    Netlink(String),
    External(String),
    Internal(String),
    OperationFailed(String),
    Cancelled,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            ServiceError::Io(err) => write!(f, "io error: {err}"),
            ServiceError::Netlink(msg) => write!(f, "netlink error: {msg}"),
            ServiceError::External(msg) => write!(f, "external error: {msg}"),
            ServiceError::Internal(msg) => write!(f, "internal error: {msg}"),
            ServiceError::OperationFailed(msg) => write!(f, "operation failed: {msg}"),
            ServiceError::Cancelled => write!(f, "operation cancelled"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<std::io::Error> for ServiceError {
    fn from(err: std::io::Error) -> Self {
        ServiceError::Io(err)
    }
}

impl From<ServiceError> for DaemonError {
    fn from(err: ServiceError) -> Self {
        err.to_daemon_error()
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
            ServiceError::OperationFailed(msg) => DaemonError::new(ErrorCode::Internal, msg, true),
            ServiceError::Cancelled => DaemonError::new(ErrorCode::Cancelled, "cancelled", false),
        }
    }

    pub fn to_daemon_error_with_source(&self, source: &'static str) -> DaemonError {
        self.to_daemon_error().with_source(source)
    }

    pub fn to_daemon_error_with_code(
        &self,
        code: ErrorCode,
        source: &'static str,
    ) -> DaemonError {
        match self {
            ServiceError::InvalidInput(msg) => DaemonError::new(ErrorCode::BadRequest, msg, false)
                .with_source(source),
            ServiceError::Io(err) => DaemonError::new(ErrorCode::Io, err.to_string(), false)
                .with_detail(format!("{:?}", err))
                .with_source(source),
            ServiceError::Netlink(msg) => DaemonError::new(ErrorCode::Netlink, msg, false)
                .with_source(source),
            ServiceError::External(msg) => DaemonError::new(code, msg, false)
                .with_source(source),
            ServiceError::Internal(msg) => DaemonError::new(ErrorCode::Internal, msg, false)
                .with_source(source),
            ServiceError::OperationFailed(msg) => DaemonError::new(code, msg, true)
                .with_source(source),
            ServiceError::Cancelled => DaemonError::new(ErrorCode::Cancelled, "cancelled", false)
                .with_source(source),
        }
    }
}
