use log::{debug, info};

use crate::auth::PeerCred;
use rustyjack_ipc::{Endpoint, ErrorCode, ResponseBody, ResponseOk};

pub fn log_request(
    request_id: u64,
    endpoint: Endpoint,
    peer: PeerCred,
    duration_ms: u64,
    response: &ResponseBody,
) {
    match response {
        ResponseBody::Ok(ok_response) => {
            if let ResponseOk::JobStarted(job_started) = ok_response {
                info!(
                    "request_id={} endpoint={:?} peer_uid={} peer_pid={} duration_ms={} result=ok job_id={}",
                    request_id, endpoint, peer.uid, peer.pid, duration_ms, job_started.job_id
                );
            } else {
                info!(
                    "request_id={} endpoint={:?} peer_uid={} peer_pid={} duration_ms={} result=ok",
                    request_id, endpoint, peer.uid, peer.pid, duration_ms
                );
            }
        }
        ResponseBody::Err(err) => {
            let code_name = match err.code {
                ErrorCode::BadRequest => "bad_request",
                ErrorCode::IncompatibleProtocol => "incompatible_protocol",
                ErrorCode::Unauthorized => "unauthorized",
                ErrorCode::Forbidden => "forbidden",
                ErrorCode::NotFound => "not_found",
                ErrorCode::Busy => "busy",
                ErrorCode::Timeout => "timeout",
                ErrorCode::Cancelled => "cancelled",
                ErrorCode::Io => "io_error",
                ErrorCode::Netlink => "netlink_error",
                ErrorCode::MountFailed => "mount_failed",
                ErrorCode::WifiFailed => "wifi_failed",
                ErrorCode::UpdateFailed => "update_failed",
                ErrorCode::CleanupFailed => "cleanup_failed",
                ErrorCode::NotImplemented => "not_implemented",
                ErrorCode::Internal => "internal_error",
            };
            
            let source_str = err
                .source
                .as_ref()
                .map(|s| format!(" source={}", s))
                .unwrap_or_default();
            let retryable_str = if err.retryable { " retryable=true" } else { "" };
            
            info!(
                "request_id={} endpoint={:?} peer_uid={} peer_pid={} duration_ms={} result=error code={}{}{}",
                request_id, endpoint, peer.uid, peer.pid, duration_ms, code_name, source_str, retryable_str
            );
            
            if let Some(detail) = &err.detail {
                debug!(
                    "request_id={} error_detail: {}",
                    request_id, detail
                );
            }
        }
        ResponseBody::Event(_) => {
            info!(
                "request_id={} endpoint={:?} peer_uid={} peer_pid={} duration_ms={} result=event",
                request_id, endpoint, peer.uid, peer.pid, duration_ms
            );
        }
    }
}
