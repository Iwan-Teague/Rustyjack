use log::info;

use crate::auth::PeerCred;
use rustyjack_ipc::{Endpoint, ErrorCode, ResponseBody};

pub fn log_request(
    request_id: u64,
    endpoint: Endpoint,
    peer: PeerCred,
    duration_ms: u64,
    response: &ResponseBody,
) {
    let result = match response {
        ResponseBody::Ok(_) => "ok",
        ResponseBody::Err(err) => match err.code {
            ErrorCode::Cancelled => "cancelled",
            _ => "error",
        },
        ResponseBody::Event(_) => "event",
    };

    info!(
        "request_id={} endpoint={:?} peer_uid={} peer_pid={} duration_ms={} result={}",
        request_id, endpoint, peer.uid, peer.pid, duration_ms, result
    );
}
