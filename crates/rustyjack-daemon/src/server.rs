use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time;
use tracing::{debug, instrument, warn};

use rustyjack_ipc::{
    endpoint_for_body, AuthzSummary, ClientHello, DaemonError, ErrorCode, FeatureFlag, HelloAck,
    RequestEnvelope, ResponseBody, ResponseEnvelope, PROTOCOL_VERSION,
};

use crate::auth::{
    authorization_for_peer, ops_allows, peer_credentials, required_ops_for_request,
    required_tier_for_request, tier_allows,
};
use crate::config::DaemonConfig;
use crate::dispatch::handle_request;
use crate::state::DaemonState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROTOCOL_VIOLATIONS: usize = 3;
const ERROR_REQUEST_ID: u64 = 0;

fn build_feature_list(_config: &DaemonConfig) -> Vec<FeatureFlag> {
    let mut features = Vec::new();

    // Always enabled features
    features.push(FeatureFlag::JobProgress);
    features.push(FeatureFlag::UdsTimeouts);
    features.push(FeatureFlag::GroupBasedAuth);

    features
}

async fn read_frame_timed(
    stream: &mut UnixStream,
    max_frame: u32,
    timeout_duration: Duration,
) -> io::Result<Vec<u8>> {
    match time::timeout(timeout_duration, read_frame(stream, max_frame)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "frame read timeout",
        )),
    }
}

async fn write_frame_timed(
    stream: &mut UnixStream,
    payload: &[u8],
    max_frame: u32,
    timeout_duration: Duration,
) -> io::Result<()> {
    match time::timeout(timeout_duration, write_frame(stream, payload, max_frame)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "frame write timeout",
        )),
    }
}

pub async fn run(listener: UnixListener, state: Arc<DaemonState>, shutdown: Arc<Notify>) {
    let max_connections = state.config.max_connections.max(1);
    let conn_limit = Arc::new(Semaphore::new(max_connections));
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            result = listener.accept() => {
                let (stream, _addr) = match result {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!("Accept error: {}", err);
                        continue;
                    }
                };

                let permit = match conn_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!("Connection limit reached, rejecting");
                        continue;
                    }
                };

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, state).await;
                });
            }
        }
    }
}

#[instrument(skip(stream, state), fields(pid, uid, gid, tier))]
async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) {
    let peer = match peer_credentials(&stream) {
        Ok(cred) => cred,
        Err(err) => {
            warn!("Failed to read peer credentials: {}", err);
            return;
        }
    };

    // Add peer info to span
    let span = tracing::Span::current();
    span.record("pid", peer.pid);
    span.record("uid", peer.uid);
    span.record("gid", peer.gid);

    let authz = authorization_for_peer(&peer, &state.config);
    span.record("tier", format!("{:?}", authz).as_str());

    debug!("New connection accepted");

    let mut stream = stream;

    let hello_payload = match time::timeout(
        HANDSHAKE_TIMEOUT,
        read_frame(&mut stream, state.config.max_frame),
    )
    .await
    {
        Ok(Ok(payload)) => payload,
        Ok(Err(err)) => {
            warn!("Handshake frame error: {}", err);
            return;
        }
        Err(_) => {
            warn!("Handshake timed out from pid {}", peer.pid);
            return;
        }
    };

    let hello: ClientHello = match serde_json::from_slice(&hello_payload) {
        Ok(hello) => hello,
        Err(err) => {
            let _ = send_error_timed(
                &mut stream,
                PROTOCOL_VERSION,
                ERROR_REQUEST_ID,
                protocol_violation(format!("invalid hello: {}", err)),
                state.config.max_frame,
                state.config.write_timeout,
            )
            .await;
            return;
        }
    };

    if hello.protocol_version != PROTOCOL_VERSION {
        let _ = send_error_timed(
            &mut stream,
            PROTOCOL_VERSION,
            ERROR_REQUEST_ID,
            DaemonError::new(
                ErrorCode::IncompatibleProtocol,
                format!("unsupported protocol {}", hello.protocol_version),
                false,
            ),
            state.config.max_frame,
            state.config.write_timeout,
        )
        .await;
        return;
    }

    let ack = HelloAck {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: state.version.clone(),
        features: build_feature_list(&state.config),
        max_frame: state.config.max_frame,
        authz: AuthzSummary {
            uid: peer.uid,
            gid: peer.gid,
            role: authz,
        },
    };

    let ack_bytes = match serde_json::to_vec(&ack) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!("Failed to serialize hello ack: {}", err);
            return;
        }
    };

    if let Err(err) = write_frame_timed(
        &mut stream,
        &ack_bytes,
        state.config.max_frame,
        state.config.write_timeout,
    )
    .await
    {
        warn!("Failed to send hello ack: {}", err);
        return;
    }

    let max_rps = state.config.max_requests_per_second;
    let mut tokens = max_rps;
    let mut last_refill = Instant::now();
    let mut violations = 0usize;

    loop {
        let payload = match read_frame_timed(
            &mut stream,
            state.config.max_frame,
            state.config.read_timeout,
        )
        .await
        {
            Ok(payload) => payload,
            Err(err) => {
                if err.kind() == io::ErrorKind::TimedOut {
                    warn!("Frame read timeout from pid {} uid {}", peer.pid, peer.uid);
                    let _ = send_error_timed(
                        &mut stream,
                        PROTOCOL_VERSION,
                        ERROR_REQUEST_ID,
                        DaemonError::new(ErrorCode::Timeout, "read timeout", true),
                        state.config.max_frame,
                        state.config.write_timeout,
                    )
                    .await;
                } else if err.kind() != io::ErrorKind::UnexpectedEof {
                    warn!("Frame read error from pid {}: {}", peer.pid, err);
                }
                break;
            }
        };

        let request: RequestEnvelope = match serde_json::from_slice(&payload) {
            Ok(req) => req,
            Err(err) => {
                violations += 1;
                let _ = send_error_timed(
                    &mut stream,
                    PROTOCOL_VERSION,
                    ERROR_REQUEST_ID,
                    protocol_violation(format!("invalid request: {}", err)),
                    state.config.max_frame,
                    state.config.write_timeout,
                )
                .await;
                if violations >= MAX_PROTOCOL_VIOLATIONS {
                    warn!("Too many protocol violations from pid {}", peer.pid);
                    break;
                }
                continue;
            }
        };

        if request.v != PROTOCOL_VERSION {
            violations += 1;
            let _ = send_error_timed(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                DaemonError::new(
                    ErrorCode::IncompatibleProtocol,
                    "protocol version mismatch",
                    false,
                ),
                state.config.max_frame,
                state.config.write_timeout,
            )
            .await;
            if violations >= MAX_PROTOCOL_VIOLATIONS {
                break;
            }
            continue;
        }

        if request.endpoint != endpoint_for_body(&request.body) {
            violations += 1;
            let _ = send_error_timed(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                protocol_violation("endpoint/body mismatch"),
                state.config.max_frame,
                state.config.write_timeout,
            )
            .await;
            if violations >= MAX_PROTOCOL_VIOLATIONS {
                break;
            }
            continue;
        }

        if max_rps > 0 {
            if last_refill.elapsed() >= Duration::from_secs(1) {
                tokens = max_rps;
                last_refill = Instant::now();
            }
            if tokens == 0 {
                let _ = send_error_timed(
                    &mut stream,
                    PROTOCOL_VERSION,
                    request.request_id,
                    DaemonError::new(ErrorCode::Busy, "rate limit exceeded", true),
                    state.config.max_frame,
                    state.config.write_timeout,
                )
                .await;
                continue;
            }
            tokens -= 1;
        }

        // Create request span with timing
        let start = std::time::Instant::now();
        let request_span = tracing::info_span!(
            "request",
            request_id = request.request_id,
            endpoint = ?request.endpoint,
            duration_ms = tracing::field::Empty,
        );
        let _enter = request_span.enter();

        debug!("Processing request");

        let required = required_tier_for_request(request.endpoint, &request.body);
        if !tier_allows(authz, required) {
            let _ = send_error_timed(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                DaemonError::new(ErrorCode::Forbidden, "forbidden", false),
                state.config.max_frame,
                state.config.write_timeout,
            )
            .await;
            continue;
        }

        let required_ops = required_ops_for_request(request.endpoint, &request.body);
        let ops = state.ops_runtime.read().await;
        if !ops_allows(&ops, required_ops) {
            let _ = send_error_timed(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                DaemonError::new(
                    ErrorCode::Forbidden,
                    "operation disabled by ops config",
                    false,
                ),
                state.config.max_frame,
                state.config.write_timeout,
            )
            .await;
            continue;
        }
        drop(ops);

        let response = handle_request(&state, request, peer).await;
        let payload = match serde_json::to_vec(&response) {
            Ok(payload) => payload,
            Err(err) => {
                warn!("Failed to serialize response: {}", err);
                break;
            }
        };

        if let Err(err) = write_frame_timed(
            &mut stream,
            &payload,
            state.config.max_frame,
            state.config.write_timeout,
        )
        .await
        {
            if err.kind() == io::ErrorKind::TimedOut {
                warn!(
                    "Response write timeout to pid {} for request {}",
                    peer.pid, response.request_id
                );
            } else {
                warn!("Failed to write response: {}", err);
            }
            break;
        }

        // Record request duration
        let duration_ms = start.elapsed().as_millis() as u64;
        request_span.record("duration_ms", duration_ms);
        debug!(duration_ms, "Request completed");
    }
}

fn protocol_violation(err: impl Into<String>) -> DaemonError {
    DaemonError::new(ErrorCode::BadRequest, err, false)
}

async fn read_frame(stream: &mut UnixStream, max_frame: u32) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = match rustyjack_ipc::decode_frame_length(len_buf, max_frame) {
        Ok(len) => len,
        Err(err) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame length: {:?}", err),
            ));
        }
    };
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut UnixStream, payload: &[u8], max_frame: u32) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty payload"));
    }
    if payload.len() as u32 > max_frame {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload exceeds max_frame",
        ));
    }
    let frame = rustyjack_ipc::encode_frame(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn send_error_timed(
    stream: &mut UnixStream,
    version: u32,
    request_id: u64,
    err: DaemonError,
    max_frame: u32,
    timeout_duration: Duration,
) -> Result<()> {
    let envelope = ResponseEnvelope {
        v: version,
        request_id,
        body: ResponseBody::Err(err),
    };
    let payload = serde_json::to_vec(&envelope)?;
    write_frame_timed(stream, &payload, max_frame, timeout_duration).await?;
    Ok(())
}
