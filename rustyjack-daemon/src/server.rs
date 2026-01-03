use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::warn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio::time;

use rustyjack_ipc::{
    endpoint_for_body, AuthzSummary, ClientHello, DaemonError, Endpoint, ErrorCode, HelloAck,
    JobStartRequest, RequestBody, RequestEnvelope, ResponseBody, ResponseEnvelope,
    PROTOCOL_VERSION,
};

use crate::auth::{
    authorization_for, peer_credentials, required_tier, required_tier_for_jobkind, tier_allows,
};
use crate::dispatch::handle_request;
use crate::state::DaemonState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROTOCOL_VIOLATIONS: usize = 3;
const ERROR_REQUEST_ID: u64 = 0;

pub async fn run(listener: UnixListener, state: Arc<DaemonState>, shutdown: Arc<Notify>) {
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

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handle_connection(stream, state).await;
                });
            }
        }
    }
}

async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) {
    let peer = match peer_credentials(&stream) {
        Ok(cred) => cred,
        Err(err) => {
            warn!("Failed to read peer credentials: {}", err);
            return;
        }
    };

    let authz = authorization_for(peer.uid);
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
            let _ = send_error(
                &mut stream,
                PROTOCOL_VERSION,
                ERROR_REQUEST_ID,
                protocol_violation(format!("invalid hello: {}", err)),
                state.config.max_frame,
            )
            .await;
            return;
        }
    };

    if hello.protocol_version != PROTOCOL_VERSION {
        let _ = send_error(
            &mut stream,
            PROTOCOL_VERSION,
            ERROR_REQUEST_ID,
            DaemonError::new(
                ErrorCode::IncompatibleProtocol,
                format!("unsupported protocol {}", hello.protocol_version),
                false,
            ),
            state.config.max_frame,
        )
        .await;
        return;
    }

    let ack = HelloAck {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: state.version.clone(),
        features: Vec::new(),
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

    if let Err(err) = write_frame(&mut stream, &ack_bytes, state.config.max_frame).await {
        warn!("Failed to send hello ack: {}", err);
        return;
    }

    let mut violations = 0usize;

    loop {
        let payload = match read_frame(&mut stream, state.config.max_frame).await {
            Ok(payload) => payload,
            Err(err) => {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    warn!("Frame read error: {}", err);
                }
                break;
            }
        };

        let request: RequestEnvelope = match serde_json::from_slice(&payload) {
            Ok(req) => req,
            Err(err) => {
                violations += 1;
                let _ = send_error(
                    &mut stream,
                    PROTOCOL_VERSION,
                    ERROR_REQUEST_ID,
                    protocol_violation(format!("invalid request: {}", err)),
                    state.config.max_frame,
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
            let _ = send_error(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                DaemonError::new(
                    ErrorCode::IncompatibleProtocol,
                    "protocol version mismatch",
                    false,
                ),
                state.config.max_frame,
            )
            .await;
            if violations >= MAX_PROTOCOL_VIOLATIONS {
                break;
            }
            continue;
        }

        if request.endpoint != endpoint_for_body(&request.body) {
            violations += 1;
            let _ = send_error(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                protocol_violation("endpoint/body mismatch"),
                state.config.max_frame,
            )
            .await;
            if violations >= MAX_PROTOCOL_VIOLATIONS {
                break;
            }
            continue;
        }

        let required = required_tier(request.endpoint);
        if !tier_allows(authz, required) {
            let _ = send_error(
                &mut stream,
                PROTOCOL_VERSION,
                request.request_id,
                DaemonError::new(ErrorCode::Forbidden, "forbidden", false),
                state.config.max_frame,
            )
            .await;
            continue;
        }

        if request.endpoint == Endpoint::JobStart {
            if let RequestBody::JobStart(JobStartRequest { ref job }) = request.body {
                let job_required = required_tier_for_jobkind(&job.kind);
                if !tier_allows(authz, job_required) {
                    let _ = send_error(
                        &mut stream,
                        PROTOCOL_VERSION,
                        request.request_id,
                        DaemonError::new(
                            ErrorCode::Forbidden,
                            "insufficient privileges for this job type",
                            false,
                        ),
                        state.config.max_frame,
                    )
                    .await;
                    continue;
                }
            }
        }

        let response = handle_request(&state, request, peer).await;
        let payload = match serde_json::to_vec(&response) {
            Ok(payload) => payload,
            Err(err) => {
                warn!("Failed to serialize response: {}", err);
                break;
            }
        };

        if let Err(err) = write_frame(&mut stream, &payload, state.config.max_frame).await {
            warn!("Failed to write response: {}", err);
            break;
        }
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload exceeds max_frame"));
    }
    let frame = rustyjack_ipc::encode_frame(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn send_error(
    stream: &mut UnixStream,
    version: u32,
    request_id: u64,
    err: DaemonError,
    max_frame: u32,
) -> Result<()> {
    let envelope = ResponseEnvelope {
        v: version,
        request_id,
        body: ResponseBody::Err(err),
    };
    let payload = serde_json::to_vec(&envelope)?;
    write_frame(stream, &payload, max_frame).await?;
    Ok(())
}
