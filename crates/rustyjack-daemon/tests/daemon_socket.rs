#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::Notify;

use rustyjack_client::{ClientConfig, DaemonClient};
use rustyjack_daemon::{config::DaemonConfig, ops::OpsConfig, server, state::DaemonState};
use rustyjack_ipc::{CoreDispatchRequest, ErrorCode, LegacyCommand, RequestBody, ResponseBody};

#[tokio::test(flavor = "current_thread")]
async fn status_reports_ops_and_core_dispatch_forbidden() {
    let socket_path =
        std::env::temp_dir().join(format!("rustyjackd-test-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("bind socket");

    let mut config = DaemonConfig::from_env();
    config.socket_path = socket_path.clone();
    config.ops = OpsConfig::appliance_defaults();
    config.allow_core_dispatch = false;

    let state = Arc::new(DaemonState::new(config));
    let shutdown = Arc::new(Notify::new());
    let server_state = Arc::clone(&state);
    let server_shutdown = Arc::clone(&shutdown);

    let server_task = tokio::spawn(async move {
        server::run(listener, server_state, server_shutdown).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = DaemonClient::connect_with_config(ClientConfig {
        socket_path: socket_path.clone(),
        client_name: "daemon-test".to_string(),
        client_version: "test".to_string(),
        ..Default::default()
    })
    .await
    .expect("connect");

    let status = client.status().await.expect("status");
    assert!(status.ops.wifi_ops);
    assert!(status.ops.eth_ops);
    assert!(!status.ops.system_ops);

    let response = client
        .request(RequestBody::CoreDispatch(CoreDispatchRequest {
            legacy: LegacyCommand::CommandDispatch,
            args: serde_json::json!({}),
        }))
        .await
        .expect("core dispatch request");

    match response {
        ResponseBody::Err(err) => assert_eq!(err.code, ErrorCode::Forbidden),
        _ => panic!("expected forbidden response"),
    }

    shutdown.notify_waiters();
    let _ = server_task.await;
    let _ = std::fs::remove_file(&socket_path);
}
