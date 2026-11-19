//! The admin listener's reload status, and the webhook listener's push
//! deliveries. Each runs on its own listener with its own allow list.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::sync::Notify;
use tsong_config::GitHost;
use tsong_git::webhook::{pushed_branch, signature_header, verify};
use tsong_secrets::Secret;

use serde_json::json;

use crate::reload::Status;
use crate::telemetry::Metrics;

/// How the webhook knows a delivery is real and whether it matters.
pub struct Hook {
    pub host: GitHost,
    pub secret: Secret,
    /// The branch whose pushes trigger a reload.
    pub branch: String,
}

struct Admin {
    status: Arc<Mutex<Status>>,
    metrics: Arc<Metrics>,
}

/// `GET /status` and `GET /metrics`.
pub fn status_router(status: Arc<Mutex<Status>>, metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(Arc::new(Admin { status, metrics }))
}

async fn status_handler(State(admin): State<Arc<Admin>>) -> Response {
    let status = admin
        .status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    axum::Json(status).into_response()
}

/// The Prometheus text exposition format.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

async fn metrics_handler(State(admin): State<Arc<Admin>>) -> Response {
    match admin.metrics.encode() {
        Ok(text) => ([(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)], text).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /health/live`, which answers 200 while the process runs, and
/// `GET /health/ready`, which answers 200 while `ready` is set: once the
/// listeners are bound, until shutdown begins. Otherwise it answers 503.
pub fn health_router(ready: Arc<AtomicBool>) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { axum::Json(json!({ "live": true })) }),
        )
        .route("/health/ready", get(readiness))
        .with_state(ready)
}

async fn readiness(State(ready): State<Arc<AtomicBool>>) -> Response {
    if ready.load(Ordering::Acquire) {
        axum::Json(json!({ "ready": true })).into_response()
    } else {
        let body = json!({ "ready": false });
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response()
    }
}

/// The largest delivery accepted: GitHub caps push payloads at 25 MB.
pub const MAX_DELIVERY: usize = 25 * 1024 * 1024;

struct Deliveries {
    hook: Hook,
    reload: Arc<Notify>,
}

/// `POST /hooks/config`. A verified push to the watched branch wakes
/// `reload`.
pub fn webhook_router(hook: Hook, reload: Arc<Notify>) -> Router {
    Router::new()
        .route("/hooks/config", post(webhook))
        .layer(DefaultBodyLimit::max(MAX_DELIVERY))
        .with_state(Arc::new(Deliveries { hook, reload }))
}

/// 401 for a delivery that fails verification. 202 for a push to the
/// watched branch, which triggers a reload. 204 for anything else verified,
/// such as a ping or a push to another branch.
async fn webhook(
    State(deliveries): State<Arc<Deliveries>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let hook = &deliveries.hook;
    let signature = headers
        .get(signature_header(hook.host))
        .map(|value| value.as_bytes());
    if !verify(hook.host, hook.secret.expose(), signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if pushed_branch(&body).as_deref() == Some(hook.branch.as_str()) {
        deliveries.reload.notify_one();
        StatusCode::ACCEPTED.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}
