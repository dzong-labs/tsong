//! The admin listener's reload status, and the webhook listener's push
//! deliveries. Each runs on its own listener with its own allow list.

use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::sync::Notify;
use tsong_config::GitHost;
use tsong_git::webhook::{pushed_branch, signature_header, verify};

use crate::reload::Status;

/// How the webhook knows a delivery is real and whether it matters.
pub struct Hook {
    pub host: GitHost,
    pub secret: Vec<u8>,
    /// The branch whose pushes trigger a reload.
    pub branch: String,
}

/// `GET /status`.
pub fn status_router(status: Arc<Mutex<Status>>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .with_state(status)
}

async fn status_handler(State(status): State<Arc<Mutex<Status>>>) -> Response {
    let status = status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    axum::Json(status).into_response()
}

struct Deliveries {
    hook: Hook,
    reload: Arc<Notify>,
}

/// `POST /hooks/config`. A verified push to the watched branch wakes
/// `reload`.
pub fn webhook_router(hook: Hook, reload: Arc<Notify>) -> Router {
    Router::new()
        .route("/hooks/config", post(webhook))
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
    if !verify(hook.host, &hook.secret, signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if pushed_branch(&body).as_deref() == Some(hook.branch.as_str()) {
        deliveries.reload.notify_one();
        StatusCode::ACCEPTED.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}
