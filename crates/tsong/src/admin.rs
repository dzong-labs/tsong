//! The admin listener: the Git host's push webhook, and the reload status.

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

struct Admin {
    hook: Option<Hook>,
    reload: Arc<Notify>,
    status: Arc<Mutex<Status>>,
}

/// `POST /hooks/config` and `GET /status`. A verified push to the watched
/// branch wakes `reload`; without a hook, the webhook answers 404.
pub fn router(hook: Option<Hook>, reload: Arc<Notify>, status: Arc<Mutex<Status>>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/hooks/config", post(webhook))
        .with_state(Arc::new(Admin {
            hook,
            reload,
            status,
        }))
}

async fn status_handler(State(admin): State<Arc<Admin>>) -> Response {
    let status = admin
        .status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    axum::Json(status).into_response()
}

/// 401 for a delivery that fails verification. 202 for a push to the
/// watched branch, which triggers a reload. 204 for anything else verified,
/// such as a ping or a push to another branch.
async fn webhook(State(admin): State<Arc<Admin>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(hook) = &admin.hook else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let signature = headers
        .get(signature_header(hook.host))
        .map(|value| value.as_bytes());
    if !verify(hook.host, &hook.secret, signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if pushed_branch(&body).as_deref() == Some(hook.branch.as_str()) {
        admin.reload.notify_one();
        StatusCode::ACCEPTED.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}
