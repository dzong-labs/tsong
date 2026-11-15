//! The issuer over HTTP: the token endpoint, the JWKS and discovery.

use std::sync::Arc;

use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::{ExchangeError, Issuer, TokenRequest};

/// The issuer's routes: `POST /token`, `GET /jwks.json` and
/// `GET /.well-known/openid-configuration`.
pub fn router(issuer: Arc<Issuer>) -> Router {
    Router::new()
        .route("/token", post(token))
        .route("/jwks.json", get(jwks))
        .route("/.well-known/openid-configuration", get(discovery))
        .with_state(issuer)
}

async fn token(
    State(issuer): State<Arc<Issuer>>,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
    let result = match form {
        Ok(Form(request)) => issuer.exchange(request).await,
        Err(rejection) => Err(ExchangeError::InvalidRequest(rejection.body_text())),
    };
    let mut response = match result {
        Ok(token) => Json(token).into_response(),
        Err(error) => {
            let status =
                StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = json!({
                "error": error.code(),
                "error_description": error.to_string(),
            });
            (status, Json(body)).into_response()
        }
    };
    // RFC 6749 section 5.1: token responses are never cached.
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn jwks(State(issuer): State<Arc<Issuer>>) -> Response {
    Json(issuer.jwks()).into_response()
}

async fn discovery(State(issuer): State<Arc<Issuer>>) -> Response {
    Json(issuer.discovery()).into_response()
}
