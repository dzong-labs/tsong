use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::sync::Notify;
use tower::ServiceExt;
use tsong::admin::{Hook, status_router, webhook_router};
use tsong::reload::Status;
use tsong_config::{GitHost, hex};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const PUSH_MAIN: &str = r#"{"ref":"refs/heads/main","after":"abc"}"#;

/// A fresh webhook secret, as hex text.
fn secret() -> TestResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(hex(&bytes))
}

struct Fixture {
    router: Router,
    reload: Arc<Notify>,
    secret: String,
}

fn webhook(host: GitHost) -> TestResult<Fixture> {
    let reload = Arc::new(Notify::new());
    let secret = secret()?;
    let hook = Hook {
        host,
        secret: secret.clone().into_bytes(),
        branch: "main".into(),
    };
    Ok(Fixture {
        router: webhook_router(hook, reload.clone()),
        reload,
        secret,
    })
}

fn github_signature(secret: &str, body: &str) -> TestResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(body.as_bytes());
    Ok(format!("sha256={}", hex(&mac.finalize().into_bytes())))
}

/// Delivers `body` with `header` set to `value`, returning the status.
async fn deliver(f: &Fixture, header: &str, value: &str, body: &str) -> TestResult<StatusCode> {
    let request = Request::post("/hooks/config")
        .header(header, value)
        .body(Body::from(body.to_owned()))?;
    Ok(f.router.clone().oneshot(request).await?.status())
}

/// Whether `reload` was notified, without waiting long.
async fn notified(reload: &Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(50), reload.notified())
        .await
        .is_ok()
}

#[tokio::test]
async fn status_reports_the_reloads() -> TestResult {
    let status = Arc::new(Mutex::new(Status {
        revision: "r7".into(),
        loaded_at: 42,
        reloads: 3,
        failed_reloads: 1,
        last_failure: Some("fetch_failed".into()),
    }));
    let response = status_router(status)
        .oneshot(Request::get("/status").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        body,
        json!({
            "revision": "r7",
            "loaded_at": 42,
            "reloads": 3,
            "failed_reloads": 1,
            "last_failure": "fetch_failed",
        })
    );
    Ok(())
}

#[tokio::test]
async fn the_status_listener_has_no_webhook() -> TestResult {
    let router = status_router(Arc::default());
    let request = Request::post("/hooks/config").body(Body::from(PUSH_MAIN))?;
    assert_eq!(
        router.oneshot(request).await?.status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn the_webhook_listener_has_no_status() -> TestResult {
    let f = webhook(GitHost::GitHub)?;
    let request = Request::get("/status").body(Body::empty())?;
    assert_eq!(
        f.router.clone().oneshot(request).await?.status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn a_signed_github_push_to_the_branch_triggers_a_reload() -> TestResult {
    let f = webhook(GitHost::GitHub)?;
    let signature = github_signature(&f.secret, PUSH_MAIN)?;
    let status = deliver(&f, "x-hub-signature-256", &signature, PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn other_verified_deliveries_are_acknowledged_and_ignored() -> TestResult {
    let f = webhook(GitHost::GitHub)?;
    for body in [
        r#"{"ref":"refs/heads/next"}"#,
        r#"{"zen":"Keep it logically awesome."}"#,
    ] {
        let signature = github_signature(&f.secret, body)?;
        let status = deliver(&f, "x-hub-signature-256", &signature, body).await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    assert!(!notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn an_unverified_delivery_is_refused() -> TestResult {
    let f = webhook(GitHost::GitHub)?;
    let wrong = github_signature(&secret()?, PUSH_MAIN)?;
    let status = deliver(&f, "x-hub-signature-256", &wrong, PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unsigned = Request::post("/hooks/config").body(Body::from(PUSH_MAIN))?;
    let status = f.router.clone().oneshot(unsigned).await?.status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let gitlab_style = deliver(&f, "x-gitlab-token", &f.secret, PUSH_MAIN).await?;
    assert_eq!(gitlab_style, StatusCode::UNAUTHORIZED);
    assert!(!notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn a_gitlab_push_carries_the_token() -> TestResult {
    let f = webhook(GitHost::GitLab)?;
    let status = deliver(&f, "x-gitlab-token", &f.secret, PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(notified(&f.reload).await);
    let wrong = deliver(&f, "x-gitlab-token", &secret()?, PUSH_MAIN).await?;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn a_large_push_is_read_whole() -> TestResult {
    let f = webhook(GitHost::GitHub)?;
    let padding = "x".repeat(3 * 1024 * 1024);
    let body = format!(r#"{{"ref":"refs/heads/main","padding":"{padding}"}}"#);
    let signature = github_signature(&f.secret, &body)?;
    let status = deliver(&f, "x-hub-signature-256", &signature, &body).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    let too_large = "x".repeat(tsong::admin::MAX_DELIVERY + 1);
    let status = deliver(&f, "x-hub-signature-256", &signature, &too_large).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}
