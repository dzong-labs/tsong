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
use tsong::admin::{Hook, router};
use tsong::reload::Status;
use tsong_config::{GitHost, hex};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const SECRET: &[u8] = b"s3cret";
const PUSH_MAIN: &str = r#"{"ref":"refs/heads/main","after":"abc"}"#;

struct Fixture {
    router: Router,
    reload: Arc<Notify>,
}

fn fixture(host: Option<GitHost>) -> Fixture {
    let reload = Arc::new(Notify::new());
    let status = Arc::new(Mutex::new(Status {
        revision: "r7".into(),
        author: Some("Ada <ada@example.test>".into()),
        loaded_at: 42,
        reloads: 3,
        failed_reloads: 1,
        last_failure: Some("fetching: offline".into()),
    }));
    let hook = host.map(|host| Hook {
        host,
        secret: SECRET.to_vec(),
        branch: "main".into(),
    });
    Fixture {
        router: router(hook, reload.clone(), status),
        reload,
    }
}

fn github_signature(body: &str) -> TestResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET)?;
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
    let f = fixture(None);
    let response = f
        .router
        .oneshot(Request::get("/status").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        body,
        json!({
            "revision": "r7",
            "author": "Ada <ada@example.test>",
            "loaded_at": 42,
            "reloads": 3,
            "failed_reloads": 1,
            "last_failure": "fetching: offline",
        })
    );
    Ok(())
}

#[tokio::test]
async fn without_a_hook_there_is_no_webhook() -> TestResult {
    let f = fixture(None);
    let status = deliver(&f, "x-gitlab-token", "s3cret", PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn a_signed_github_push_to_the_branch_triggers_a_reload() -> TestResult {
    let f = fixture(Some(GitHost::GitHub));
    let signature = github_signature(PUSH_MAIN)?;
    let status = deliver(&f, "x-hub-signature-256", &signature, PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn other_verified_deliveries_are_acknowledged_and_ignored() -> TestResult {
    let f = fixture(Some(GitHost::GitHub));
    for body in [
        r#"{"ref":"refs/heads/next"}"#,
        r#"{"zen":"Keep it logically awesome."}"#,
    ] {
        let signature = github_signature(body)?;
        let status = deliver(&f, "x-hub-signature-256", &signature, body).await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    assert!(!notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn an_unverified_delivery_is_refused() -> TestResult {
    let f = fixture(Some(GitHost::GitHub));
    let wrong = github_signature(r#"{"ref":"refs/heads/other"}"#)?;
    let status = deliver(&f, "x-hub-signature-256", &wrong, PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let unsigned = Request::post("/hooks/config").body(Body::from(PUSH_MAIN))?;
    let status = f.router.clone().oneshot(unsigned).await?.status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let gitlab_style = deliver(&f, "x-gitlab-token", "s3cret", PUSH_MAIN).await?;
    assert_eq!(gitlab_style, StatusCode::UNAUTHORIZED);
    assert!(!notified(&f.reload).await);
    Ok(())
}

#[tokio::test]
async fn a_gitlab_push_carries_the_token() -> TestResult {
    let f = fixture(Some(GitHost::GitLab));
    let status = deliver(&f, "x-gitlab-token", "s3cret", PUSH_MAIN).await?;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(notified(&f.reload).await);
    let wrong = deliver(&f, "x-gitlab-token", "guess", PUSH_MAIN).await?;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    Ok(())
}
