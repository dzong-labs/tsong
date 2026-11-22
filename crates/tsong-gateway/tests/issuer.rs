//! The gateway with the real issuer as its exchanger.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong_clock::ManualClock;
use tsong_gateway::Gateway;
use tsong_issuer::Issuer;
use tsong_keys::{FileKey, KeySet, SigningAlgorithm};
use tsong_validate::Validator;
use tsong_validate::testkit::{FakeFetcher, TestKey, pem};

/// The claims of a JWT, without verifying it.
fn payload(token: &str) -> TestResult<Value> {
    let payload = token.split('.').nth(1).ok_or("not a JWT")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

/// The gateway, with the real issuer as its exchanger and every route
/// pointing at an echoing downstream, and the inbound issuer's key.
async fn gateway() -> TestResult<(axum::Router, TestKey)> {
    let address = downstream().await?;
    let config = Arc::new(config_to(&format!("http://{address}"))?);
    let inbound = TestKey::new("in-1", 1)?;
    let fetcher = Arc::new(FakeFetcher::with(vec![inbound.jwk()]));
    let clock = Arc::new(ManualClock::at(NOW));
    let validator = Validator::new(&config, fetcher, clock.clone());
    let key = Arc::new(FileKey::from_pem(
        "tsong-1",
        SigningAlgorithm::ES256,
        &pem(5)?,
    )?);
    let issuer = Issuer::new(
        config.clone(),
        KeySet::new(vec![key], vec![])?,
        validator,
        clock.clone(),
    );
    let metrics = Arc::new(tsong_gateway::GatewayMetrics::default());
    let gateway = Gateway::new(&config, Arc::new(issuer), clock, metrics)?;
    let router = tsong_gateway::router(Arc::new(gateway));
    Ok((router, inbound))
}

#[tokio::test]
async fn the_issuer_mints_the_token_the_downstream_receives() -> TestResult {
    let (router, inbound) = gateway().await?;

    let token = inbound.sign(&json!({
        "iss": "https://issuer.test",
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 3600,
        "scope": "orders.read",
    }))?;
    let response = router
        .clone()
        .oneshot(get("orders.test", "/", Some(&token))?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let echoed: Value = serde_json::from_slice(&body)?;
    let authorization = echoed
        .pointer("/headers/authorization/0")
        .and_then(Value::as_str)
        .ok_or("no authorization reached the downstream")?;
    let minted = authorization
        .strip_prefix("Bearer ")
        .ok_or("not a bearer token")?;
    assert_ne!(minted, token);
    let claims = payload(minted)?;
    assert_eq!(claims.get("iss"), Some(&json!("https://tsong.test")));
    assert_eq!(claims.get("aud"), Some(&json!(["tsong", "orders.test"])));
    assert_eq!(claims.get("scope"), Some(&json!("orders.read")));

    let refused = inbound.sign(&json!({
        "iss": "https://issuer.test",
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 3600,
        "scope": "orders.delete",
    }))?;
    let response = router
        .oneshot(get("orders.test", "/", Some(&refused))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn a_malformed_scope_claim_is_an_invalid_token() -> TestResult {
    let (router, inbound) = gateway().await?;

    // Ignored, the claim would read as no scope, which the route admits.
    let token = inbound.sign(&json!({
        "iss": "https://issuer.test",
        "sub": "alice",
        "aud": "tsong",
        "exp": NOW + 3600,
        "scope": 7,
    }))?;
    let response = router
        .oneshot(get("orders.test", "/", Some(&token))?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("www-authenticate")
            .map(|value| value.as_bytes()),
        Some(&br#"Bearer error="invalid_token""#[..])
    );
    Ok(())
}
