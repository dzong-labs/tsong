mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong_issuer::{ACCESS_TOKEN, TOKEN_EXCHANGE, router};

/// The status, headers and JSON body of the issuer's response to `request`.
async fn send(h: &Harness, request: Request<Body>) -> TestResult<(StatusCode, HeaderMap, Value)> {
    let response = router(h.issuer.clone()).oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, headers, serde_json::from_slice(&bytes)?))
}

fn form(body: &str) -> TestResult<Request<Body>> {
    Ok(Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))?)
}

fn exchange_form(h: &Harness, audience: &str) -> TestResult<Request<Body>> {
    let token = h.inbound.sign(&subject(json!({}))?)?;
    form(&format!(
        "grant_type={}&subject_token={token}&subject_token_type={}&audience={audience}",
        TOKEN_EXCHANGE.replace(':', "%3A"),
        ACCESS_TOKEN.replace(':', "%3A"),
    ))
}

fn assert_not_cached(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|value| value.as_bytes()),
        Some(&b"no-store"[..])
    );
    assert_eq!(
        headers.get(header::PRAGMA).map(|value| value.as_bytes()),
        Some(&b"no-cache"[..])
    );
}

#[tokio::test]
async fn the_token_endpoint_exchanges_a_form() -> TestResult {
    let h = harness()?;
    let (status, headers, body) = send(&h, exchange_form(&h, "orders-api")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_not_cached(&headers);
    for (name, value) in [
        ("token_type", json!("Bearer")),
        ("issued_token_type", json!(ACCESS_TOKEN)),
        ("expires_in", json!(900)),
        ("scope", json!("orders.read orders.write")),
    ] {
        assert_eq!(body.get(name), Some(&value), "{name}");
    }
    let segments = body
        .get("access_token")
        .and_then(Value::as_str)
        .map(|token| token.split('.').count());
    assert_eq!(segments, Some(3));
    Ok(())
}

#[tokio::test]
async fn a_route_without_scopes_omits_the_scope_field() -> TestResult {
    let h = harness()?;
    let (status, _, body) = send(&h, exchange_form(&h, "plain.test")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("scope").is_none());
    Ok(())
}

#[tokio::test]
async fn errors_are_oauth_json() -> TestResult {
    let h = harness()?;
    let (status, headers, body) = send(&h, exchange_form(&h, "nowhere")?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_not_cached(&headers);
    assert_eq!(
        body,
        json!({
            "error": "invalid_target",
            "error_description": r#"no route has audience "nowhere""#,
        })
    );
    Ok(())
}

#[tokio::test]
async fn an_unavailable_jwks_is_a_503() -> TestResult {
    let h = harness()?;
    h.fetcher.fail(true);
    let (status, _, body) = send(&h, exchange_form(&h, "orders-api")?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("temporarily_unavailable")));
    Ok(())
}

#[tokio::test]
async fn a_body_that_is_not_a_form_is_an_invalid_request() -> TestResult {
    let h = harness()?;
    let request = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))?;
    let (status, headers, body) = send(&h, request).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_not_cached(&headers);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
    Ok(())
}

#[tokio::test]
async fn the_jwks_is_served() -> TestResult {
    let h = harness()?;
    let request = Request::get("/jwks.json").body(Body::empty())?;
    let (status, _, body) = send(&h, request).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, h.issuer.jwks());
    Ok(())
}

#[tokio::test]
async fn the_discovery_document_is_served() -> TestResult {
    let h = harness()?;
    let request = Request::get("/.well-known/openid-configuration").body(Body::empty())?;
    let (status, _, body) = send(&h, request).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, h.issuer.discovery());
    Ok(())
}
