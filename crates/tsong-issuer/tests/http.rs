mod common;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong_issuer::{ACCESS_TOKEN, TOKEN_EXCHANGE, router};

/// The status, headers and JSON body of the issuer's response to `request`
/// from 127.0.0.1.
async fn send(h: &Harness, request: Request<Body>) -> TestResult<(StatusCode, HeaderMap, Value)> {
    send_from(h, "127.0.0.1:5000", request).await
}

/// The issuer's response to `request` on a connection from `peer`.
async fn send_from(
    h: &Harness,
    peer: &str,
    mut request: Request<Body>,
) -> TestResult<(StatusCode, HeaderMap, Value)> {
    let peer: SocketAddr = peer.parse()?;
    request.extensions_mut().insert(ConnectInfo(peer));
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
    exchange_form_with(h, audience, "")
}

/// A token exchange form for the default subject token, with `extra`
/// appended to its query.
fn exchange_form_with(h: &Harness, audience: &str, extra: &str) -> TestResult<Request<Body>> {
    let token = h.inbound.sign(&subject(json!({}))?)?;
    form(&format!(
        "grant_type={}&subject_token={token}&subject_token_type={}&audience={audience}{extra}",
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
    let (status, headers, body) = send(&h, exchange_form(&h, "orders.test")?).await?;
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
async fn a_token_narrowed_to_no_scope_omits_the_scope_field() -> TestResult {
    let h = harness()?;
    // An empty scope request narrows the minted token to no scope.
    let form = exchange_form_with(&h, "orders.test", "&scope=")?;
    let (status, _, body) = send(&h, form).await?;
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
            "error_description": r#"no route has host "nowhere""#,
        })
    );
    Ok(())
}

#[tokio::test]
async fn an_unavailable_jwks_is_a_503() -> TestResult {
    let h = harness()?;
    h.fetcher.fail(true);
    let (status, _, body) = send(&h, exchange_form(&h, "orders.test")?).await?;
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

#[tokio::test]
async fn the_token_endpoint_obeys_the_gateway_allow_list() -> TestResult {
    let h = harness()?;
    let (status, headers, body) =
        send_from(&h, "192.0.2.1:5000", exchange_form(&h, "orders.test")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_not_cached(&headers);
    assert_eq!(
        body,
        json!({
            "error": "access_denied",
            "error_description": "client address not allowed",
        })
    );
    let (status, _, _) = send_from(
        &h,
        "[::ffff:10.2.0.1]:5000",
        exchange_form(&h, "orders.test")?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn the_token_endpoint_obeys_the_route_allow_list() -> TestResult {
    let h = harness()?;
    let (status, _, body) = send_from(&h, "10.2.0.1:5000", exchange_form(&h, "OPEN.test")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.get("error"), Some(&json!("access_denied")));
    let (status, _, _) = send_from(&h, "10.1.0.1:5000", exchange_form(&h, "open.test")?).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = send_from(&h, "10.2.0.1:5000", exchange_form(&h, "nowhere")?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_target")));
    Ok(())
}

#[tokio::test]
async fn the_token_endpoint_finds_the_client_through_trusted_proxies() -> TestResult {
    let h = harness()?;
    let through = |forwarded_for: &str| -> TestResult<Request<Body>> {
        let mut request = exchange_form(&h, "open.test")?;
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded_for.parse()?);
        Ok(request)
    };
    let (status, _, _) = send_from(&h, "10.0.0.5:5000", through("10.1.0.1")?).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send_from(&h, "10.0.0.5:5000", through("10.1.0.1, 10.2.0.1")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send_from(&h, "10.2.0.1:5000", through("10.1.0.1")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, body) = send_from(&h, "10.0.0.5:5000", through("not-an-ip")?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "error": "invalid_request",
            "error_description": "malformed X-Forwarded-For",
        })
    );
    Ok(())
}

#[tokio::test]
async fn the_token_endpoint_observes_the_request_context() -> TestResult {
    let h = harness()?;
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let mut request = exchange_form(&h, "orders.test")?;
    request
        .headers_mut()
        .insert("x-request-id", "req-42".parse()?);
    request
        .headers_mut()
        .insert("traceparent", traceparent.parse()?);
    let (status, _, _) = send(&h, request).await?;
    assert_eq!(status, StatusCode::OK);
    let event = h.events.last()?;
    assert_eq!(event.context.request_id.as_deref(), Some("req-42"));
    assert_eq!(
        event.context.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    Ok(())
}
