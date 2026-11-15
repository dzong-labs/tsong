mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong_issuer::{ACCESS_TOKEN, TOKEN_EXCHANGE, router};

async fn send(h: &Harness, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = router(h.issuer.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

fn form(body: &str) -> Request<Body> {
    Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn exchange_form(h: &Harness, audience: &str) -> String {
    let token = h.inbound.sign(&subject(json!({})));
    format!(
        "grant_type={}&subject_token={token}&subject_token_type={}&audience={audience}",
        TOKEN_EXCHANGE.replace(':', "%3A"),
        ACCESS_TOKEN.replace(':', "%3A"),
    )
}

fn assert_not_cached(headers: &axum::http::HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
}

#[tokio::test]
async fn the_token_endpoint_exchanges_a_form() {
    let h = harness();
    let (status, headers, body) = send(&h, form(&exchange_form(&h, "orders-api"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_not_cached(&headers);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN);
    assert_eq!(body["expires_in"], 900);
    assert_eq!(body["scope"], "orders.read orders.write");
    assert_eq!(body["access_token"].as_str().unwrap().split('.').count(), 3);
}

#[tokio::test]
async fn a_route_without_scopes_omits_the_scope_field() {
    let h = harness();
    let (status, _, body) = send(&h, form(&exchange_form(&h, "plain.test"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("scope").is_none());
}

#[tokio::test]
async fn errors_are_oauth_json() {
    let h = harness();
    let (status, headers, body) = send(&h, form(&exchange_form(&h, "nowhere"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_not_cached(&headers);
    assert_eq!(
        body,
        json!({
            "error": "invalid_target",
            "error_description": r#"no route has audience "nowhere""#,
        })
    );
}

#[tokio::test]
async fn an_unavailable_jwks_is_a_503() {
    let h = harness();
    h.fetcher.fail(true);
    let (status, _, body) = send(&h, form(&exchange_form(&h, "orders-api"))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn a_body_that_is_not_a_form_is_an_invalid_request() {
    let h = harness();
    let request = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, headers, body) = send(&h, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_not_cached(&headers);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn the_jwks_is_served() {
    let h = harness();
    let request = Request::get("/jwks.json").body(Body::empty()).unwrap();
    let (status, _, body) = send(&h, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, h.issuer.jwks());
}

#[tokio::test]
async fn the_discovery_document_is_served() {
    let h = harness();
    let request = Request::get("/.well-known/openid-configuration")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&h, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, h.issuer.discovery());
}
