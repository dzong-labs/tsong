//! Exchanges as an observer sees them, and the request context they carry.

mod common;

use axum::http::{HeaderMap, HeaderValue};
use common::*;
use serde_json::json;
use tsong_issuer::{ExchangeContext, REQUEST_ID, TRACEPARENT, request_id_is_valid, trace_id};

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";

#[test]
fn a_traceparent_names_its_trace() {
    let valid = format!("00-{TRACE}-{PARENT}-01");
    assert_eq!(trace_id(&valid), Some(TRACE));
    assert_eq!(trace_id(&format!(" {valid} ")), Some(TRACE));
    for invalid in [
        format!("01-{TRACE}-{PARENT}-01"),
        format!("00-{}-{PARENT}-01", TRACE.to_uppercase()),
        format!("00-{}-{PARENT}-01", "0".repeat(32)),
        format!("00-{TRACE}-{}-01", "0".repeat(16)),
        format!("00-{TRACE}-{PARENT}-1"),
        format!("00-{TRACE}-{PARENT}-01-extra"),
        format!("00-{TRACE}-{PARENT}"),
        format!("00-{}-{PARENT}-01", &TRACE[..31]),
        format!("00-{TRACE}-{}-01", &PARENT[..15]),
        format!("00-{TRACE}-{PARENT}-zz"),
        String::new(),
    ] {
        assert_eq!(trace_id(&invalid), None, "{invalid}");
    }
}

#[test]
fn a_request_id_is_short_visible_ascii() {
    assert!(request_id_is_valid("r-1"));
    assert!(request_id_is_valid(&"x".repeat(128)));
    assert!(!request_id_is_valid(""));
    assert!(!request_id_is_valid(&"x".repeat(129)));
    assert!(!request_id_is_valid("has space"));
    assert!(!request_id_is_valid("caf\u{e9}"));
}

#[test]
fn the_context_comes_from_the_headers() -> TestResult {
    let mut headers = HeaderMap::new();
    assert_eq!(
        ExchangeContext::from_headers(&headers),
        ExchangeContext::default()
    );
    headers.insert(REQUEST_ID, HeaderValue::from_static("r-1"));
    headers.insert(
        TRACEPARENT,
        HeaderValue::from_str(&format!("00-{TRACE}-{PARENT}-01"))?,
    );
    assert_eq!(
        ExchangeContext::from_headers(&headers),
        ExchangeContext {
            request_id: Some("r-1".into()),
            trace_id: Some(TRACE.into()),
        }
    );
    headers.insert(REQUEST_ID, HeaderValue::from_static("bad id"));
    headers.insert(TRACEPARENT, HeaderValue::from_static("garbage"));
    assert_eq!(
        ExchangeContext::from_headers(&headers),
        ExchangeContext::default()
    );
    Ok(())
}

#[tokio::test]
async fn an_issued_token_is_observed_with_who_asked_for_it() -> TestResult {
    let h = harness()?;
    let context = ExchangeContext {
        request_id: Some("r-7".into()),
        trace_id: Some(TRACE.into()),
    };
    h.issuer
        .exchange_with(request(&h, "orders.test", subject(json!({})))?, &context)
        .await?;
    let event = h.events.last()?;
    assert_eq!(event.context, context);
    assert_eq!(event.audience.as_deref(), Some("orders.test"));
    assert_eq!(event.trusted_issuer.as_deref(), Some("test"));
    assert_eq!(event.iss.as_deref(), Some("https://issuer.test"));
    assert_eq!(event.sub.as_deref(), Some("alice"));
    assert_eq!(event.scope.as_deref(), Some("orders.read orders.write"));
    assert_eq!(event.error, None);
    assert_eq!(event.error_description, None);
    Ok(())
}

#[tokio::test]
async fn a_refusal_is_observed_with_what_was_known() -> TestResult {
    let h = harness()?;
    let scoped = subject(json!({ "scope": "orders.read admin" }));
    let refused = h.issuer.exchange(request(&h, "orders.test", scoped)?).await;
    assert!(refused.is_err());
    let event = h.events.last()?;
    assert_eq!(event.context, ExchangeContext::default());
    assert_eq!(event.error, Some("invalid_scope"));
    assert_eq!(
        event.error_description.as_deref(),
        Some(
            r#"the subject token's scope "admin" is outside the scopes allowed for "orders.test""#
        )
    );
    assert_eq!(event.iss.as_deref(), Some("https://issuer.test"));
    assert_eq!(event.sub.as_deref(), Some("alice"));
    assert_eq!(event.scope, None);

    let unsigned = request(&h, "orders.test", subject(json!({}))).map(|mut request| {
        request.subject_token = Some("not a jwt".into());
        request
    })?;
    assert!(h.issuer.exchange(unsigned).await.is_err());
    let event = h.events.last()?;
    assert_eq!(event.error, Some("invalid_request"));
    assert_eq!(
        (event.trusted_issuer, event.iss, event.sub),
        (None, None, None)
    );
    assert_eq!(h.events.events().len(), 2);
    Ok(())
}
