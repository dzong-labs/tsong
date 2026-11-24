mod common;

use std::time::Duration;

use common::{NOW, TestResult, minted};
use tsong_gateway::lifetime;
use tsong_issuer::TokenResponse;

fn response(access_token: String, expires_in: u64) -> TokenResponse {
    TokenResponse {
        access_token,
        issued_token_type: tsong_issuer::ACCESS_TOKEN.into(),
        token_type: "Bearer".into(),
        expires_in,
        scope: None,
    }
}

#[test]
fn a_token_is_kept_until_its_exp_less_the_skew() -> TestResult {
    let skew = Duration::from_secs(30);
    let token = response(minted("a", NOW + 900)?, 1);
    assert_eq!(lifetime(&token, NOW, skew), Duration::from_secs(870));
    assert_eq!(lifetime(&token, NOW + 880, skew), Duration::ZERO);
    assert_eq!(lifetime(&token, NOW + 2000, skew), Duration::ZERO);
    Ok(())
}

#[test]
fn expires_in_stands_in_when_exp_cannot_be_read() -> TestResult {
    let skew = Duration::from_secs(30);
    for token in [
        "opaque".to_owned(),
        "h.!!!.s".to_owned(),
        "h.bm90IGpzb24.s".to_owned(),
        format!("h.{}.s", "eyJuYW1lIjoibm8gZXhwIn0"),
        format!("h.{}.s", "eyJleHAiOiJzb29uIn0"),
    ] {
        assert_eq!(
            lifetime(&response(token.clone(), 600), NOW, skew),
            Duration::from_secs(570),
            "{token}"
        );
    }
    assert_eq!(
        lifetime(&response("opaque".into(), 10), NOW, skew),
        Duration::ZERO
    );
    Ok(())
}

mod correlation {
    use axum::http::{HeaderMap, HeaderValue};
    use tsong_gateway::correlate;
    use tsong_issuer::trace_id;

    use super::TestResult;

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).and_then(|value| value.to_str().ok())
    }

    #[test]
    fn a_valid_request_id_is_kept_and_anything_else_replaced() -> TestResult {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("r-1"));
        assert_eq!(correlate(&mut headers).as_deref(), Some("r-1"));
        assert_eq!(header(&headers, "x-request-id"), Some("r-1"));

        for inbound in [None, Some("has space")] {
            let mut headers = HeaderMap::new();
            if let Some(value) = inbound {
                headers.insert("x-request-id", HeaderValue::from_str(value)?);
            }
            let id = correlate(&mut headers).ok_or("no request ID")?;
            assert_eq!(id.len(), 32, "{inbound:?}");
            assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert_eq!(header(&headers, "x-request-id"), Some(id.as_str()));
        }
        let (mut first, mut second) = (HeaderMap::new(), HeaderMap::new());
        assert_ne!(correlate(&mut first), correlate(&mut second));
        Ok(())
    }

    #[test]
    fn a_valid_traceparent_continues_with_a_new_span() -> TestResult {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static(INBOUND));
        headers.insert("tracestate", HeaderValue::from_static("vendor=1"));
        correlate(&mut headers).ok_or("no request ID")?;
        let outbound = header(&headers, "traceparent").ok_or("no traceparent")?;
        assert_eq!(trace_id(outbound), Some(TRACE));
        assert_ne!(outbound, INBOUND, "the gateway's hop is its own span");
        assert!(outbound.ends_with("-01"), "{outbound}");
        assert_eq!(header(&headers, "tracestate"), Some("vendor=1"));
        Ok(())
    }

    #[test]
    fn a_missing_or_invalid_traceparent_starts_a_trace() -> TestResult {
        for inbound in [None, Some("garbage")] {
            let mut headers = HeaderMap::new();
            if let Some(value) = inbound {
                headers.insert("traceparent", HeaderValue::from_str(value)?);
                headers.insert("tracestate", HeaderValue::from_static("vendor=1"));
            }
            correlate(&mut headers).ok_or("no request ID")?;
            let outbound = header(&headers, "traceparent").ok_or("no traceparent")?;
            let trace = trace_id(outbound).ok_or("an invalid traceparent")?;
            assert_ne!(trace, TRACE);
            assert!(outbound.ends_with("-00"), "{outbound}");
            assert_eq!(header(&headers, "tracestate"), None, "{inbound:?}");
        }
        Ok(())
    }
}

#[tokio::test]
async fn the_entries_gauge_follows_the_cache() -> TestResult {
    use std::sync::Arc;

    use common::FakeExchanger;
    use tsong_clock::ManualClock;
    use tsong_gateway::{ExchangeCache, GatewayMetrics};
    use tsong_issuer::ExchangeContext;

    let metrics = Arc::new(GatewayMetrics::default());
    metrics.cache_entries.set(5);
    let cache = ExchangeCache::new(
        Arc::new(FakeExchanger::default()),
        Arc::new(ManualClock::at(NOW)),
        1,
        Duration::from_secs(30),
        metrics.clone(),
    );
    assert_eq!(metrics.cache_entries.get(), 0, "a new cache starts empty");
    let context = ExchangeContext::default();
    cache
        .token("alice", "orders.test", &context)
        .await
        .map_err(|e| e.to_string())?;
    cache
        .token("bob", "orders.test", &context)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(metrics.cache_entries.get(), 2);
    cache.housekeep().await;
    assert_eq!(metrics.cache_entries.get(), 1, "a cache of one keeps one");
    Ok(())
}

#[test]
fn the_gateway_metrics_register_under_their_names() -> TestResult {
    use prometheus_client::registry::Registry;
    use tsong_gateway::{GatewayMetrics, RouteLabel, RouteStatus};

    let mut registry = Registry::default();
    let metrics = GatewayMetrics::register(&mut registry);
    metrics.cache_hits.inc();
    metrics.cache_misses.inc();
    metrics.cache_entries.set(3);
    let route = || "orders".to_owned();
    metrics
        .requests
        .get_or_create(&RouteStatus {
            route: route(),
            status: 200,
        })
        .inc();
    metrics
        .anonymous_requests
        .get_or_create(&RouteStatus {
            route: route(),
            status: 502,
        })
        .inc();
    metrics
        .downstream_seconds
        .get_or_create(&RouteLabel { route: route() })
        .observe(0.002);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)?;
    for expected in [
        "tsong_cache_hits_total 1",
        "tsong_cache_misses_total 1",
        "tsong_cache_entries 3",
        r#"tsong_gateway_requests_total{route="orders",status="200"} 1"#,
        r#"tsong_anonymous_requests_total{route="orders",status="502"} 1"#,
        r#"tsong_downstream_seconds_count{route="orders"} 1"#,
        r#"tsong_downstream_seconds_bucket{le="0.001",route="orders"} 0"#,
    ] {
        assert!(text.contains(expected), "{expected} in\n{text}");
    }
    Ok(())
}
