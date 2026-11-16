mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use tsong::admin::{health_router, status_router};
use tsong::reload::{Outcome, Reloader};
use tsong::state::State;
use tsong::telemetry::{CountingFetcher, ExchangeAudit, IssuerLabel, Metrics, OutcomeLabel};
use tsong_clock::{Clock, ManualClock};
use tsong_config::{Config, ConfigError, TrustedIssuer};
use tsong_issuer::{ExchangeContext, ExchangeEvent, ExchangeObserver};
use tsong_validate::JwksFetcher;
use tsong_validate::testkit::FakeFetcher;

fn event(error: Option<&'static str>) -> ExchangeEvent {
    ExchangeEvent {
        context: ExchangeContext {
            request_id: Some("r-1".into()),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".into()),
        },
        audience: Some("orders.test".into()),
        trusted_issuer: Some("okta".into()),
        iss: Some("https://okta.test".into()),
        sub: Some("alice".into()),
        scope: error.is_none().then(|| "orders.read".into()),
        error,
        error_description: error.map(|_| "scope \"admin\" is not allowed".into()),
        duration: Duration::from_millis(12),
    }
}

#[test]
fn each_exchange_writes_one_audit_line_and_is_counted() -> TestResult {
    let lines = Arc::new(Recorded::default());
    let metrics = Metrics::default();
    let audit = ExchangeAudit {
        audit: lines.clone(),
        exchanges: metrics.exchanges.clone(),
        clock: Arc::new(ManualClock::at(NOW)),
    };
    audit.exchanged(&event(None));
    audit.exchanged(&event(Some("invalid_scope")));
    audit.exchanged(&event(None));
    let parsed = lines.parsed()?;
    assert_eq!(
        parsed.first(),
        Some(&json!({
            "event": "token_exchange",
            "at": NOW,
            "outcome": "issued",
            "request_id": "r-1",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "audience": "orders.test",
            "trusted_issuer": "okta",
            "iss": "https://okta.test",
            "sub": "alice",
            "scope": "orders.read",
            "error_description": null,
            "duration_ms": 12.0,
        }))
    );
    let refused = parsed.get(1).ok_or("no second line")?;
    assert_eq!(refused.get("outcome"), Some(&json!("invalid_scope")));
    assert_eq!(
        refused.get("error_description"),
        Some(&json!("scope \"admin\" is not allowed"))
    );
    let count = |outcome: &str| {
        metrics
            .exchanges
            .get_or_create(&OutcomeLabel {
                outcome: outcome.into(),
            })
            .get()
    };
    assert_eq!((count("issued"), count("invalid_scope")), (2, 1));
    Ok(())
}

#[tokio::test]
async fn failed_jwks_fetches_are_counted_by_issuer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let text = format!(
        "{}\n[trusted_issuers.okta]\nissuer = \"https://okta.test\"\naudiences = [\"tsong\"]\nalgorithms = [\"ES256\"]\n",
        config_text(&key, "https://one.test", 8444, "")
    );
    let config = Config::from_toml(&text)?;
    let okta: &TrustedIssuer = config.trusted_issuers.get("okta").ok_or("no okta")?;
    let inner = FakeFetcher::with(vec![]);
    let metrics = Metrics::default();
    let fetcher = CountingFetcher {
        inner,
        failures: metrics.jwks_failures.clone(),
    };
    fetcher.fetch(okta).await?;
    fetcher.inner.fail(true);
    assert!(fetcher.fetch(okta).await.is_err());
    assert!(fetcher.fetch(okta).await.is_err());
    let failures = metrics
        .jwks_failures
        .get_or_create(&IssuerLabel {
            issuer: "https://okta.test".into(),
        })
        .get();
    assert_eq!(failures, 2);
    Ok(())
}

#[test]
fn the_metrics_encode_as_prometheus_text() -> TestResult {
    let metrics = Metrics::default();
    metrics.gateway.cache_hits.inc();
    let route = || "orders".to_owned();
    metrics
        .gateway
        .requests
        .get_or_create(&tsong_gateway::RouteStatus {
            route: route(),
            status: 200,
        })
        .inc();
    metrics
        .gateway
        .downstream_seconds
        .get_or_create(&tsong_gateway::RouteLabel { route: route() })
        .observe(0.01);
    let issued = OutcomeLabel {
        outcome: "issued".into(),
    };
    metrics.exchanges.get_or_create(&issued).inc();
    metrics
        .jwks_failures
        .get_or_create(&IssuerLabel {
            issuer: "https://okta.test".into(),
        })
        .inc();
    metrics
        .reloads
        .get_or_create(&OutcomeLabel {
            outcome: "applied".into(),
        })
        .inc();
    let text = metrics.encode()?;
    for expected in [
        "tsong_cache_hits_total 1",
        "# TYPE tsong_cache_misses counter",
        "# TYPE tsong_cache_entries gauge",
        r#"tsong_gateway_requests_total{route="orders",status="200"} 1"#,
        r#"tsong_downstream_seconds_count{route="orders"} 1"#,
        r#"tsong_exchanges_total{outcome="issued"} 1"#,
        r#"tsong_jwks_fetch_failures_total{issuer="https://okta.test"} 1"#,
        r#"tsong_config_reloads_total{outcome="applied"} 1"#,
    ] {
        assert!(text.contains(expected), "{expected} in\n{text}");
    }
    Ok(())
}

#[tokio::test]
async fn reloads_are_counted_by_outcome() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let store = Arc::new(QueueStore::default());
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::at(NOW));
    let first = State::build(
        snapshot(&config_text(&key, "https://one.test", 8444, ""), "r1")?,
        clock.clone(),
    )?;
    let metrics = Arc::new(Metrics::default());
    let reloader = Reloader::new(
        Box::new(Shared(store.clone())),
        first,
        Arc::new(Recorded::default()),
        clock,
    )
    .with_metrics(metrics.clone());
    store.push(Ok(fetched(
        &config_text(&key, "https://two.test", 8444, ""),
        "r2",
    )?));
    assert_eq!(reloader.reload().await, Outcome::Applied);
    store.push(Err(ConfigError::Store("offline".into())));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    store.push(Ok(fetched("not toml [", "r3")?));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    let count = |outcome: &str| {
        metrics
            .reloads
            .get_or_create(&OutcomeLabel {
                outcome: outcome.into(),
            })
            .get()
    };
    assert_eq!(count("applied"), 1);
    assert_eq!(count("fetch_failed"), 1);
    assert_eq!(count("invalid_config"), 1);
    Ok(())
}

#[tokio::test]
async fn metrics_are_served_on_the_admin_listener() -> TestResult {
    let metrics = Arc::new(Metrics::default());
    metrics.gateway.cache_misses.inc();
    let response = status_router(Arc::default(), metrics)
        .oneshot(Request::get("/metrics").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let body = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body.contains("tsong_cache_misses_total 1"), "{body}");
    Ok(())
}

/// The status and JSON body of `path` on the health router.
async fn health(ready: Arc<AtomicBool>, path: &str) -> TestResult<(StatusCode, Value)> {
    let response = health_router(ready)
        .oneshot(Request::get(path).body(Body::empty())?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    Ok((status, body))
}

#[tokio::test]
async fn liveness_answers_while_readiness_waits_for_the_listeners() -> TestResult {
    let ready = Arc::new(AtomicBool::new(false));
    assert_eq!(
        health(ready.clone(), "/health/live").await?,
        (StatusCode::OK, json!({ "live": true }))
    );
    assert_eq!(
        health(ready.clone(), "/health/ready").await?,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ready": false, "missing": ["listeners_bound"] })
        )
    );
    ready.store(true, Ordering::Release);
    assert_eq!(
        health(ready, "/health/ready").await?,
        (StatusCode::OK, json!({ "ready": true }))
    );
    Ok(())
}
