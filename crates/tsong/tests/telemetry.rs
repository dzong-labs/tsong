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
use tsong::telemetry::{
    ExchangeAudit, IssuerLabel, Metrics, ObservedFetcher, OutcomeLabel, Refresher, refresh,
};
use tsong_clock::ManualClock;
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

/// A config trusting `https://okta.test`, with keys that expire after
/// `max_age`.
fn okta_config(dir: &std::path::Path, max_age: &str) -> TestResult<Config> {
    let key = write_key(dir)?;
    let text = format!(
        "{}\n[trusted_issuers.okta]\nsub_prefix = \"okta\"\nissuer = \"https://okta.test\"\naudiences = [\"tsong\"]\nalgorithms = [\"ES256\"]\njwks_max_age = \"{max_age}\"\n",
        config_text(&key, "https://one.test", 8444, "")
    );
    Ok(Config::from_toml(&text)?)
}

fn okta(config: &Config) -> TestResult<&TrustedIssuer> {
    Ok(config.trusted_issuers.get("okta").ok_or("no okta")?)
}

fn failures(metrics: &Metrics) -> u64 {
    metrics
        .jwks_failures
        .get_or_create(&IssuerLabel {
            issuer: "https://okta.test".into(),
        })
        .get()
}

#[tokio::test]
async fn failed_jwks_fetches_are_counted_and_audited_and_so_is_the_recovery() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = okta_config(dir.path(), "1h")?;
    let okta = okta(&config)?;
    let lines = Arc::new(Recorded::default());
    let metrics = Metrics::default();
    let fetcher = ObservedFetcher::new(
        FakeFetcher::with(vec![]),
        metrics.jwks_failures.clone(),
        lines.clone(),
        Arc::new(ManualClock::at(NOW)),
    );
    fetcher.fetch(okta).await?;
    fetcher.inner().fail(true);
    assert!(fetcher.fetch(okta).await.is_err());
    assert!(fetcher.fetch(okta).await.is_err());
    fetcher.inner().fail(false);
    fetcher.fetch(okta).await?;
    fetcher.fetch(okta).await?;
    assert_eq!(failures(&metrics), 2);
    let failed = json!({
        "event": "jwks_fetch",
        "at": NOW,
        "outcome": "failed",
        "issuer": "https://okta.test",
        "error": "discovery document: down",
    });
    let recovered = json!({
        "event": "jwks_fetch",
        "at": NOW,
        "outcome": "recovered",
        "issuer": "https://okta.test",
        "error": null,
    });
    assert_eq!(lines.parsed()?, [failed.clone(), failed, recovered]);
    Ok(())
}

#[tokio::test]
async fn the_refresher_refetches_expired_keys_and_reports_their_age() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = okta_config(dir.path(), "1h")?;
    let clock = Arc::new(ManualClock::at(NOW));
    let fetcher = Arc::new(FakeFetcher::with(vec![]));
    let validator = tsong_validate::Validator::new(&config, fetcher.clone(), clock.clone());
    let keys =
        tsong_keys::KeySet::from_config(&config.issuer.signing, &tsong_secrets::Secrets::default())
            .await?;
    let issuer = tsong_issuer::Issuer::new(Arc::new(config), keys, validator, clock.clone());
    let metrics = Metrics::default();
    let age = || {
        metrics
            .jwks_age
            .get_or_create(&IssuerLabel {
                issuer: "https://okta.test".into(),
            })
            .get()
    };

    let stale = IssuerLabel {
        issuer: "https://removed.test".into(),
    };
    metrics.jwks_age.get_or_create(&stale).set(42);

    fetcher.fail(true);
    refresh(&issuer, &metrics.jwks_age).await;
    let encoded = metrics.encode()?;
    assert!(
        !encoded.contains("okta.test") && !encoded.contains("removed.test"),
        "keys never fetched, or an issuer no longer trusted, have no age: {encoded}"
    );

    fetcher.fail(false);
    clock.advance(Duration::from_secs(10));
    refresh(&issuer, &metrics.jwks_age).await;
    assert_eq!((fetcher.fetches(), age()), (2, 0));
    clock.advance(Duration::from_secs(2699));
    refresh(&issuer, &metrics.jwks_age).await;
    assert_eq!((fetcher.fetches(), age()), (2, 2699));
    clock.advance(Duration::from_secs(1));
    refresh(&issuer, &metrics.jwks_age).await;
    assert_eq!((fetcher.fetches(), age()), (3, 0));
    Ok(())
}

#[tokio::test]
async fn a_refresher_runs_on_its_tick_until_dropped() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = okta_config(dir.path(), "1s")?;
    let fetcher = Arc::new(FakeFetcher::with(vec![]));
    let clock = Arc::new(tsong_clock::SystemClock);
    let validator = tsong_validate::Validator::new(&config, fetcher.clone(), clock.clone());
    let keys =
        tsong_keys::KeySet::from_config(&config.issuer.signing, &tsong_secrets::Secrets::default())
            .await?;
    let issuer = tsong_issuer::Issuer::new(Arc::new(config), keys, validator, clock);
    let metrics = Metrics::default();
    let refresher = Refresher::spawn(
        Arc::new(issuer),
        metrics.jwks_age.clone(),
        Duration::from_millis(10),
    )
    .ok_or("no runtime")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fetcher.fetches() < 2 {
        if tokio::time::Instant::now() > deadline {
            return Err("the refresher never refetched".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(refresher);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stopped = fetcher.fetches();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(fetcher.fetches(), stopped, "fetched after it was dropped");
    Ok(())
}

#[test]
fn a_refresher_needs_a_runtime() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = okta_config(dir.path(), "1h")?;
    let clock = Arc::new(ManualClock::at(NOW));
    let validator =
        tsong_validate::Validator::new(&config, Arc::new(FakeFetcher::default()), clock.clone());
    // Keys load on a runtime of their own, gone before the spawn.
    let keys = tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(tsong_keys::KeySet::from_config(
            &config.issuer.signing,
            &tsong_secrets::Secrets::default(),
        ))?;
    let issuer = tsong_issuer::Issuer::new(Arc::new(config), keys, validator, clock);
    let spawned = Refresher::spawn(
        Arc::new(issuer),
        Metrics::default().jwks_age.clone(),
        Duration::from_secs(1),
    );
    assert!(spawned.is_none());
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

/// A reloader serving r1 from a queue store, reporting into its own
/// metrics, on a manual clock.
struct Metered {
    _dir: tempfile::TempDir,
    key: std::path::PathBuf,
    store: Arc<QueueStore>,
    clock: Arc<ManualClock>,
    metrics: Arc<Metrics>,
    reloader: Reloader,
}

async fn metered() -> TestResult<Metered> {
    let dir = tempfile::tempdir()?;
    let key = write_key(dir.path())?;
    let store = Arc::new(QueueStore::default());
    let clock = Arc::new(ManualClock::at(NOW));
    let first = State::build(
        snapshot(&config_text(&key, "https://one.test", 8444, ""), "r1")?,
        clock.clone(),
    )
    .await?;
    let metrics = Arc::new(Metrics::default());
    let reloader = Reloader::new(
        Box::new(Shared(store.clone())),
        first,
        Arc::new(Recorded::default()),
        clock.clone(),
    )
    .with_metrics(metrics.clone());
    Ok(Metered {
        _dir: dir,
        key,
        store,
        clock,
        metrics,
        reloader,
    })
}

#[tokio::test]
async fn reloads_are_counted_by_outcome() -> TestResult {
    let Metered {
        _dir,
        key,
        store,
        metrics,
        reloader,
        ..
    } = metered().await?;
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
async fn the_last_fetch_and_the_served_revision_are_reported() -> TestResult {
    let Metered {
        _dir,
        key,
        store,
        clock,
        metrics,
        reloader,
    } = metered().await?;
    let fetched_at = || metrics.config_fetched.get();
    let revisions = || -> TestResult<Vec<String>> {
        let text = metrics.encode()?;
        Ok(text
            .lines()
            .filter(|line| line.starts_with("tsong_config_revision_info{"))
            .map(str::to_owned)
            .collect())
    };
    let now = i64::try_from(NOW)?;
    assert_eq!(fetched_at(), now);
    assert_eq!(
        revisions()?,
        [r#"tsong_config_revision_info{revision="r1"} 1"#]
    );

    // A store that can't be read leaves the last fetch where it was.
    clock.advance(Duration::from_secs(60));
    store.push(Err(ConfigError::Store("offline".into())));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    assert_eq!(fetched_at(), now);
    assert_eq!(status(&reloader).fetched_at, NOW);

    // A read with nothing new still counts as a fetch.
    clock.advance(Duration::from_secs(60));
    store.push(Ok(fetched(
        &config_text(&key, "https://one.test", 8444, ""),
        "r1",
    )?));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(fetched_at(), now + 120);
    assert_eq!(status(&reloader).fetched_at, NOW + 120);
    assert_eq!(status(&reloader).loaded_at, NOW);

    clock.advance(Duration::from_secs(60));
    store.push(Ok(fetched(
        &config_text(&key, "https://two.test", 8444, ""),
        "r2",
    )?));
    assert_eq!(reloader.reload().await, Outcome::Applied);
    assert_eq!(fetched_at(), now + 180);
    assert_eq!(
        revisions()?,
        [r#"tsong_config_revision_info{revision="r2"} 1"#]
    );

    // An invalid tip is flagged while r2 keeps serving, read after read.
    let tip_rejected = || metrics.config_tip_rejected.get();
    assert_eq!(tip_rejected(), 0);
    store.push(Ok(fetched("not toml [", "r3")?));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    assert_eq!(tip_rejected(), 1);
    store.push(Ok(fetched("not toml [", "r3")?));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(tip_rejected(), 1);
    assert_eq!(status(&reloader).revision, "r2");

    // A commit that restores r2's config, or touches only other files, is
    // the revision served.
    let mut same = fetched(&config_text(&key, "https://two.test", 8444, ""), "r2")?;
    same.revision = "r4".into();
    store.push(Ok(same));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(tip_rejected(), 0);
    assert_eq!(status(&reloader).revision, "r4");

    // The invalid config coming back is rejected and flagged again.
    store.push(Ok(fetched("not toml [", "r3")?));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    assert_eq!(tip_rejected(), 1);
    assert!(status(&reloader).tip_rejected);
    assert_eq!(
        revisions()?,
        [r#"tsong_config_revision_info{revision="r4"} 1"#]
    );
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
        (StatusCode::SERVICE_UNAVAILABLE, json!({ "ready": false }))
    );
    ready.store(true, Ordering::Release);
    assert_eq!(
        health(ready, "/health/ready").await?,
        (StatusCode::OK, json!({ "ready": true }))
    );
    Ok(())
}
