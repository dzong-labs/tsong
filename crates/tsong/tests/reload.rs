mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::Notify;
use tower::ServiceExt;
use tsong::reload::{Outcome, Reloader, Status};
use tsong::state::{State, current};
use tsong_clock::{Clock, ManualClock};
use tsong_config::{ConfigError, Fetched};

struct Fixture {
    _dir: tempfile::TempDir,
    key: std::path::PathBuf,
    store: Arc<QueueStore>,
    lines: Arc<Recorded>,
    clock: Arc<ManualClock>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let key = write_key(dir.path())?;
        Ok(Self {
            _dir: dir,
            key,
            store: Arc::default(),
            lines: Arc::default(),
            clock: Arc::new(ManualClock::at(NOW)),
        })
    }

    fn text(&self, issuer: &str, port: u16, routes: &str) -> String {
        config_text(&self.key, issuer, port, routes)
    }

    /// A reloader serving `text` at revision `r1`.
    fn reloader(&self, text: &str) -> TestResult<Reloader> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let first = State::build(snapshot(text, "r1")?, clock.clone())?;
        Ok(Reloader::new(
            Box::new(Shared(self.store.clone())),
            first,
            self.lines.clone(),
            clock,
        ))
    }
}

fn status(reloader: &Reloader) -> Status {
    reloader
        .status()
        .lock()
        .map(|status| status.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_first_load_is_audited_and_counted() -> TestResult {
    let f = Fixture::new()?;
    let routes = format!(
        "{}{}",
        route("b", "B.example.com", "\"*\""),
        route("a", "a.example.com", "\"*\"")
    );
    let reloader = f.reloader(&f.text("https://one.test", 8444, &routes))?;
    assert_eq!(
        f.lines.parsed()?,
        [json!({
            "event": "config_reload",
            "at": NOW,
            "outcome": "applied",
            "revision": "r1",
            "author": "Ada <ada@example.test>",
            "routes_added": ["a.example.com", "b.example.com"],
            "routes_removed": [],
            "routes_changed": [],
            "restart_required": [],
        })]
    );
    assert_eq!(
        status(&reloader),
        Status {
            revision: "r1".into(),
            loaded_at: NOW,
            fetched_at: NOW,
            reloads: 1,
            failed_reloads: 0,
            last_failure: None,
        }
    );
    assert_eq!(reloader.subscribe().borrow().revision, "r1");
    Ok(())
}

#[tokio::test]
async fn the_same_revision_changes_nothing() -> TestResult {
    let f = Fixture::new()?;
    let text = f.text("https://one.test", 8444, "");
    let reloader = f.reloader(&text)?;
    f.store.push(Ok(fetched(&text, "r1")?));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(f.lines.parsed()?.len(), 1);
    assert_eq!(status(&reloader).reloads, 1);
    Ok(())
}

#[tokio::test]
async fn a_new_revision_is_swapped_in_and_its_changes_audited() -> TestResult {
    let f = Fixture::new()?;
    let before = format!(
        "{}{}",
        route("a", "a.example.com", "\"read\""),
        route("b", "b.example.com", "\"read\"")
    );
    let reloader = f.reloader(&f.text("https://one.test", 8444, &before))?;
    let receiver = reloader.subscribe();
    let after = format!(
        "{}{}{}",
        route("a", "A.example.com", "\"read\", \"write\""),
        route("c", "c.example.com", "\"read\""),
        route("d", "d.example.com", "\"read\"")
    );
    f.store.push(Ok(fetched(
        &f.text("https://two.test", 9444, &after),
        "r2",
    )?));
    f.clock.advance(Duration::from_secs(60));
    assert_eq!(reloader.reload().await, Outcome::Applied);

    let lines = f.lines.parsed()?;
    assert_eq!(
        lines.get(1),
        Some(&json!({
            "event": "config_reload",
            "at": NOW + 60,
            "outcome": "applied",
            "revision": "r2",
            "author": "Ada <ada@example.test>",
            "routes_added": ["c.example.com", "d.example.com"],
            "routes_removed": ["b.example.com"],
            "routes_changed": ["a.example.com"],
            "restart_required": ["issuer.listen"],
        }))
    );
    let state = receiver.borrow().clone();
    assert_eq!(state.revision, "r2");
    assert_eq!(state.config.issuer.url, "https://two.test");
    let status = status(&reloader);
    assert_eq!(
        (status.revision.as_str(), status.loaded_at, status.reloads),
        ("r2", NOW + 60, 2)
    );
    Ok(())
}

#[tokio::test]
async fn an_unchanged_route_and_address_are_not_reported() -> TestResult {
    let f = Fixture::new()?;
    let routes = route("a", "a.example.com", "\"read\"");
    let reloader = f.reloader(&f.text("https://one.test", 8444, &routes))?;
    f.store.push(Ok(fetched(
        &f.text("https://two.test", 8444, &routes),
        "r2",
    )?));
    assert_eq!(reloader.reload().await, Outcome::Applied);
    let line = f.lines.parsed()?.get(1).cloned().ok_or("no second line")?;
    for field in [
        "routes_added",
        "routes_removed",
        "routes_changed",
        "restart_required",
    ] {
        assert_eq!(line.get(field), Some(&json!([])), "{field}");
    }
    Ok(())
}

#[tokio::test]
async fn a_failed_load_keeps_the_old_state() -> TestResult {
    let f = Fixture::new()?;
    let reloader = f.reloader(&f.text("https://one.test", 8444, ""))?;
    f.store
        .push(Err(ConfigError::Store("fetching: offline".into())));
    f.clock.advance(Duration::from_secs(5));
    assert_eq!(
        reloader.reload().await,
        Outcome::Rejected("fetching: offline".into())
    );
    assert_eq!(
        f.lines.parsed()?.get(1),
        Some(&json!({
            "event": "config_reload",
            "at": NOW + 5,
            "outcome": "rejected",
            "reason": "fetch_failed",
            "revision": null,
            "serving": "r1",
            "error": "fetching: offline",
        }))
    );
    let status = status(&reloader);
    assert_eq!(status.revision, "r1");
    assert_eq!(status.reloads, 1);
    assert_eq!(status.failed_reloads, 1);
    assert_eq!(status.last_failure.as_deref(), Some("fetch_failed"));
    assert_eq!(reloader.subscribe().borrow().revision, "r1");
    Ok(())
}

#[tokio::test]
async fn a_config_whose_state_fails_to_build_is_rejected() -> TestResult {
    let f = Fixture::new()?;
    let reloader = f.reloader(&f.text("https://one.test", 8444, ""))?;
    let missing = f.key.with_file_name("missing.pem");
    let text = config_text(&missing, "https://two.test", 8444, "");
    f.store.push(Ok(fetched(&text, "r2")?));
    let Outcome::Rejected(error) = reloader.reload().await else {
        return Err("expected a rejection".into());
    };
    assert!(error.starts_with(r#"reading key "k1""#), "{error}");
    let line = f.lines.parsed()?.get(1).cloned().ok_or("no second line")?;
    assert_eq!(line.get("revision"), Some(&json!("r2")));
    assert_eq!(line.get("outcome"), Some(&json!("rejected")));
    assert_eq!(line.get("reason"), Some(&json!("build_failed")));
    assert_eq!(reloader.subscribe().borrow().revision, "r1");
    let status = status(&reloader);
    assert_eq!(status.failed_reloads, 1);
    assert_eq!(status.last_failure.as_deref(), Some("build_failed"));
    Ok(())
}

#[tokio::test]
async fn each_failure_has_a_short_reason_and_the_detail_only_in_the_log() -> TestResult {
    let f = Fixture::new()?;
    let reloader = f.reloader(&f.text("https://one.test", 8444, ""))?;
    let unparsable = fetched("max_entries = [", "r2")?;
    let invalid = fetched(
        &f.text("https://two.test", 8444, "")
            .replace("max_entries = 10", "max_entries = 0"),
        "r3",
    )?;
    let mut cases = Vec::new();
    for text in [unparsable, invalid] {
        let detail = text.clone().parse().err().map(|error| error.to_string());
        cases.push((
            Ok(text),
            detail.ok_or("expected a failure")?,
            "invalid_config",
        ));
    }
    let unreadable = ConfigError::Read {
        path: "missing.toml".into(),
        source: std::io::Error::other("gone"),
    };
    let detail = unreadable.to_string();
    cases.push((Err(unreadable), detail, "fetch_failed"));
    for (result, detail, reason) in cases {
        f.store.push(result);
        assert_eq!(reloader.reload().await, Outcome::Rejected(detail.clone()));
        let line = f.lines.parsed()?.last().cloned().ok_or("no line")?;
        assert_eq!(line.get("reason"), Some(&json!(reason)), "{detail}");
        assert_eq!(line.get("error"), Some(&json!(detail)));
        assert_eq!(status(&reloader).last_failure.as_deref(), Some(reason));
    }
    Ok(())
}

/// The issuer named by the discovery document `router` serves.
async fn issuer_of(router: &axum::Router) -> TestResult<Value> {
    let request = Request::get("/.well-known/openid-configuration").body(Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    Ok(body.get("issuer").cloned().unwrap_or(Value::Null))
}

#[tokio::test]
async fn requests_reach_the_current_state() -> TestResult {
    let f = Fixture::new()?;
    let reloader = f.reloader(&f.text("https://one.test", 8444, ""))?;
    let issuer = current(reloader.subscribe(), |state| &state.issuer);
    let gateway = current(reloader.subscribe(), |state| &state.gateway);
    assert_eq!(issuer_of(&issuer).await?, json!("https://one.test"));
    f.store
        .push(Ok(fetched(&f.text("https://two.test", 8444, ""), "r2")?));
    reloader.reload().await;
    assert_eq!(issuer_of(&issuer).await?, json!("https://two.test"));
    let unrouted = Request::get("/")
        .header("host", "nowhere.test")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            5000,
        ))))
        .body(Body::empty())?;
    let response = gateway.oneshot(unrouted).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Waits until `reloader` has made `reloads` reloads.
async fn reloaded(reloader: &Reloader, reloads: u64) -> TestResult {
    for _ in 0..200 {
        if status(reloader).reloads >= reloads {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("never reached {reloads} reloads").into())
}

#[tokio::test]
async fn the_loop_reloads_on_each_trigger_and_stops_when_told() -> TestResult {
    let f = Fixture::new()?;
    let reloader = Arc::new(f.reloader(&f.text("https://one.test", 8444, ""))?);
    let trigger = Arc::new(Notify::new());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = {
        let (reloader, trigger) = (reloader.clone(), trigger.clone());
        tokio::spawn(async move {
            tsong::reload_loop(&reloader, &trigger, Duration::from_secs(3600), async {
                let _ = stopped.await;
            })
            .await;
        })
    };
    f.store
        .push(Ok(fetched(&f.text("https://two.test", 8444, ""), "r2")?));
    trigger.notify_one();
    reloaded(&reloader, 2).await?;
    stop.send(()).map_err(|()| "the loop stopped early")?;
    tokio::time::timeout(Duration::from_secs(5), task).await??;
    Ok(())
}

#[tokio::test]
async fn the_loop_reloads_on_each_poll() -> TestResult {
    let f = Fixture::new()?;
    let reloader = Arc::new(f.reloader(&f.text("https://one.test", 8444, ""))?);
    f.store
        .push(Ok(fetched(&f.text("https://two.test", 8444, ""), "r2")?));
    let trigger = Notify::new();
    let polling = tsong::reload_loop(&reloader, &trigger, Duration::from_millis(10), async {
        let _ = reloaded(&reloader, 2).await;
    });
    tokio::time::timeout(Duration::from_secs(5), polling).await?;
    assert_eq!(reloader.subscribe().borrow().revision, "r2");
    Ok(())
}

#[test]
fn lines_are_written_one_to_a_line() {
    use tsong::reload::{Audit, Lines};

    let lines = Lines::new(Vec::new());
    lines.record(r#"{"a":1}"#);
    lines.record(r#"{"b":2}"#);
    assert_eq!(lines.into_inner(), b"{\"a\":1}\n{\"b\":2}\n");
}

#[tokio::test]
async fn a_new_revision_with_the_same_content_changes_nothing() -> TestResult {
    let f = Fixture::new()?;
    let text = f.text("https://one.test", 8444, "");
    let reloader = f.reloader(&text)?;
    let mut unrelated = fetched(&text, "r2")?;
    unrelated.content = "content of r1".into();
    f.store.push(Ok(unrelated));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(f.lines.parsed()?.len(), 1);
    assert_eq!(status(&reloader).revision, "r1");
    Ok(())
}

/// Text that doesn't parse, fetched at `revision` with `content`.
fn invalid_at(revision: &str, content: &str) -> TestResult<Fetched> {
    let mut invalid = fetched("not toml [", revision)?;
    invalid.content = content.into();
    Ok(invalid)
}

#[tokio::test]
async fn an_invalid_config_is_rejected_once_until_it_changes() -> TestResult {
    let f = Fixture::new()?;
    let text = f.text("https://one.test", 8444, "");
    let reloader = f.reloader(&text)?;
    f.store.push(Ok(invalid_at("r2", "bad")?));
    let Outcome::Rejected(detail) = reloader.reload().await else {
        return Err("expected a rejection".into());
    };
    assert!(detail.starts_with("parsing: "), "{detail}");
    let line = f
        .lines
        .parsed()?
        .get(1)
        .cloned()
        .ok_or("no rejection line")?;
    assert_eq!(line.get("revision"), Some(&json!("r2")));
    assert_eq!(line.get("reason"), Some(&json!("invalid_config")));

    f.store.push(Ok(invalid_at("r3", "bad")?));
    assert_eq!(reloader.reload().await, Outcome::Unchanged);
    assert_eq!(
        f.lines.parsed()?.len(),
        2,
        "the same invalid config isn't audited again"
    );
    assert_eq!(status(&reloader).failed_reloads, 1);

    f.store.push(Ok(invalid_at("r4", "worse")?));
    assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    assert_eq!(status(&reloader).failed_reloads, 2);

    f.store
        .push(Ok(fetched(&f.text("https://two.test", 8444, ""), "r5")?));
    assert_eq!(reloader.reload().await, Outcome::Applied);
    f.store.push(Ok(invalid_at("r6", "worse")?));
    assert!(
        matches!(reloader.reload().await, Outcome::Rejected(_)),
        "a valid config in between clears the memory"
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_fetch_is_retried_every_time() -> TestResult {
    let f = Fixture::new()?;
    let reloader = f.reloader(&f.text("https://one.test", 8444, ""))?;
    for _ in 0..2 {
        f.store.push(Err(ConfigError::Store("offline".into())));
        assert!(matches!(reloader.reload().await, Outcome::Rejected(_)));
    }
    assert_eq!(status(&reloader).failed_reloads, 2);
    assert_eq!(
        status(&reloader).last_failure.as_deref(),
        Some("fetch_failed")
    );
    Ok(())
}

/// A store whose load never finishes, like a fetch stuck on a dead
/// connection.
struct Stalled;

impl tsong_config::ConfigStore for Stalled {
    fn load(&self) -> tsong_config::LoadFuture<'_> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn shutdown_does_not_wait_for_a_stalled_reload() -> TestResult {
    let f = Fixture::new()?;
    let clock: Arc<dyn Clock> = f.clock.clone();
    let first = State::build(
        snapshot(&f.text("https://one.test", 8444, ""), "r1")?,
        clock.clone(),
    )?;
    let reloader = Arc::new(Reloader::new(
        Box::new(Stalled),
        first,
        f.lines.clone(),
        clock,
    ));
    let trigger = Arc::new(Notify::new());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = {
        let (reloader, trigger) = (reloader.clone(), trigger.clone());
        tokio::spawn(async move {
            tsong::reload_loop(&reloader, &trigger, Duration::from_secs(3600), async {
                let _ = stopped.await;
            })
            .await;
        })
    };
    trigger.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send(()).map_err(|()| "the loop stopped early")?;
    tokio::time::timeout(Duration::from_secs(5), task).await??;
    Ok(())
}
