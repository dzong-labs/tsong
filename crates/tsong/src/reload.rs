//! Reloading: load the config from its store, build its state, and swap it
//! in, or keep the old state and say why. Every attempt that finds a new
//! revision, or fails, is audited and counted.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use serde_json::json;
use tokio::sync::watch;
use tsong_clock::Clock;
use tsong_config::{Config, ConfigStore, Route};

/// The store couldn't produce the config, such as a failed fetch.
pub const FETCH_FAILED: &str = "fetch_failed";
/// The config didn't parse or validate.
pub const INVALID_CONFIG: &str = "invalid_config";
/// The config was valid, but its state didn't build, such as a missing key
/// file.
pub const BUILD_FAILED: &str = "build_failed";

use crate::state::{State, listen_addresses};

/// Where audit lines go: stdout in production, collected by the platform.
pub trait Audit: Send + Sync {
    fn record(&self, line: &str);
}

/// Writes each audit line, and a newline, to a writer: stdout in
/// production. A line that can't be written is dropped; auditing never
/// stops a reload.
pub struct Lines<W>(Mutex<W>);

impl<W> Lines<W> {
    pub fn new(writer: W) -> Self {
        Self(Mutex::new(writer))
    }

    /// The writer, with everything written to it.
    pub fn into_inner(self) -> W {
        self.0.into_inner().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<W: Write + Send> Audit for Lines<W> {
    fn record(&self, line: &str) {
        let mut writer = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(writer, "{line}").and_then(|()| writer.flush());
    }
}

/// What `GET /status` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Status {
    /// The revision being served.
    pub revision: String,
    /// When it was loaded, in Unix seconds.
    pub loaded_at: u64,
    /// Reloads that swapped in a new revision, the first load included.
    pub reloads: u64,
    /// Reloads that kept the old state.
    pub failed_reloads: u64,
    /// Why the last failed reload failed, in short: `fetch_failed`,
    /// `invalid_config` or `build_failed`. The audit log has the detail.
    pub last_failure: Option<String>,
}

/// What a reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new revision is being served.
    Applied,
    /// The store's revision is the one being served.
    Unchanged,
    /// The old state is still served, for this reason.
    Rejected(String),
}

/// Reloads the config from one store into one watch channel.
pub struct Reloader {
    store: Box<dyn ConfigStore>,
    state: watch::Sender<Arc<State>>,
    status: Arc<Mutex<Status>>,
    audit: Arc<dyn Audit>,
    clock: Arc<dyn Clock>,
    /// The content of the last config rejected as invalid. It can't become
    /// valid until it changes, so it is not rejected again.
    invalid: Mutex<Option<String>>,
}

impl Reloader {
    /// A reloader serving `first`, already built from `store`'s config.
    pub fn new(
        store: Box<dyn ConfigStore>,
        first: State,
        audit: Arc<dyn Audit>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let status = Status {
            revision: first.revision.clone(),
            loaded_at: clock.unix_seconds(),
            reloads: 1,
            ..Status::default()
        };
        audit.record(&applied(None, &first, &status));
        let (state, _) = watch::channel(Arc::new(first));
        Self {
            store,
            state,
            status: Arc::new(Mutex::new(status)),
            invalid: Mutex::new(None),
            audit,
            clock,
        }
    }

    /// A receiver of the current state and each state swapped in after it.
    pub fn subscribe(&self) -> watch::Receiver<Arc<State>> {
        self.state.subscribe()
    }

    /// The status the admin listener reports.
    pub fn status(&self) -> Arc<Mutex<Status>> {
        self.status.clone()
    }

    /// Fetches the store's config and, when its content is new and it
    /// parses, validates and builds, swaps it in.
    pub async fn reload(&self) -> Outcome {
        let current = self.state.borrow().clone();
        let fetched = match self.store.load().await {
            Ok(fetched) => fetched,
            Err(error) => return self.reject(&current, None, FETCH_FAILED, error.to_string()),
        };
        let content = fetched.content.clone();
        let rejected = self
            .invalid
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if content == current.content || rejected.as_ref() == Some(&content) {
            return Outcome::Unchanged;
        }
        let revision = fetched.revision.clone();
        let snapshot = match fetched.parse() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                *self.invalid.lock().unwrap_or_else(PoisonError::into_inner) = Some(content);
                return self.reject(&current, Some(&revision), INVALID_CONFIG, error.to_string());
            }
        };
        let next = match State::build(snapshot, self.clock.clone()) {
            Ok(next) => next,
            Err(error) => {
                return self.reject(&current, Some(&revision), BUILD_FAILED, error.to_string());
            }
        };
        *self.invalid.lock().unwrap_or_else(PoisonError::into_inner) = None;
        let line = {
            let mut status = self.lock();
            status.revision = next.revision.clone();
            status.loaded_at = self.clock.unix_seconds();
            status.reloads += 1;
            applied(Some(&current.config), &next, &status)
        };
        self.audit.record(&line);
        self.state.send_replace(Arc::new(next));
        Outcome::Applied
    }

    fn reject(
        &self,
        current: &State,
        revision: Option<&str>,
        reason: &str,
        error: String,
    ) -> Outcome {
        {
            let mut status = self.lock();
            status.failed_reloads += 1;
            status.last_failure = Some(reason.to_owned());
        }
        let line = json!({
            "event": "config_reload",
            "at": self.clock.unix_seconds(),
            "outcome": "rejected",
            "reason": reason,
            "revision": revision,
            "serving": current.revision,
            "error": error,
        });
        self.audit.record(&line.to_string());
        Outcome::Rejected(error)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The audit line for `next` replacing `previous`, or for the first load.
fn applied(previous: Option<&Config>, next: &State, status: &Status) -> String {
    let old = previous.map(routes_by_host).unwrap_or_default();
    let new = routes_by_host(&next.config);
    let added: Vec<&str> = new
        .keys()
        .filter(|host| !old.contains_key(*host))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = old
        .keys()
        .filter(|host| !new.contains_key(*host))
        .map(String::as_str)
        .collect();
    let changed: Vec<&str> = old
        .iter()
        .filter(|(host, route)| new.get(*host).is_some_and(|next| next != *route))
        .map(|(host, _)| host.as_str())
        .collect();
    let restart: Vec<&str> = previous
        .map(|previous| {
            listen_addresses(previous)
                .into_iter()
                .zip(listen_addresses(&next.config))
                .filter(|(old, new)| old != new)
                .map(|((field, _), _)| field)
                .collect()
        })
        .unwrap_or_default();
    json!({
        "event": "config_reload",
        "at": status.loaded_at,
        "outcome": "applied",
        "revision": next.revision,
        "author": next.author,
        "routes_added": added,
        "routes_removed": removed,
        "routes_changed": changed,
        "restart_required": restart,
    })
    .to_string()
}

/// A config's routes keyed by lowercased host, the first route winning a
/// repeated host, as in `RouteTable`.
fn routes_by_host(config: &Config) -> BTreeMap<String, &Route> {
    let mut routes = BTreeMap::new();
    for route in &config.routes {
        routes
            .entry(route.host.to_ascii_lowercase())
            .or_insert(route);
    }
    routes
}
