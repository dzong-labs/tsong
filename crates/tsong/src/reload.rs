//! Reloading: load the config from its store, build its state, and swap it
//! in, or keep the old state and say why. Every attempt that finds a new
//! revision, or fails, is audited and counted.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;
use serde_json::json;
use tokio::sync::watch;
use tsong_clock::Clock;
use tsong_config::{Config, ConfigStore};

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
    pub author: Option<String>,
    /// When it was loaded, in Unix seconds.
    pub loaded_at: u64,
    /// Reloads that swapped in a new revision, the first load included.
    pub reloads: u64,
    /// Reloads that kept the old state.
    pub failed_reloads: u64,
    /// Why the last failed reload failed.
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
            author: first.author.clone(),
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

    /// Loads the store's config and, when its revision is new and it
    /// builds, swaps it in.
    pub async fn reload(&self) -> Outcome {
        let current = self.state.borrow().clone();
        let snapshot = match self.store.load().await {
            Ok(snapshot) => snapshot,
            Err(error) => return self.reject(&current, None, error.to_string()),
        };
        if snapshot.revision == current.revision {
            return Outcome::Unchanged;
        }
        let revision = snapshot.revision.clone();
        let next = match State::build(snapshot, self.clock.clone()) {
            Ok(next) => next,
            Err(error) => return self.reject(&current, Some(&revision), error.to_string()),
        };
        let line = {
            let mut status = self.lock();
            status.revision = next.revision.clone();
            status.author = next.author.clone();
            status.loaded_at = self.clock.unix_seconds();
            status.reloads += 1;
            applied(Some(&current.config), &next, &status)
        };
        self.audit.record(&line);
        self.state.send_replace(Arc::new(next));
        Outcome::Applied
    }

    fn reject(&self, current: &State, revision: Option<&str>, error: String) -> Outcome {
        {
            let mut status = self.lock();
            status.failed_reloads += 1;
            status.last_failure = Some(error.clone());
        }
        let line = json!({
            "event": "config_reload",
            "at": self.clock.unix_seconds(),
            "outcome": "rejected",
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
    let hosts = |config: Option<&Config>| -> BTreeSet<String> {
        config
            .map(|config| {
                config
                    .routes
                    .iter()
                    .map(|route| route.host.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (old, new) = (hosts(previous), hosts(Some(&next.config)));
    let route = |config: &Config, host: &str| {
        config
            .routes
            .iter()
            .find(|route| route.host.eq_ignore_ascii_case(host))
            .cloned()
    };
    let changed: Vec<&String> = match previous {
        Some(previous) => old
            .intersection(&new)
            .filter(|host| route(previous, host) != route(&next.config, host))
            .collect(),
        None => Vec::new(),
    };
    let restart: Vec<&str> = match previous {
        Some(previous) => listen_addresses(previous)
            .into_iter()
            .zip(listen_addresses(&next.config))
            .filter(|(old, new)| old != new)
            .map(|((field, _), _)| field)
            .collect(),
        None => Vec::new(),
    };
    json!({
        "event": "config_reload",
        "at": status.loaded_at,
        "outcome": "applied",
        "revision": next.revision,
        "author": next.author,
        "routes_added": new.difference(&old).collect::<Vec<_>>(),
        "routes_removed": old.difference(&new).collect::<Vec<_>>(),
        "routes_changed": changed,
        "restart_required": restart,
    })
    .to_string()
}
