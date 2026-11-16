//! Configs, signing keys and stores for the reload tests.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use tsong::reload::Audit;
use tsong_config::{Config, ConfigError, ConfigStore, LoadFuture, Snapshot};

pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub const NOW: u64 = 1_000_000;

/// Writes a signing key to `dir` and returns its path.
pub fn write_key(dir: &Path) -> TestResult<PathBuf> {
    let pem = SigningKey::from_slice(&[7; 32])?.to_pkcs8_pem(LineEnding::LF)?;
    let path = dir.join("k1.pem");
    std::fs::write(&path, pem.as_bytes())?;
    Ok(path)
}

/// A route on `host` allowing `scopes`.
pub fn route(name: &str, host: &str, scopes: &str) -> String {
    format!(
        r#"
[[routes]]
name = "{name}"
host = "{host}"
downstream = "https://{name}-lb.example.com"
append_audience = ""
allowed_audiences = ["*"]
allowed_scopes = [{scopes}]
"#
    )
}

/// A config issuing as `issuer` on `port`, signing with the key at `key`,
/// with `routes`.
pub fn config_text(key: &Path, issuer: &str, port: u16, routes: &str) -> String {
    format!(
        r#"
[issuer]
url = "{issuer}"
listen = "127.0.0.1:{port}"
token_lifetime = "15m"
clock_skew = "30s"

[issuer.signing]
provider = "file"
algorithm = "ES256"

[[issuer.signing.keys]]
kid = "k1"
path = '{}'
state = "active"

[gateway]
listen = "127.0.0.1:0"
allow = ["127.0.0.0/8"]

[gateway.cache]
max_entries = 10
{routes}"#,
        key.display()
    )
}

/// A snapshot of `text` at `revision`.
pub fn snapshot(text: &str, revision: &str) -> TestResult<Snapshot> {
    Ok(Snapshot {
        config: Config::from_toml(text)?,
        revision: revision.into(),
        author: Some("Ada <ada@example.test>".into()),
    })
}

/// A store that answers each load with the next queued result, and with a
/// store error once the queue is empty.
#[derive(Default)]
pub struct QueueStore {
    queue: Mutex<VecDeque<Result<Snapshot, ConfigError>>>,
}

impl QueueStore {
    pub fn push(&self, result: Result<Snapshot, ConfigError>) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(result);
    }
}

/// A `QueueStore` the test keeps a handle on while the reloader owns it.
pub struct Shared(pub Arc<QueueStore>);

impl ConfigStore for Shared {
    fn load(&self) -> LoadFuture<'_> {
        let next = self
            .0
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Err(ConfigError::Store("nothing queued".into())));
        Box::pin(async move { next })
    }
}

/// Audit lines, kept for inspection.
#[derive(Default)]
pub struct Recorded(Mutex<Vec<String>>);

impl Recorded {
    /// The lines recorded so far, parsed as JSON.
    pub fn parsed(&self) -> TestResult<Vec<serde_json::Value>> {
        let lines = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(lines
            .iter()
            .map(|line| serde_json::from_str(line))
            .collect::<Result<_, _>>()?)
    }
}

impl Audit for Recorded {
    fn record(&self, line: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.to_owned());
    }
}
