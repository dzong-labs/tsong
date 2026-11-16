//! Where a config comes from: a file, or a Git branch, behind one trait.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use sha2::{Digest, Sha256};

use crate::{Config, ConfigError};

/// A validated config and the revision it was read at.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub config: Config,
    /// What identifies this version of the config: a commit ID, or a hash
    /// of a file's contents. Equal revisions hold equal configs.
    pub revision: String,
    /// Who made this revision, when the store knows.
    pub author: Option<String>,
}

/// What [`ConfigStore::load`] returns.
pub type LoadFuture<'a> = Pin<Box<dyn Future<Output = Result<Snapshot, ConfigError>> + Send + 'a>>;

/// A source of validated configs.
pub trait ConfigStore: Send + Sync {
    /// Loads the current config, validated.
    fn load(&self) -> LoadFuture<'_>;
}

/// A TOML file on disk.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ConfigStore for FileStore {
    fn load(&self) -> LoadFuture<'_> {
        let result = std::fs::read_to_string(&self.path)
            .map_err(|source| ConfigError::Read {
                path: self.path.clone(),
                source,
            })
            .and_then(|text| {
                Ok(Snapshot {
                    config: Config::from_file_text(&text, &self.path)?,
                    revision: hex(&Sha256::digest(text.as_bytes())),
                    author: None,
                })
            });
        Box::pin(async move { result })
    }
}

/// Bytes as lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
