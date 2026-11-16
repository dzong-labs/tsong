//! Where a config comes from: a file, or a Git branch, behind one trait.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use sha2::{Digest, Sha256};

use crate::{Config, ConfigError};

/// A validated config and the revision it was read at.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub config: Config,
    /// What identifies where the config was read: a commit ID, or a hash
    /// of a file's contents.
    pub revision: String,
    /// What identifies the config's text: the file's blob ID in Git, or a
    /// hash of its contents. Equal contents hold equal configs, even at
    /// different revisions.
    pub content: String,
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
        let result = read(&self.path).and_then(|text| {
            let hash = hex(&Sha256::digest(text.as_bytes()));
            Ok(Snapshot {
                config: Config::from_file_text(&text, &self.path)?,
                revision: hash.clone(),
                content: hash,
                author: None,
            })
        });
        Box::pin(async move { result })
    }
}

/// The text of the file at `path`.
pub(crate) fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })
}

/// Hexadecimal text, in either case, as bytes.
pub fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

/// Bytes as lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}
