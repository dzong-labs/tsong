//! Where a config comes from. A file today; Git or a cloud parameter store
//! later, behind the same trait.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use crate::{Config, ConfigError};

/// What [`ConfigStore::load`] returns.
pub type LoadFuture<'a> = Pin<Box<dyn Future<Output = Result<Config, ConfigError>> + Send + 'a>>;

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
        let result = Config::load(&self.path);
        Box::pin(async move { result })
    }
}
