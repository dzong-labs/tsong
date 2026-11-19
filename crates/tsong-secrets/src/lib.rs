//! Reads the secrets a config refers to. Each scheme has a source, and
//! [`Secrets`] sends each reference to the source for its scheme.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub use tsong_config::{Scheme, SecretRef};

/// A secret's bytes. Its `Debug` hides them.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Why a secret couldn't be read. It names the reference, never the
/// secret.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret {0} is not set")]
    NotSet(String),
    #[error("secret {0} is not Unicode")]
    NotUnicode(String),
    #[error("reading secret {reference}: {source}")]
    Read {
        reference: String,
        source: std::io::Error,
    },
    #[error("secret {0} is empty")]
    Empty(String),
    #[error("no source reads {0} secrets")]
    NoSource(Scheme),
}

/// The secret a source read, or why it couldn't.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Secret, SecretError>> + Send + 'a>>;

/// Reads the secrets of one scheme.
pub trait SecretSource: Send + Sync {
    /// The secret `reference` names. Its scheme is this source's.
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> ResolveFuture<'a>;
}

/// Reads `env:` secrets from environment variables.
#[derive(Debug, Clone, Copy, Default)]
pub struct Env;

impl SecretSource for Env {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> ResolveFuture<'a> {
        let read = match std::env::var(reference.id()) {
            Ok(value) => Ok(Secret::new(value.into_bytes())),
            Err(std::env::VarError::NotPresent) => Err(SecretError::NotSet(reference.to_string())),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(SecretError::NotUnicode(reference.to_string()))
            }
        };
        Box::pin(async move { read })
    }
}

/// Reads `file:` secrets from files.
#[derive(Debug, Clone, Copy, Default)]
pub struct File;

impl SecretSource for File {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> ResolveFuture<'a> {
        // A secret is small and read only at startup and reload, so it is
        // read in place, without a runtime.
        let read = std::fs::read(reference.id())
            .map(Secret::new)
            .map_err(|source| SecretError::Read {
                reference: reference.to_string(),
                source,
            });
        Box::pin(async move { read })
    }
}

/// A source for each scheme.
#[derive(Clone)]
pub struct Secrets {
    sources: BTreeMap<Scheme, Arc<dyn SecretSource>>,
}

impl Default for Secrets {
    /// Environment variables and files.
    fn default() -> Self {
        Self::empty()
            .with(Scheme::Env, Arc::new(Env))
            .with(Scheme::File, Arc::new(File))
    }
}

impl Secrets {
    /// No sources: every reference fails until one is added.
    pub fn empty() -> Self {
        Self {
            sources: BTreeMap::new(),
        }
    }

    /// These sources, with `source` reading `scheme` in place of any other.
    pub fn with(mut self, scheme: Scheme, source: Arc<dyn SecretSource>) -> Self {
        self.sources.insert(scheme, source);
        self
    }

    /// The secret `reference` names. An empty secret is refused.
    pub async fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        let source = self
            .sources
            .get(&reference.scheme())
            .ok_or(SecretError::NoSource(reference.scheme()))?;
        let secret = source.resolve(reference).await?;
        if secret.expose().is_empty() {
            return Err(SecretError::Empty(reference.to_string()));
        }
        Ok(secret)
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.sources.keys()).finish()
    }
}
