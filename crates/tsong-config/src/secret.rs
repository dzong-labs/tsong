//! References to secrets, written `<scheme>:<id>`: `env:TSONG_SECRET`,
//! `file:keys/k1.pem`. A secret field takes only a reference, never the
//! secret itself, so a config holds no secrets and can live in Git.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, de::Error};

/// Where a secret is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    /// An environment variable, named by the id.
    Env,
    /// A file, at the path the id gives. A relative path is taken from the
    /// config file's directory.
    File,
}

impl Scheme {
    /// Every scheme.
    pub const ALL: [Self; 2] = [Self::Env, Self::File];

    /// The scheme as a reference writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A reference to a secret: a scheme, and an id the scheme's source looks
/// the secret up by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    scheme: Scheme,
    id: String,
}

/// Why text isn't a secret reference. It never quotes the text, which may
/// be a secret written in by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    #[error("a secret must be a reference, <scheme>:<id>, with scheme env or file")]
    NoScheme,
    #[error("a secret reference's scheme must be env or file")]
    UnknownScheme,
    #[error("a secret reference needs an id after its scheme")]
    NoId,
}

impl SecretRef {
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Takes a relative file path from `dir`.
    pub(crate) fn rebase(&mut self, dir: &Path) -> Result<(), RebaseError> {
        if !self.is_relative_file() {
            return Ok(());
        }
        self.id = dir
            .join(&self.id)
            .into_os_string()
            .into_string()
            .map_err(|_| RebaseError)?;
        Ok(())
    }

    /// Whether this is a file reference with a relative path.
    pub(crate) fn is_relative_file(&self) -> bool {
        self.scheme == Scheme::File && Path::new(&self.id).is_relative()
    }
}

/// A directory that isn't UTF-8, which a reference can't hold.
#[derive(Debug)]
pub(crate) struct RebaseError;

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (scheme, id) = text.split_once(':').ok_or(SecretRefError::NoScheme)?;
        let scheme = Scheme::ALL
            .into_iter()
            .find(|known| known.name() == scheme)
            .ok_or(SecretRefError::UnknownScheme)?;
        if id.is_empty() {
            return Err(SecretRefError::NoId);
        }
        Ok(Self {
            scheme,
            id: id.to_owned(),
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.id)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}
