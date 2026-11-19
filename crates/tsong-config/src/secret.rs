//! References to secrets, written as a table with one key, the scheme:
//! `{ env = "TSONG_SECRET" }`, `{ file = "keys/k1.pem" }`. A secret field
//! takes only a reference, never the secret itself, so a config holds no
//! secrets and can live in Git. A string is a value and a table is a
//! reference, so neither needs escaping.

use std::fmt;
use std::path::Path;

use serde::de::{Deserialize, Deserializer, Error};
use toml::Value;

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

    /// The scheme as a reference writes it: the table's key.
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

/// Why a value isn't a secret reference. It never quotes the value, which
/// may be a secret written in by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    #[error(
        r#"a secret must be a reference, such as {{ env = "NAME" }} or {{ file = "path" }}, never the secret"#
    )]
    NotATable,
    #[error("a secret reference must have exactly one key, env or file")]
    NotOneScheme,
    #[error("a secret reference's key must be env or file")]
    UnknownScheme,
    #[error("a secret reference's id must be a string")]
    IdNotAString,
    #[error("a secret reference's id must not be empty")]
    NoId,
}

impl SecretRef {
    /// A reference to the secret `id` names in `scheme`.
    pub fn new(scheme: Scheme, id: impl Into<String>) -> Result<Self, SecretRefError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SecretRefError::NoId);
        }
        Ok(Self { scheme, id })
    }

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

/// The reference as a config writes it, such as `{ env = "NAME" }`.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ {} = \"", self.scheme)?;
        for c in self.id.chars() {
            match c {
                '"' => f.write_str("\\\"")?,
                '\\' => f.write_str("\\\\")?,
                '\n' => f.write_str("\\n")?,
                '\t' => f.write_str("\\t")?,
                '\r' => f.write_str("\\r")?,
                c if c.is_control() => write!(f, "\\u{:04X}", u32::from(c))?,
                c => fmt::Write::write_char(f, c)?,
            }
        }
        f.write_str("\" }")
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    /// Reads any value first, so a value that isn't a reference is refused
    /// by shape, and its contents never reach an error.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fail = |error: SecretRefError| D::Error::custom(error);
        // A value TOML can't hold, such as an integer past 64 bits, fails
        // here; that error would quote it.
        let value =
            Value::deserialize(deserializer).map_err(|_| fail(SecretRefError::NotATable))?;
        let Value::Table(table) = value else {
            return Err(fail(SecretRefError::NotATable));
        };
        let mut entries = table.into_iter();
        let (Some((key, id)), None) = (entries.next(), entries.next()) else {
            return Err(fail(SecretRefError::NotOneScheme));
        };
        let scheme = Scheme::ALL
            .into_iter()
            .find(|known| known.name() == key)
            .ok_or_else(|| fail(SecretRefError::UnknownScheme))?;
        let Value::String(id) = id else {
            return Err(fail(SecretRefError::IdNotAString));
        };
        Self::new(scheme, id).map_err(fail)
    }
}
