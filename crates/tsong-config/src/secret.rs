//! References to secrets, written as a table with one key, the scheme:
//! `{ env = "TSONG_SECRET" }`, `{ file = "keys/k1.pem" }`. A secret field
//! takes only a reference, never the secret itself, so a config holds no
//! secrets and can live in Git. A string is a value and a table is a
//! reference, so neither needs escaping.

use std::fmt;
use std::path::Path;

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};

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
        write!(f, "{{ {} = {:?} }}", self.scheme, self.id)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ReferenceVisitor)
    }
}

struct ReferenceVisitor;

/// A value that isn't a table: refused without being quoted.
fn not_a_table<E: de::Error>() -> Result<SecretRef, E> {
    Err(E::custom(SecretRefError::NotATable))
}

impl<'de> Visitor<'de> for ReferenceVisitor {
    type Value = SecretRef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a secret reference table")
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<SecretRef, E> {
        not_a_table()
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<SecretRef, E> {
        not_a_table()
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<SecretRef, E> {
        not_a_table()
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<SecretRef, E> {
        not_a_table()
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<SecretRef, E> {
        not_a_table()
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, _: A) -> Result<SecretRef, A::Error> {
        not_a_table()
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SecretRef, A::Error> {
        let fail = |error: SecretRefError| <A::Error as de::Error>::custom(error);
        let key: String = map
            .next_key()?
            .ok_or_else(|| fail(SecretRefError::NotOneScheme))?;
        let scheme = Scheme::ALL
            .into_iter()
            .find(|known| known.name() == key)
            .ok_or_else(|| fail(SecretRefError::UnknownScheme))?;
        let id = map
            .next_value::<Id>()?
            .0
            .ok_or_else(|| fail(SecretRefError::IdNotAString))?;
        if map.next_key::<de::IgnoredAny>()?.is_some() {
            return Err(fail(SecretRefError::NotOneScheme));
        }
        SecretRef::new(scheme, id).map_err(fail)
    }
}

/// A reference's id: a string, or nothing for any other value, which is
/// refused without being quoted.
struct Id(Option<String>);

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor;

        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: de::Error>(self, id: &str) -> Result<Id, E> {
                Ok(Id(Some(id.to_owned())))
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Id, E> {
                Ok(Id(None))
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Id, E> {
                Ok(Id(None))
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Id, E> {
                Ok(Id(None))
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Id, E> {
                Ok(Id(None))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Id, A::Error> {
                while seq.next_element::<de::IgnoredAny>()?.is_some() {}
                Ok(Id(None))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Id, A::Error> {
                while map
                    .next_entry::<de::IgnoredAny, de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(Id(None))
            }
        }

        deserializer.deserialize_any(IdVisitor)
    }
}
