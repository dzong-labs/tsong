//! The active key and the retiring ones.

use std::collections::BTreeSet;
use std::sync::Arc;

use tsong_config::{KeyProvider, KeyState, Signing};

use crate::{FileKey, KeyError, SigningKey};

/// The keys an issuer publishes: one that signs, and the retiring ones that
/// stay in the JWKS until the tokens they signed expire.
#[derive(Clone)]
pub struct KeySet {
    active: Arc<dyn SigningKey>,
    retiring: Vec<Arc<dyn SigningKey>>,
}

impl KeySet {
    /// A set from keys loaded elsewhere. Kids must be unique.
    pub fn new(
        active: Arc<dyn SigningKey>,
        retiring: Vec<Arc<dyn SigningKey>>,
    ) -> Result<Self, KeyError> {
        let mut kids = BTreeSet::new();
        for key in std::iter::once(&active).chain(&retiring) {
            if !kids.insert(key.kid().to_owned()) {
                return Err(KeyError::DuplicateKid(key.kid().to_owned()));
            }
        }
        Ok(Self { active, retiring })
    }

    /// Loads the keys a config lists.
    pub fn from_config(signing: &Signing) -> Result<Self, KeyError> {
        let mut active = None;
        let mut retiring = Vec::new();
        for entry in &signing.keys {
            let key: Arc<dyn SigningKey> = match signing.provider {
                KeyProvider::File => {
                    let path = entry.path.as_deref().ok_or_else(|| KeyError::MissingPath {
                        kid: entry.kid.clone(),
                    })?;
                    Arc::new(FileKey::load(&entry.kid, path)?)
                }
            };
            match entry.state {
                KeyState::Active if active.is_some() => return Err(KeyError::ManyActiveKeys),
                KeyState::Active => active = Some(key),
                KeyState::Retiring => retiring.push(key),
            }
        }
        Self::new(active.ok_or(KeyError::NoActiveKey)?, retiring)
    }

    /// The key that signs new tokens.
    pub fn active(&self) -> &dyn SigningKey {
        self.active.as_ref()
    }

    /// Every key, active first.
    pub fn keys(&self) -> impl Iterator<Item = &dyn SigningKey> {
        std::iter::once(&self.active)
            .chain(&self.retiring)
            .map(Arc::as_ref)
    }

    /// The JWKS document downstream services fetch to validate Tsong's tokens.
    pub fn jwks(&self) -> serde_json::Value {
        let keys: Vec<_> = self.keys().map(SigningKey::public_jwk).collect();
        serde_json::json!({ "keys": keys })
    }
}
