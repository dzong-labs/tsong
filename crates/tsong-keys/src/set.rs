//! The active keys and the retiring ones.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tsong_config::{KeyProvider, KeyState, Signing};
use tsong_secrets::Secrets;

use crate::{FileKey, KeyError, SigningAlgorithm, SigningKey};

/// The keys an issuer publishes: one that signs for each algorithm, and the
/// retiring ones that stay in the JWKS until the tokens they signed expire.
#[derive(Clone)]
pub struct KeySet {
    active: BTreeMap<SigningAlgorithm, Arc<dyn SigningKey>>,
    retiring: Vec<Arc<dyn SigningKey>>,
}

impl KeySet {
    /// A set from keys loaded elsewhere. Kids must be unique, at least one
    /// key must be active, and no two active keys may share an algorithm.
    pub fn new(
        active: Vec<Arc<dyn SigningKey>>,
        retiring: Vec<Arc<dyn SigningKey>>,
    ) -> Result<Self, KeyError> {
        let mut kids = BTreeSet::new();
        for key in active.iter().chain(&retiring) {
            if !kids.insert(key.kid().to_owned()) {
                return Err(KeyError::DuplicateKid(key.kid().to_owned()));
            }
        }
        let mut by_algorithm = BTreeMap::new();
        for key in active {
            let algorithm = key.algorithm();
            if by_algorithm.insert(algorithm, key).is_some() {
                return Err(KeyError::ManyActiveKeys(algorithm));
            }
        }
        if by_algorithm.is_empty() {
            return Err(KeyError::NoActiveKey);
        }
        Ok(Self {
            active: by_algorithm,
            retiring,
        })
    }

    /// Loads the keys a config lists, reading each through `secrets`.
    pub async fn from_config(signing: &Signing, secrets: &Secrets) -> Result<Self, KeyError> {
        let mut active = Vec::new();
        let mut retiring = Vec::new();
        for entry in &signing.keys {
            let key: Arc<dyn SigningKey> =
                match signing.provider {
                    KeyProvider::File => {
                        let reference = entry.private_key.as_ref().ok_or_else(|| {
                            KeyError::MissingPrivateKey {
                                kid: entry.kid.clone(),
                            }
                        })?;
                        let pem = secrets.resolve(reference).await.map_err(|source| {
                            KeyError::Secret {
                                kid: entry.kid.clone(),
                                source,
                            }
                        })?;
                        Arc::new(FileKey::from_pem(
                            &entry.kid,
                            entry.algorithm,
                            pem.expose(),
                        )?)
                    }
                };
            match entry.state {
                KeyState::Active => active.push(key),
                KeyState::Retiring => retiring.push(key),
            }
        }
        Self::new(active, retiring)
    }

    /// The key that signs new tokens with `algorithm`, if one is active.
    pub fn active(&self, algorithm: SigningAlgorithm) -> Option<&dyn SigningKey> {
        self.active.get(&algorithm).map(Arc::as_ref)
    }

    /// The active keys, ordered by algorithm.
    pub fn active_keys(&self) -> impl Iterator<Item = &dyn SigningKey> {
        self.active.values().map(Arc::as_ref)
    }

    /// Every key: the active ones by algorithm, then the retiring ones.
    pub fn keys(&self) -> impl Iterator<Item = &dyn SigningKey> {
        self.active_keys()
            .chain(self.retiring.iter().map(Arc::as_ref))
    }

    /// The JWKS document downstream services fetch to validate Tsong's tokens.
    pub fn jwks(&self) -> serde_json::Value {
        let keys: Vec<_> = self.keys().map(SigningKey::public_jwk).collect();
        serde_json::json!({ "keys": keys })
    }
}
