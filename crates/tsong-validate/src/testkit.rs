//! Test doubles for an inbound issuer: a signing key and a JWKS source.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey as EcKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use tsong_config::TrustedIssuer;
use tsong_keys::{FileKey, SigningAlgorithm, SigningKey};

use crate::{FetchError, FetchFuture, JwksFetcher};

/// Why a test double couldn't be built or used.
pub type TestKitError = Box<dyn std::error::Error + Send + Sync>;

/// A PKCS#8 PEM P-256 private key for a fixed seed, so tests need no
/// randomness.
pub fn pem(seed: u8) -> Result<String, TestKitError> {
    let key = EcKey::from_slice(&[seed; 32])?;
    Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
}

/// An ES256 key for a fixed seed.
pub struct TestKey {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

impl TestKey {
    pub fn new(kid: &str, seed: u8) -> Result<Self, TestKitError> {
        let pem = pem(seed)?;
        Ok(Self {
            kid: kid.into(),
            encoding: EncodingKey::from_ec_pem(pem.as_bytes())?,
            jwk: FileKey::from_pem(kid, SigningAlgorithm::ES256, &pem)?.public_jwk(),
        })
    }

    /// The public key as a JWK.
    pub fn jwk(&self) -> Value {
        self.jwk.clone()
    }

    /// The encoding key, to sign tokens with a custom header.
    pub fn encoding(&self) -> &EncodingKey {
        &self.encoding
    }

    /// An ES256 JWT of `claims`, naming this key.
    pub fn sign(&self, claims: &Value) -> Result<String, TestKitError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding)?)
    }
}

/// A JWKS source that counts its fetches and fails while told to.
#[derive(Default)]
pub struct FakeFetcher {
    keys: Mutex<Vec<Value>>,
    failing: Mutex<bool>,
    fetches: AtomicUsize,
}

impl FakeFetcher {
    pub fn with(keys: Vec<Value>) -> Self {
        let fetcher = Self::default();
        fetcher.set_keys(keys);
        fetcher
    }

    /// Replaces the JWKS it serves.
    pub fn set_keys(&self, keys: Vec<Value>) {
        *self.keys.lock().unwrap_or_else(|p| p.into_inner()) = keys;
    }

    /// Makes fetches fail, or succeed again.
    pub fn fail(&self, failing: bool) {
        *self.failing.lock().unwrap_or_else(|p| p.into_inner()) = failing;
    }

    /// How many times it has been fetched.
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl JwksFetcher for FakeFetcher {
    fn fetch<'a>(&'a self, _: &'a TrustedIssuer) -> FetchFuture<'a> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let result = if *self.failing.lock().unwrap_or_else(|p| p.into_inner()) {
            Err(FetchError::Discovery("down".into()))
        } else {
            let keys = self.keys.lock().unwrap_or_else(|p| p.into_inner()).clone();
            serde_json::from_value::<JwkSet>(json!({ "keys": keys }))
                .map_err(|error| FetchError::Discovery(error.to_string()))
        };
        Box::pin(async move { result })
    }
}
