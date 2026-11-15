//! Test doubles for an inbound issuer: a signing key and a JWKS source.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use tsong_config::TrustedIssuer;

use crate::{FetchError, FetchFuture, JwksFetcher};

/// An ES256 key for a fixed seed, so tests need no randomness.
pub struct TestKey {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

impl TestKey {
    pub fn new(kid: &str, seed: u8) -> Self {
        let key = SigningKey::from_slice(&[seed; 32]).expect("a valid scalar");
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("encodable");
        let point = key.verifying_key().to_sec1_point(false);
        let coordinate = |bytes: Option<&_>| URL_SAFE_NO_PAD.encode(bytes.expect("uncompressed"));
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": coordinate(point.x()),
            "y": coordinate(point.y()),
            "kid": kid,
            "use": "sig",
            "alg": "ES256",
        });
        Self {
            kid: kid.into(),
            encoding: EncodingKey::from_ec_pem(pem.as_bytes()).expect("a P-256 PEM"),
            jwk,
        }
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
    pub fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding).expect("signable")
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
