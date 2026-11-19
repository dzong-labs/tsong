//! Signing keys for the tokens Tsong issues.
//!
//! [`SigningKey`] signs bytes and describes its public half; it never hands
//! out private key material, so the same trait fits a key file, a cloud KMS
//! or an HSM. [`KeySet`] holds an active key per algorithm and the retiring
//! ones, and publishes them all as a JWKS. [`FileKey`] is the first
//! provider.

mod file;
mod set;

use std::future::Future;
use std::pin::Pin;

pub use file::FileKey;
pub use set::KeySet;
pub use tsong_config::SigningAlgorithm;

/// What [`SigningKey::sign`] returns.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + 'a>>;

/// A key that signs, wherever its private half lives.
pub trait SigningKey: Send + Sync {
    /// The key ID that JWS headers and the JWKS carry.
    fn kid(&self) -> &str;

    /// The JWS algorithm it signs with.
    fn algorithm(&self) -> SigningAlgorithm;

    /// The public key as a JWK, with `kid`, `use` and `alg` set.
    fn public_jwk(&self) -> serde_json::Value;

    /// Signs `message`, returning the signature in JWS form: for ECDSA,
    /// the fixed-width `r || s`.
    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a>;
}

/// Why a key couldn't be loaded or used.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key {kid:?}: {source}")]
    Secret {
        kid: String,
        source: tsong_secrets::SecretError,
    },
    #[error("key {kid:?} is not a PKCS#8 PEM {expected} private key")]
    Decode { kid: String, expected: &'static str },
    #[error("key {kid:?} has no private_key")]
    MissingPrivateKey { kid: String },
    #[error("key {kid:?} failed to sign")]
    Sign { kid: String },
    #[error("no key is active")]
    NoActiveKey,
    #[error("more than one {0} key is active")]
    ManyActiveKeys(SigningAlgorithm),
    #[error("kid {0:?} appears more than once")]
    DuplicateKid(String),
}
