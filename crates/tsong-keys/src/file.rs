//! A P-256 private key in a PKCS#8 PEM file, signing ES256 in process.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{self, Signature};
use p256::pkcs8::DecodePrivateKey;

use crate::{KeyError, SignFuture, SigningAlgorithm, SigningKey};

/// An ES256 key read from a PEM file.
pub struct FileKey {
    kid: String,
    key: ecdsa::SigningKey,
}

impl FileKey {
    /// Reads the key at `path`.
    pub fn load(kid: &str, path: &Path) -> Result<Self, KeyError> {
        let pem = std::fs::read_to_string(path).map_err(|source| KeyError::Read {
            kid: kid.to_owned(),
            source,
        })?;
        Self::from_pem(kid, &pem)
    }

    /// Parses a PKCS#8 PEM P-256 private key.
    pub fn from_pem(kid: &str, pem: &str) -> Result<Self, KeyError> {
        let key = ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|_| KeyError::Decode {
            kid: kid.to_owned(),
        })?;
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey for FileKey {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn public_jwk(&self) -> serde_json::Value {
        let point = self.key.verifying_key().to_sec1_point(false);
        let encode = |bytes: Option<&_>| URL_SAFE_NO_PAD.encode(bytes.expect("uncompressed point"));
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": encode(point.x()),
            "y": encode(point.y()),
            "kid": self.kid,
            "use": "sig",
            "alg": "ES256",
        })
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a> {
        let signature: Signature = self.key.sign(message);
        let bytes = signature.to_bytes().to_vec();
        Box::pin(async move { Ok(bytes) })
    }
}
