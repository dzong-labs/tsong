//! A PKCS#8 PEM private key, signing in process.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::{KeyError, SignFuture, SigningAlgorithm, SigningKey};

/// A private key read from PEM, for one algorithm.
pub struct FileKey {
    kid: String,
    algorithm: SigningAlgorithm,
    key: Key,
    jwk: Value,
}

enum Key {
    Ec(EcdsaKeyPair),
    Rsa(Arc<RsaKeyPair>, &'static signature::RsaSignatureEncoding),
    Ed(Ed25519KeyPair),
}

/// The key type an algorithm needs, as errors name it. For ECDSA and
/// EdDSA, it is also the JWK `crv`.
fn key_type(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::ES256 => "P-256",
        SigningAlgorithm::ES384 => "P-384",
        SigningAlgorithm::EdDSA => "Ed25519",
        SigningAlgorithm::RS256
        | SigningAlgorithm::RS384
        | SigningAlgorithm::RS512
        | SigningAlgorithm::PS256
        | SigningAlgorithm::PS384
        | SigningAlgorithm::PS512 => "RSA (2048 to 8192 bits)",
    }
}

impl FileKey {
    /// Parses a PKCS#8 PEM private key of the type `algorithm` signs with.
    pub fn from_pem(
        kid: &str,
        algorithm: SigningAlgorithm,
        pem: impl AsRef<[u8]>,
    ) -> Result<Self, KeyError> {
        let decode = || KeyError::Decode {
            kid: kid.to_owned(),
            expected: key_type(algorithm),
        };
        let pem = pem::parse(pem).map_err(|_| decode())?;
        let der = pem.contents();
        let rsa = |encoding| {
            // aws-lc-rs refuses a modulus outside 2048 to 8192 bits.
            let pair = RsaKeyPair::from_pkcs8(der).map_err(|_| decode())?;
            let public = pair.public_key();
            let public = json!({
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero()),
                "e": URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero()),
            });
            Ok((Key::Rsa(Arc::new(pair), encoding), public))
        };
        let (key, public) = match algorithm {
            SigningAlgorithm::ES256 | SigningAlgorithm::ES384 => {
                let signing = if algorithm == SigningAlgorithm::ES256 {
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING
                } else {
                    &signature::ECDSA_P384_SHA384_FIXED_SIGNING
                };
                let pair = EcdsaKeyPair::from_pkcs8(signing, der).map_err(|_| decode())?;
                // The uncompressed point: 0x04, then x and y of equal length.
                let point = pair.public_key().as_ref();
                let coordinates = point.get(1..).ok_or_else(decode)?;
                let (x, y) = coordinates.split_at(coordinates.len() / 2);
                let public = json!({
                    "kty": "EC",
                    "crv": key_type(algorithm),
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                });
                (Key::Ec(pair), public)
            }
            SigningAlgorithm::EdDSA => {
                let pair = Ed25519KeyPair::from_pkcs8(der).map_err(|_| decode())?;
                let public = json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
                });
                (Key::Ed(pair), public)
            }
            SigningAlgorithm::RS256 => rsa(&signature::RSA_PKCS1_SHA256)?,
            SigningAlgorithm::RS384 => rsa(&signature::RSA_PKCS1_SHA384)?,
            SigningAlgorithm::RS512 => rsa(&signature::RSA_PKCS1_SHA512)?,
            SigningAlgorithm::PS256 => rsa(&signature::RSA_PSS_SHA256)?,
            SigningAlgorithm::PS384 => rsa(&signature::RSA_PSS_SHA384)?,
            SigningAlgorithm::PS512 => rsa(&signature::RSA_PSS_SHA512)?,
        };
        let mut jwk = public;
        if let Some(fields) = jwk.as_object_mut() {
            fields.insert("kid".into(), json!(kid));
            fields.insert("use".into(), json!("sig"));
            fields.insert("alg".into(), json!(algorithm.name()));
        }
        Ok(Self {
            kid: kid.to_owned(),
            algorithm,
            key,
            jwk,
        })
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey for FileKey {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn public_jwk(&self) -> Value {
        self.jwk.clone()
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> SignFuture<'a> {
        let failed = |_| KeyError::Sign {
            kid: self.kid.clone(),
        };
        match &self.key {
            Key::Ec(pair) => {
                let signed = pair
                    .sign(&SystemRandom::new(), message)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(failed);
                Box::pin(async move { signed })
            }
            Key::Ed(pair) => {
                let signature = pair.sign(message).as_ref().to_vec();
                Box::pin(async move { Ok(signature) })
            }
            // An RSA signature takes milliseconds, more for a large key, so
            // under Tokio it runs on the blocking pool rather than an async
            // worker. Outside a runtime it signs in place.
            Key::Rsa(pair, encoding) => {
                let (pair, encoding) = (Arc::clone(pair), *encoding);
                let sign = move |message: &[u8]| {
                    let mut signature = vec![0; pair.public_modulus_len()];
                    pair.sign(encoding, &SystemRandom::new(), message, &mut signature)
                        .map(|()| signature)
                };
                let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                    let signed = sign(message).map_err(failed);
                    return Box::pin(async move { signed });
                };
                let message = message.to_vec();
                Box::pin(async move {
                    runtime
                        .spawn_blocking(move || sign(&message))
                        .await
                        .map_err(|_| KeyError::Sign {
                            kid: self.kid.clone(),
                        })?
                        .map_err(failed)
                })
            }
        }
    }
}
