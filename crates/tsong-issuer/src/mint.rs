//! Signing the tokens the issuer mints.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use tsong_keys::{SigningAlgorithm, SigningKey};

use crate::ExchangeError;

/// A compact JWS of `claims`, signed by `key`, typed as an access token
/// (RFC 9068).
pub(crate) async fn sign(
    key: &dyn SigningKey,
    claims: &Map<String, Value>,
) -> Result<String, ExchangeError> {
    let header = json!({
        "alg": algorithm(key.algorithm()),
        "typ": "at+jwt",
        "kid": key.kid(),
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(Value::Object(claims.clone()).to_string()),
    );
    let signature = key.sign(input.as_bytes()).await?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

fn algorithm(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::ES256 => "ES256",
    }
}

/// A fresh token ID: 128 random bits.
pub(crate) fn jti() -> Result<String, ExchangeError> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| ExchangeError::Server(format!("randomness: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
