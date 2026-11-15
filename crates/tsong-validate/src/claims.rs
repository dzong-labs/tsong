//! A token that passed validation.

use serde_json::{Map, Value};

/// A validated token's claims, and the trusted issuer that signed it.
#[derive(Debug, Clone, PartialEq)]
pub struct Validated {
    issuer: String,
    claims: Map<String, Value>,
}

impl Validated {
    pub(crate) fn new(issuer: String, claims: Map<String, Value>) -> Self {
        Self { issuer, claims }
    }

    /// The name of the trusted issuer, as the config's `trusted_issuers`
    /// keys it.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Every claim.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The `sub` claim, when it is a string.
    pub fn subject(&self) -> Option<&str> {
        self.claims.get("sub").and_then(Value::as_str)
    }

    /// The `exp` claim, in whole seconds. Validation guarantees one.
    pub fn expires_at(&self) -> Option<u64> {
        let exp = self.claims.get("exp")?;
        exp.as_u64()
            .or_else(|| exp.as_f64().map(|seconds| seconds as u64))
    }
}
