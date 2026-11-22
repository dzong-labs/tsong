//! A token that passed validation.

use std::collections::BTreeSet;

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
    /// The `aud` claim's values. Validation has refused an `aud` that is
    /// not a string or an array of strings.
    pub fn audiences(&self) -> Vec<&str> {
        self.claims.get("aud").and_then(strings).unwrap_or_default()
    }

    /// The scopes the token grants: its `scope` claim, space-separated, and
    /// its `scp` claim, a string or an array, as Entra issues it.
    /// Validation has refused a scope claim of any other shape, and an
    /// `scp` item that is empty or holds whitespace, so nothing here is
    /// dropped or split.
    pub fn scopes(&self) -> BTreeSet<&str> {
        let mut scopes = BTreeSet::new();
        for name in ["scope", "scp"] {
            match self.claims.get(name) {
                Some(Value::String(text)) => scopes.extend(text.split_whitespace()),
                Some(value) => scopes.extend(strings(value).unwrap_or_default()),
                None => {}
            }
        }
        scopes
    }
}

/// The values of a claim that is a string or an array of strings, or
/// `None` when it is another shape or an item is not a string.
pub(crate) fn strings(value: &Value) -> Option<Vec<&str>> {
    match value {
        Value::String(text) => Some(vec![text.as_str()]),
        Value::Array(items) => items.iter().map(Value::as_str).collect(),
        _ => None,
    }
}
