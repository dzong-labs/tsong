//! Inbound token validation, shared by the issuer and the gateway.
//!
//! [`Validator::validate`] accepts a JWT only when every check passes: the
//! issuer is trusted, the algorithm is one the issuer is allowed, the `typ`
//! header is one of the issuer's token types, the signature verifies
//! against the issuer's JWKS, the audience is accepted, the `scope` and
//! `scp` claims are well formed, and the token is inside its `nbf`..`exp`
//! window, give or take the clock skew. The config sets the values each
//! check compares against; no check can be turned off.
//!
//! Each issuer's keys expire `jwks_max_age` after they were fetched.
//! [`Validator::refresh_due`] renews them before then; keys that expire
//! anyway are refetched by the next token. Until a fetch succeeds, the
//! issuer's tokens are refused and the fetch is retried every `jwks_retry`. A token with an unknown key ID, or whose
//! signature fails with a known one, refetches the keys once, no more often
//! than `jwks_refetch`.
//!
//! Opaque tokens need introspection, which isn't built yet: they fail with
//! [`ValidateError::Unsupported`].

mod claims;
mod jwks;
#[cfg(feature = "test-util")]
pub mod testkit;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tsong_clock::Clock;
use tsong_config::{
    Config, InboundAlgorithm, TrustedIssuer, Validation, is_scope_char, is_scope_token,
};

pub use claims::Validated;
pub use jwks::{FetchError, FetchFuture, HttpFetcher, JwksFetcher};

/// Why a token was refused.
#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    #[error("the token is not a well-formed JWT")]
    Malformed,
    #[error("the token has no {0} claim")]
    MissingClaim(&'static str),
    #[error("the token's {0} claim is not valid")]
    InvalidClaim(&'static str),
    #[error("issuer {0:?} is not trusted")]
    UntrustedIssuer(String),
    #[error("{0} is not supported yet")]
    Unsupported(&'static str),
    #[error("algorithm {0} is not allowed for this issuer")]
    Algorithm(String),
    #[error("the token has no typ header")]
    MissingType,
    #[error("token type is not accepted for this issuer")]
    TokenType,
    #[error("the token has no kid")]
    MissingKid,
    #[error("no key {0:?} in the issuer's JWKS")]
    UnknownKey(String),
    #[error("the signature is not valid")]
    Signature,
    #[error("no audience in the token is accepted")]
    Audience,
    #[error("the token has expired")]
    Expired,
    #[error("the token is not valid yet")]
    NotYetValid,
    #[error("fetching the issuer's JWKS: {0}")]
    Jwks(#[from] FetchError),
    #[error("the issuer's keys are missing or expired, and no fetch has succeeded since")]
    KeysExpired,
}

/// Validates inbound tokens against the trusted issuers of one config.
pub struct Validator {
    issuers: Vec<Issuer>,
    fetcher: Arc<dyn JwksFetcher>,
    clock: Arc<dyn Clock>,
    skew: u64,
}

/// A trusted issuer and its cached keys.
struct Issuer {
    name: String,
    trusted: TrustedIssuer,
    keys: Mutex<Keys>,
}

#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, Jwk>,
    /// When the keys were last fetched successfully.
    fetched_at: Option<SystemTime>,
    /// When a fetch was last tried, successful or not.
    tried_at: Option<SystemTime>,
    /// When the last fetch failed, while no fetch has succeeded since.
    failed_at: Option<SystemTime>,
}

/// How long ago `then` was, or zero when it is in the future.
fn age(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or(Duration::ZERO)
}

impl Keys {
    /// Whether the keys were fetched less than `max_age` ago.
    fn fresh(&self, now: SystemTime, max_age: Duration) -> bool {
        self.fetched_at
            .is_some_and(|fetched_at| age(now, fetched_at) < max_age)
    }

    /// Whether `jwks_refetch` has passed since the last try, for a refetch
    /// a token asks for.
    fn may_refetch(&self, now: SystemTime, trusted: &TrustedIssuer) -> bool {
        self.tried_at
            .is_none_or(|tried_at| age(now, tried_at) >= trusted.jwks_refetch)
    }

    /// Whether `jwks_retry` has passed since the last failure, for fetching
    /// missing or expired keys.
    fn may_retry(&self, now: SystemTime, trusted: &TrustedIssuer) -> bool {
        self.failed_at
            .is_none_or(|failed_at| age(now, failed_at) >= trusted.jwks_retry)
    }
}

impl Validator {
    pub fn new(config: &Config, fetcher: Arc<dyn JwksFetcher>, clock: Arc<dyn Clock>) -> Self {
        let issuers = config
            .trusted_issuers
            .iter()
            .map(|(name, trusted)| Issuer {
                name: name.clone(),
                trusted: trusted.clone(),
                keys: Mutex::default(),
            })
            .collect();
        Self {
            issuers,
            fetcher,
            clock,
            skew: config.issuer.clock_skew.as_secs(),
        }
    }

    /// Validates `token`, returning its claims and the name of the trusted
    /// issuer that signed it.
    pub async fn validate(&self, token: &str) -> Result<Validated, ValidateError> {
        let Some((header, payload)) = split(token) else {
            return Err(self.not_a_jwt());
        };
        let iss = match payload.get("iss") {
            Some(Value::String(iss)) => iss,
            Some(_) => return Err(ValidateError::InvalidClaim("iss")),
            None => return Err(ValidateError::MissingClaim("iss")),
        };
        let issuer = self
            .issuers
            .iter()
            .find(|issuer| issuer.trusted.issuer == *iss)
            .ok_or_else(|| ValidateError::UntrustedIssuer(iss.clone()))?;
        if issuer.trusted.validation == Validation::Introspection {
            return Err(ValidateError::Unsupported("introspection"));
        }
        let algorithm = allowed_algorithm(&issuer.trusted, header.alg)?;
        check_type(&issuer.trusted, header.typ.as_deref())?;
        let kid = header.kid.ok_or(ValidateError::MissingKid)?;
        let (jwk, _) = self.key(issuer, &kid, Refetch::IfUnknown).await?;
        match verify(token, &jwk, algorithm) {
            Err(ValidateError::Signature) => {
                // The issuer may have replaced the key under the same kid.
                // A refetch that is skipped, fails or drops the kid leaves
                // the signature refused: a forgery stays a bad signature.
                let Ok((jwk, true)) = self.key(issuer, &kid, Refetch::Now).await else {
                    return Err(ValidateError::Signature);
                };
                verify(token, &jwk, algorithm)?;
            }
            other => other?,
        }
        self.check_audience(&issuer.trusted, &payload)?;
        self.check_times(&payload)?;
        check_scopes(&payload)?;
        Ok(Validated::new(issuer.name.clone(), payload))
    }

    /// Why a token that isn't a JWT was refused: it may be opaque, which
    /// needs introspection.
    fn not_a_jwt(&self) -> ValidateError {
        if self
            .issuers
            .iter()
            .any(|issuer| issuer.trusted.validation == Validation::Introspection)
        {
            ValidateError::Unsupported("introspection")
        } else {
            ValidateError::Malformed
        }
    }

    /// The key `kid` names, and whether the keys were refetched to find it.
    /// Missing or expired keys are fetched first, retried no more often than
    /// `jwks_retry` after a failure; until a fetch succeeds the key is
    /// refused. Fresh keys are refetched when `refetch` asks, no more often
    /// than `jwks_refetch`.
    async fn key(
        &self,
        issuer: &Issuer,
        kid: &str,
        refetch: Refetch,
    ) -> Result<(Jwk, bool), ValidateError> {
        let trusted = &issuer.trusted;
        let mut keys = issuer.keys.lock().await;
        let now = self.clock.now();
        let refetched = if !keys.fresh(now, trusted.jwks_max_age) {
            if !keys.may_retry(now, trusted) {
                return Err(ValidateError::KeysExpired);
            }
            self.refresh(issuer, &mut keys, now).await?;
            true
        } else {
            let wanted = match refetch {
                Refetch::IfUnknown => !keys.by_kid.contains_key(kid),
                Refetch::Now => true,
            };
            if wanted && keys.may_refetch(now, trusted) {
                self.refresh(issuer, &mut keys, now).await?;
                true
            } else {
                false
            }
        };
        let jwk = keys
            .by_kid
            .get(kid)
            .cloned()
            .ok_or_else(|| ValidateError::UnknownKey(kid.to_owned()))?;
        Ok((jwk, refetched))
    }

    /// Fetches the issuer's keys into `keys`, keeping the signing keys that
    /// have a key ID.
    async fn refresh(
        &self,
        issuer: &Issuer,
        keys: &mut Keys,
        now: SystemTime,
    ) -> Result<(), ValidateError> {
        keys.tried_at = Some(now);
        let set = match self.fetcher.fetch(&issuer.trusted).await {
            Ok(set) => set,
            Err(error) => {
                keys.failed_at = Some(now);
                return Err(error.into());
            }
        };
        keys.failed_at = None;
        keys.by_kid = set
            .keys
            .into_iter()
            .filter(|jwk| {
                matches!(
                    jwk.common.public_key_use,
                    None | Some(PublicKeyUse::Signature)
                )
            })
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, jwk)))
            .collect();
        keys.fetched_at = Some(now);
        Ok(())
    }

    /// Refetches the keys of every JWT issuer whose keys are missing or
    /// three quarters through their `jwks_max_age`, retrying a failure no
    /// more often than its `jwks_retry`. Run on a schedule, it renews keys
    /// before they expire, so a brief outage at renewal refuses nothing, and
    /// it notices an issuer that has come back. Issuers are refreshed at
    /// once, so one that doesn't answer delays no other. A failure is the
    /// fetcher's to report; keys it leaves expired refuse their tokens.
    pub async fn refresh_due(&self) {
        let refreshes = self
            .issuers
            .iter()
            .filter(|issuer| issuer.trusted.validation == Validation::Jwt)
            .map(|issuer| async move {
                let trusted = &issuer.trusted;
                let mut keys = issuer.keys.lock().await;
                let now = self.clock.now();
                let renew_at = trusted.jwks_max_age - trusted.jwks_max_age / 4;
                if !keys.fresh(now, renew_at) && keys.may_retry(now, trusted) {
                    let _ = self.refresh(issuer, &mut keys, now).await;
                }
            });
        futures_util::future::join_all(refreshes).await;
    }

    /// How long ago each JWT issuer's keys were fetched, by its `iss`:
    /// `None` for keys never fetched.
    pub async fn key_ages(&self) -> Vec<(String, Option<Duration>)> {
        let now = self.clock.now();
        let mut ages = Vec::new();
        for issuer in &self.issuers {
            if issuer.trusted.validation != Validation::Jwt {
                continue;
            }
            let fetched_at = issuer.keys.lock().await.fetched_at;
            ages.push((
                issuer.trusted.issuer.clone(),
                fetched_at.map(|fetched_at| age(now, fetched_at)),
            ));
        }
        ages
    }

    fn check_audience(
        &self,
        trusted: &TrustedIssuer,
        payload: &Map<String, Value>,
    ) -> Result<(), ValidateError> {
        let aud = payload
            .get("aud")
            .ok_or(ValidateError::MissingClaim("aud"))?;
        let auds = claims::strings(aud).ok_or(ValidateError::InvalidClaim("aud"))?;
        let matched = auds
            .iter()
            .any(|aud| trusted.audiences.iter().any(|a| a == aud));
        if matched {
            Ok(())
        } else {
            Err(ValidateError::Audience)
        }
    }

    fn check_times(&self, payload: &Map<String, Value>) -> Result<(), ValidateError> {
        let now = self.clock.unix_seconds();
        let exp = time_claim(payload, "exp")?.ok_or(ValidateError::MissingClaim("exp"))?;
        if now >= exp.saturating_add(self.skew) {
            return Err(ValidateError::Expired);
        }
        if let Some(nbf) = time_claim(payload, "nbf")?
            && now.saturating_add(self.skew) < nbf
        {
            return Err(ValidateError::NotYetValid);
        }
        Ok(())
    }
}

/// A JWT's header and its payload, read without verifying anything.
fn split(token: &str) -> Option<(jsonwebtoken::Header, Map<String, Value>)> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let mut parts = token.split('.');
    let payload = parts.nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let payload = serde_json::from_slice(&bytes).ok()?;
    Some((header, payload))
}

/// The header's algorithm, when the issuer allows it, with the JWK
/// algorithm a key for it declares.
fn allowed_algorithm(
    trusted: &TrustedIssuer,
    alg: Algorithm,
) -> Result<(Algorithm, KeyAlgorithm), ValidateError> {
    trusted
        .algorithms
        .iter()
        .map(|&allowed| algorithms(allowed))
        .find(|(algorithm, _)| *algorithm == alg)
        .ok_or_else(|| ValidateError::Algorithm(format!("{alg:?}")))
}

/// Checks the header's `typ` is one of the issuer's token types (RFC 8725
/// section 3.11). A token without one is refused unless the issuer sets
/// `require_token_type = false`.
fn check_type(trusted: &TrustedIssuer, typ: Option<&str>) -> Result<(), ValidateError> {
    let Some(typ) = typ else {
        return if trusted.require_token_type {
            Err(ValidateError::MissingType)
        } else {
            Ok(())
        };
    };
    if trusted
        .token_types
        .iter()
        .any(|accepted| accepted.matches(typ))
    {
        Ok(())
    } else {
        Err(ValidateError::TokenType)
    }
}

fn algorithms(allowed: InboundAlgorithm) -> (Algorithm, KeyAlgorithm) {
    match allowed {
        InboundAlgorithm::RS256 => (Algorithm::RS256, KeyAlgorithm::RS256),
        InboundAlgorithm::RS384 => (Algorithm::RS384, KeyAlgorithm::RS384),
        InboundAlgorithm::RS512 => (Algorithm::RS512, KeyAlgorithm::RS512),
        InboundAlgorithm::PS256 => (Algorithm::PS256, KeyAlgorithm::PS256),
        InboundAlgorithm::PS384 => (Algorithm::PS384, KeyAlgorithm::PS384),
        InboundAlgorithm::PS512 => (Algorithm::PS512, KeyAlgorithm::PS512),
        InboundAlgorithm::ES256 => (Algorithm::ES256, KeyAlgorithm::ES256),
        InboundAlgorithm::ES384 => (Algorithm::ES384, KeyAlgorithm::ES384),
        InboundAlgorithm::EdDSA => (Algorithm::EdDSA, KeyAlgorithm::EdDSA),
    }
}

/// When [`Validator::key`] refetches fresh keys.
#[derive(Clone, Copy)]
enum Refetch {
    /// Only when the key ID is unknown.
    IfUnknown,
    /// Whether or not the key ID is known.
    Now,
}

/// Checks that `jwk` may sign with the header's algorithm, then the
/// signature alone; the claims are checked against the config and the
/// injected clock.
fn verify(
    token: &str,
    jwk: &Jwk,
    (algorithm, key_algorithm): (Algorithm, KeyAlgorithm),
) -> Result<(), ValidateError> {
    if let Some(declared) = jwk.common.key_algorithm
        && declared != key_algorithm
    {
        return Err(ValidateError::Algorithm(format!("{algorithm:?}")));
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| ValidateError::Signature)?;
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
        .map(|_| ())
        .map_err(|_| ValidateError::Signature)
}

/// A NumericDate claim, in whole seconds.
fn time_claim(
    payload: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<u64>, ValidateError> {
    let Some(value) = payload.get(name) else {
        return Ok(None);
    };
    if let Some(seconds) = value.as_u64() {
        return Ok(Some(seconds));
    }
    match value.as_f64() {
        Some(seconds) if seconds.is_finite() && seconds >= 0.0 => Ok(Some(seconds as u64)),
        _ => Err(ValidateError::InvalidClaim(name)),
    }
}

/// Refuses a malformed scope claim, by RFC 6749 section 3.3. `scope` is a
/// string of scope tokens separated by spaces. `scp` is one too, or an
/// array, as Entra issues it, whose every item is a single scope token. A
/// scope token is one or more printable ASCII characters other than space,
/// `"` and `\`. An empty or all-space string is a token with no scopes; any
/// other whitespace is refused.
fn check_scopes(payload: &Map<String, Value>) -> Result<(), ValidateError> {
    let spaced = |text: &str| text.chars().all(|c| c == ' ' || is_scope_char(c));
    match payload.get("scope") {
        None => {}
        Some(Value::String(text)) if spaced(text) => {}
        Some(_) => return Err(ValidateError::InvalidClaim("scope")),
    }
    match payload.get("scp") {
        None => Ok(()),
        Some(Value::String(text)) if spaced(text) => Ok(()),
        Some(scp @ Value::Array(_))
            if claims::strings(scp)
                .is_some_and(|items| items.iter().copied().all(is_scope_token)) =>
        {
            Ok(())
        }
        Some(_) => Err(ValidateError::InvalidClaim("scp")),
    }
}
