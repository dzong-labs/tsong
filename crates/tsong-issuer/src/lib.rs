//! The RFC 8693 token exchange issuer.
//!
//! [`Issuer::exchange`] takes a subject token from any trusted issuer and
//! an audience naming a route's host, and returns a token Tsong signs for
//! that route. The route filters the subject token's audiences, then its
//! scopes: the token must carry at least one value the route allows, none
//! outside them, every value the route requires and none it denies. The
//! minted token keeps the subject token's audiences and scopes, narrowed
//! to the requested scopes but always keeping the required ones, and adds
//! the route's `append_audience`. Its `sub` is the trusted issuer's
//! `sub_prefix`, a `:`, and the subject, and its RFC 9493 `sub_id` keeps the
//! subject token's own `iss` and `sub`. [`router`] serves the token
//! endpoint, the JWKS and the discovery document over HTTP.

mod context;
mod error;
mod http;
mod mint;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tsong_clock::Clock;
use tsong_config::{
    Config, Policy, PolicyKind, RESERVED_CLAIMS, Refusal, Route, RouteTable, allowed, client_ip,
};
use tsong_keys::KeySet;
use tsong_validate::{Validated, Validator, scopes};

pub use context::{
    ExchangeContext, ExchangeEvent, ExchangeObserver, REQUEST_ID, TRACEPARENT, request_id_is_valid,
    trace_id,
};
pub use error::ExchangeError;
pub use http::router;

/// The token exchange grant type.
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The token type of an OAuth access token.
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// The token type of a JWT.
pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// A token exchange request, as RFC 8693 section 2.1 defines it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub requested_token_type: Option<String>,
    pub resource: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
}

/// A successful exchange, as RFC 8693 section 2.2.1 defines it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// The token exchange issuer for one config.
pub struct Issuer {
    config: Arc<Config>,
    routes: RouteTable,
    keys: KeySet,
    validator: Validator,
    clock: Arc<dyn Clock>,
    observer: Option<Arc<dyn ExchangeObserver>>,
}

/// What an exchange learned before it finished, for its event.
#[derive(Default)]
struct Seen {
    trusted_issuer: Option<String>,
    iss: Option<String>,
    sub: Option<String>,
    scope: Option<String>,
}

impl Issuer {
    pub fn new(
        config: Arc<Config>,
        keys: KeySet,
        validator: Validator,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            routes: RouteTable::new(&config.routes),
            config,
            keys,
            validator,
            clock,
            observer: None,
        }
    }

    /// The validator subject tokens are checked by.
    pub fn validator(&self) -> &Validator {
        &self.validator
    }

    /// This issuer, reporting every exchange to `observer`.
    pub fn with_observer(mut self, observer: Arc<dyn ExchangeObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Exchanges a subject token for a token Tsong signs.
    pub async fn exchange(&self, request: TokenRequest) -> Result<TokenResponse, ExchangeError> {
        self.exchange_with(request, &ExchangeContext::default())
            .await
    }

    /// Exchanges a subject token for a token Tsong signs, reporting the
    /// exchange, in `context`, to the observer.
    pub async fn exchange_with(
        &self,
        request: TokenRequest,
        context: &ExchangeContext,
    ) -> Result<TokenResponse, ExchangeError> {
        let started = Instant::now();
        let mut seen = Seen::default();
        let result = self.run(&request, &mut seen).await;
        if let Some(observer) = &self.observer {
            observer.exchanged(&ExchangeEvent {
                context: context.clone(),
                audience: request.audience.clone(),
                trusted_issuer: seen.trusted_issuer,
                iss: seen.iss,
                sub: seen.sub,
                scope: seen.scope,
                error: result.as_ref().err().map(ExchangeError::code),
                error_description: result.as_ref().err().map(ToString::to_string),
                duration: started.elapsed(),
            });
        }
        result
    }

    async fn run(
        &self,
        request: &TokenRequest,
        seen: &mut Seen,
    ) -> Result<TokenResponse, ExchangeError> {
        let (subject_token, audience) = check_request(request)?;
        let validated = self.validator.validate(subject_token).await?;
        seen.trusted_issuer = Some(validated.issuer().to_owned());
        let claim = |name: &str| {
            validated
                .claims()
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        seen.iss = claim("iss");
        seen.sub = claim("sub");
        let route = self.routes.get(audience).ok_or_else(|| {
            ExchangeError::InvalidTarget(format!("no route has host {audience:?}"))
        })?;
        let inbound_audiences = audiences(validated.claims())?;
        if let Some(refusal) = route.audiences.refusal(&inbound_audiences) {
            return Err(refused(refusal, PolicyKind::Audiences, audience));
        }
        let granted = granted_scopes(
            &route.scopes,
            audience,
            &validated,
            request.scope.as_deref(),
        )?;
        let original_sub = validated
            .subject()
            .filter(|sub| !sub.is_empty())
            .ok_or_else(|| ExchangeError::InvalidRequest("the subject token has no sub".into()))?;
        let trusted = self
            .config
            .trusted_issuers
            .get(validated.issuer())
            .ok_or_else(|| {
                ExchangeError::Server(format!(
                    "trusted issuer {:?} is not configured",
                    validated.issuer()
                ))
            })?;
        let subject = self.subject(&validated, original_sub)?;

        let now = self.clock.unix_seconds();
        let lifetime = self.config.issuer.token_lifetime.as_secs();
        let exp = validated
            .expires_at()
            .unwrap_or(0)
            .min(now.saturating_add(lifetime));
        if exp <= now {
            return Err(ExchangeError::InvalidRequest(
                "the subject token has expired".into(),
            ));
        }

        let mut claims = self.mapped_claims(&validated);
        claims.insert(
            "sub".into(),
            json!(format!("{}:{subject}", trusted.sub_prefix)),
        );
        claims.insert(
            "sub_id".into(),
            json!({ "format": "iss_sub", "iss": trusted.issuer, "sub": original_sub }),
        );
        claims.insert("iss".into(), json!(self.config.issuer.url));
        claims.insert(
            "aud".into(),
            json!(minted_audiences(inbound_audiences, route)),
        );
        claims.insert("iat".into(), json!(now));
        claims.insert("exp".into(), json!(exp));
        claims.insert("jti".into(), json!(mint::jti()?));
        let scope = (!granted.is_empty()).then(|| granted.join(" "));
        if let Some(scope) = &scope {
            claims.insert("scope".into(), json!(scope));
        }

        let key = self.keys.active(route.signing_algorithm).ok_or_else(|| {
            ExchangeError::Server(format!(
                "no active key signs {}, which route {:?} uses",
                route.signing_algorithm, route.name
            ))
        })?;
        let access_token = mint::sign(key, &claims).await?;
        seen.scope.clone_from(&scope);
        Ok(TokenResponse {
            access_token,
            issued_token_type: ACCESS_TOKEN.into(),
            token_type: "Bearer".into(),
            expires_in: exp - now,
            scope,
        })
    }

    /// The inbound claims the config carries over: copied by name, then
    /// renamed for the token's issuer. Reserved claims never carry over;
    /// config validation refuses mappings that would write them.
    fn mapped_claims(&self, validated: &Validated) -> serde_json::Map<String, Value> {
        let inbound = validated.claims();
        let mut claims = serde_json::Map::new();
        for name in &self.config.claims.copy {
            if let Some(value) = inbound.get(name) {
                claims.insert(name.clone(), value.clone());
            }
        }
        if let Some(renames) = self.config.claims.rename.get(validated.issuer()) {
            for (from, to) in renames {
                if to != "sub"
                    && let Some(value) = inbound.get(from)
                {
                    claims.insert(to.clone(), value.clone());
                }
            }
        }
        // Config validation refuses mappings onto reserved claims, so none
        // can be here to overwrite the claims Tsong sets.
        debug_assert!(
            claims
                .keys()
                .all(|name| !RESERVED_CLAIMS.contains(&name.as_str()))
        );
        claims
    }

    /// The subject the minted `sub` is made from: the claim a rename maps to
    /// `sub`, such as Entra's `oid`, or else `original_sub`. A token without
    /// the renamed claim as a non-empty string is refused rather than falling
    /// back, so one prefix never mixes two kinds of identifier.
    fn subject<'a>(
        &self,
        validated: &'a Validated,
        original_sub: &'a str,
    ) -> Result<&'a str, ExchangeError> {
        let renamed = self
            .config
            .claims
            .rename
            .get(validated.issuer())
            .and_then(|renames| renames.iter().find(|(_, to)| *to == "sub"));
        match renamed {
            None => Ok(original_sub),
            Some((from, _)) => validated
                .claims()
                .get(from)
                .and_then(Value::as_str)
                .filter(|subject| !subject.is_empty())
                .ok_or_else(|| {
                    ExchangeError::InvalidRequest(format!(
                        "the subject token has no {from}, which supplies its subject"
                    ))
                }),
        }
    }

    /// Whether a token request from the connection's `peer`, with these
    /// `X-Forwarded-For` values, may exchange for `audience`. The client
    /// must be in `gateway.allow` and, when the audience names a route with
    /// its own `allow`, in that list too: the token endpoint admits exactly
    /// the clients the gateway admits.
    pub fn admits<'a>(
        &self,
        peer: IpAddr,
        forwarded_for: impl DoubleEndedIterator<Item = &'a [u8]>,
        audience: Option<&str>,
    ) -> Result<(), ExchangeError> {
        let gateway = &self.config.gateway;
        let client = client_ip(peer, forwarded_for, &gateway.trusted_proxies)
            .ok_or_else(|| ExchangeError::InvalidRequest("malformed X-Forwarded-For".into()))?;
        let route = audience.and_then(|audience| self.routes.get(audience));
        if allowed(
            client,
            &gateway.allow,
            route.and_then(|route| route.allow.as_deref()),
        ) {
            Ok(())
        } else {
            Err(ExchangeError::AccessDenied)
        }
    }

    /// The OIDC discovery document.
    pub fn discovery(&self) -> Value {
        let url = &self.config.issuer.url;
        let base = url.trim_end_matches('/');
        json!({
            "issuer": url,
            "jwks_uri": format!("{base}/jwks.json"),
            "token_endpoint": format!("{base}/token"),
            "grant_types_supported": [TOKEN_EXCHANGE],
        })
    }

    /// The JWKS downstream services validate Tsong's tokens with.
    pub fn jwks(&self) -> Value {
        self.keys.jwks()
    }
}

/// Checks the request's shape, returning the subject token and audience.
fn check_request(request: &TokenRequest) -> Result<(&str, &str), ExchangeError> {
    if request.grant_type.as_deref() != Some(TOKEN_EXCHANGE) {
        return Err(ExchangeError::UnsupportedGrantType);
    }
    let invalid = |message: &str| Err(ExchangeError::InvalidRequest(message.into()));
    if request.actor_token.is_some() || request.actor_token_type.is_some() {
        return invalid("actor tokens are not supported yet");
    }
    if request.resource.is_some() {
        return invalid("resource is not supported; name the audience");
    }
    let Some(subject_token) = request.subject_token.as_deref() else {
        return invalid("subject_token is required");
    };
    match request.subject_token_type.as_deref() {
        Some(ACCESS_TOKEN | JWT) => {}
        Some(_) => return invalid("subject_token_type must be an access token or a JWT"),
        None => return invalid("subject_token_type is required"),
    }
    if !matches!(
        request.requested_token_type.as_deref(),
        None | Some(ACCESS_TOKEN | JWT)
    ) {
        return invalid("requested_token_type must be an access token or a JWT");
    }
    let Some(audience) = request.audience.as_deref() else {
        return invalid("audience is required");
    };
    Ok((subject_token, audience))
}

/// The subject token's `aud`: a string or an array of strings. Any other
/// `aud` refuses the exchange, so no audience escapes the route's checks.
fn audiences(claims: &serde_json::Map<String, Value>) -> Result<Vec<&str>, ExchangeError> {
    match claims.get("aud") {
        None => Ok(Vec::new()),
        Some(Value::String(aud)) => Ok(vec![aud.as_str()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    ExchangeError::InvalidRequest(format!(
                        "the subject token's audience {item} is not a string"
                    ))
                })
            })
            .collect(),
        Some(aud) => Err(ExchangeError::InvalidRequest(format!(
            "the subject token's aud {aud} is not a string or an array of strings"
        ))),
    }
}

/// The OAuth error a refusal by a route's `kind` of policy is reported as.
fn refusal_error(kind: PolicyKind, reason: String) -> ExchangeError {
    match kind {
        PolicyKind::Audiences => ExchangeError::InvalidTarget(reason),
        PolicyKind::Scopes => ExchangeError::InvalidScope(reason),
    }
}

/// Why the route for `target` refused the subject token's audiences or
/// scopes.
fn refused(refusal: Refusal<'_>, kind: PolicyKind, target: &str) -> ExchangeError {
    let (one, many) = (kind.noun(), kind.key());
    let reason = match refusal {
        Refusal::NotAllowed => {
            format!("none of the subject token's {many} is allowed for {target:?}")
        }
        Refusal::NoValue => {
            format!("the subject token has no {one}, and {target:?} requires one")
        }
        Refusal::Outside(value) => format!(
            "the subject token's {one} {value:?} is outside the {many} allowed for {target:?}"
        ),
        Refusal::Missing(value) => {
            format!("the subject token lacks {one} {value:?}, which {target:?} requires")
        }
        Refusal::Denied(value) => {
            format!("the subject token's {one} {value:?} is denied for {target:?}")
        }
    };
    refusal_error(kind, reason)
}

/// The subject token's scopes, once the scope `policy` of the route for
/// `target` accepts them, narrowed to the scopes requested when there is a
/// request.
fn granted_scopes(
    policy: &Policy,
    target: &str,
    validated: &Validated,
    requested: Option<&str>,
) -> Result<Vec<String>, ExchangeError> {
    // Sorted and without repeats, as `scopes` collects them into a set.
    let held: Vec<&str> = scopes(validated.claims()).into_iter().collect();
    // An `scp` array item is one scope. Empty, or holding whitespace, it
    // would turn into no scope or several in the minted `scope` string.
    if let Some(malformed) = held
        .iter()
        .find(|scope| scope.is_empty() || scope.contains(char::is_whitespace))
    {
        return Err(ExchangeError::InvalidRequest(format!(
            "the subject token's scope {malformed:?} is not a single scope"
        )));
    }
    if let Some(refusal) = policy.refusal(&held) {
        return Err(refused(refusal, PolicyKind::Scopes, target));
    }
    let granted: Vec<String> = match requested {
        // `refusal` proved the subject token holds every required scope,
        // and every one it holds is granted.
        None => held.iter().map(|scope| (*scope).to_owned()).collect(),
        Some(requested) => {
            let mut narrowed: Vec<&str> = Vec::new();
            for scope in requested.split_whitespace() {
                if held.binary_search(&scope).is_err() {
                    return Err(ExchangeError::InvalidScope(format!(
                        "the subject token lacks scope {scope:?}"
                    )));
                }
                if !narrowed.contains(&scope) {
                    narrowed.push(scope);
                }
            }
            // The minted token keeps every scope the route requires. The
            // subject token holds them all, so only the request can drop
            // one.
            if let Some(dropped) = policy
                .require
                .iter()
                .find(|required| !narrowed.contains(&required.as_str()))
            {
                return Err(ExchangeError::InvalidScope(format!(
                    "the requested scope drops {dropped:?}, which {target:?} requires"
                )));
            }
            narrowed.sort_unstable();
            narrowed.into_iter().map(str::to_owned).collect()
        }
    };
    // A minted token holds only scopes the subject token held and the
    // route accepts, and every scope the route requires.
    debug_assert!(
        granted
            .iter()
            .all(|scope| { held.binary_search(&scope.as_str()).is_ok() && policy.admits(scope) })
    );
    debug_assert!(
        policy
            .require
            .iter()
            .all(|required| granted.contains(required))
    );
    Ok(granted)
}

/// The subject token's audiences, then the route's `append_audience` when
/// it is set, without repeats.
fn minted_audiences<'a>(inbound: Vec<&'a str>, route: &'a Route) -> Vec<&'a str> {
    let mut minted: Vec<&str> = Vec::with_capacity(inbound.len() + 1);
    let appended = (!route.append_audience.is_empty()).then_some(route.append_audience.as_str());
    for aud in inbound.into_iter().chain(appended) {
        if !minted.contains(&aud) {
            minted.push(aud);
        }
    }
    debug_assert!(
        minted
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == minted.len()
    );
    minted
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The error `audiences` reports for a token whose `aud` is `aud`, or
    /// a test failure when it reports none.
    fn refused(aud: Value) -> Result<String, Box<dyn std::error::Error>> {
        let Value::Object(claims) = json!({ "aud": aud }) else {
            return Err("claims are an object".into());
        };
        match audiences(&claims) {
            Err(error @ ExchangeError::InvalidRequest(_)) => Ok(error.to_string()),
            other => Err(format!("expected an invalid request, got {other:?}").into()),
        }
    }

    // The validator refuses such tokens first; this holds wherever else
    // the claims come from.
    #[test]
    fn an_aud_that_is_not_strings_refuses_the_exchange() -> TestResult {
        assert_eq!(
            refused(json!(["api", 1]))?,
            "the subject token's audience 1 is not a string"
        );
        assert_eq!(
            refused(json!(["api", null]))?,
            "the subject token's audience null is not a string"
        );
        assert_eq!(
            refused(json!({ "api": true }))?,
            r#"the subject token's aud {"api":true} is not a string or an array of strings"#
        );
        Ok(())
    }

    #[test]
    fn an_aud_is_a_string_an_array_of_strings_or_absent() -> TestResult {
        let Value::Object(claims) = json!({ "aud": ["api", "other"] }) else {
            return Err("claims are an object".into());
        };
        assert_eq!(audiences(&claims)?, ["api", "other"]);
        let Value::Object(claims) = json!({ "aud": "api" }) else {
            return Err("claims are an object".into());
        };
        assert_eq!(audiences(&claims)?, ["api"]);
        assert!(audiences(&serde_json::Map::new())?.is_empty());
        Ok(())
    }
}
