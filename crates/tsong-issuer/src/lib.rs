//! The RFC 8693 token exchange issuer.
//!
//! [`Issuer::exchange`] takes a subject token from any trusted issuer and
//! an audience naming a route's host, and returns a token Tsong signs for
//! that route. The route filters the subject token: it must carry one of the
//! route's allowed audiences, and only scopes the route allows. The minted
//! token keeps the subject token's audiences and scopes, and adds the
//! route's `append_audience`. [`router`] serves the token endpoint, the JWKS
//! and the discovery document over HTTP.

mod error;
mod http;
mod mint;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tsong_clock::Clock;
use tsong_config::{Config, Route, RouteTable};
use tsong_keys::KeySet;
use tsong_validate::{Validated, Validator, scopes};

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
        }
    }

    /// Exchanges a subject token for a token Tsong signs.
    pub async fn exchange(&self, request: TokenRequest) -> Result<TokenResponse, ExchangeError> {
        let (subject_token, audience) = check_request(&request)?;
        let validated = self.validator.validate(subject_token).await?;
        let route = self.routes.get(audience).ok_or_else(|| {
            ExchangeError::InvalidTarget(format!("no route has host {audience:?}"))
        })?;
        let inbound_audiences = audiences(&validated);
        if !route.accepts_audiences(inbound_audiences.iter().copied()) {
            return Err(ExchangeError::InvalidTarget(format!(
                "the subject token's audience is not allowed for {audience:?}"
            )));
        }
        let granted = granted_scopes(route, &validated, request.scope.as_deref())?;
        let subject = self
            .renamed_sub(&validated)
            .or_else(|| validated.subject())
            .ok_or_else(|| ExchangeError::InvalidGrant("the subject token has no sub".into()))?
            .to_owned();

        let now = self.clock.unix_seconds();
        let lifetime = self.config.issuer.token_lifetime.as_secs();
        let exp = validated
            .expires_at()
            .unwrap_or(0)
            .min(now.saturating_add(lifetime));
        if exp <= now {
            return Err(ExchangeError::InvalidGrant(
                "the subject token has expired".into(),
            ));
        }

        let mut claims = self.mapped_claims(&validated);
        claims.insert("sub".into(), json!(subject));
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

        let access_token = mint::sign(self.keys.active(), &claims).await?;
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
        claims
    }

    /// The `sub` a rename gives the token, such as Entra's `oid`, when the
    /// inbound token has that claim as a string.
    fn renamed_sub<'a>(&self, validated: &'a Validated) -> Option<&'a str> {
        let renames = self.config.claims.rename.get(validated.issuer())?;
        let (from, _) = renames.iter().find(|(_, to)| *to == "sub")?;
        validated.claims().get(from)?.as_str()
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

/// The subject token's `aud`: a string or an array of strings.
fn audiences(validated: &Validated) -> Vec<&str> {
    match validated.claims().get("aud") {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// The subject token's scopes, once the route allows them all, narrowed to
/// the scopes requested when there is a request.
fn granted_scopes(
    route: &Route,
    validated: &Validated,
    requested: Option<&str>,
) -> Result<Vec<String>, ExchangeError> {
    let held = scopes(validated.claims());
    match route.refused_scope(held.iter().copied()) {
        Ok(()) => {}
        Err(None) => {
            return Err(ExchangeError::InvalidScope(format!(
                "route {:?} allows no scopes",
                route.name
            )));
        }
        Err(Some(refused)) => {
            return Err(ExchangeError::InvalidScope(format!(
                "scope {refused:?} is not allowed for route {:?}",
                route.name
            )));
        }
    }
    let Some(requested) = requested else {
        return Ok(held.into_iter().map(str::to_owned).collect());
    };
    let mut granted = Vec::new();
    for scope in requested.split_whitespace() {
        if !held.contains(scope) {
            return Err(ExchangeError::InvalidScope(format!(
                "the subject token lacks scope {scope:?}"
            )));
        }
        if !granted.iter().any(|kept| kept == scope) {
            granted.push(scope.to_owned());
        }
    }
    granted.sort();
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
    minted
}
