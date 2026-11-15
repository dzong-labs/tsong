//! The RFC 8693 token exchange issuer.
//!
//! [`Issuer::exchange`] takes a subject token from a trusted issuer and an
//! audience, and returns a token Tsong signs for the route with that
//! audience. The policy is the routes' own: the subject token's issuer must
//! be trusted on a route with the requested audience, the token must carry
//! the route's required scopes, and the scopes granted are the route's.
//! [`router`] serves the token endpoint, the JWKS and the discovery
//! document over HTTP.

mod error;
mod http;
mod mint;

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tsong_clock::Clock;
use tsong_config::{Config, Route};
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
        let route = self.route(audience, validated.issuer())?;
        check_required_scopes(route, &validated)?;
        let granted = granted_scopes(route, request.scope.as_deref())?;
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
        claims.insert("aud".into(), json!(audiences(route)));
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

    /// The first route, in config order, with `audience` that trusts
    /// `issuer`.
    fn route(&self, audience: &str, issuer: &str) -> Result<&Route, ExchangeError> {
        let mut routes = self
            .config
            .routes
            .iter()
            .filter(|route| route.audience == audience)
            .peekable();
        if routes.peek().is_none() {
            return Err(ExchangeError::InvalidTarget(format!(
                "no route has audience {audience:?}"
            )));
        }
        routes
            .find(|route| route.trusted_issuers.iter().any(|name| name == issuer))
            .ok_or_else(|| {
                ExchangeError::InvalidTarget(format!(
                    "issuer {issuer:?} may not exchange for audience {audience:?}"
                ))
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

fn check_required_scopes(route: &Route, validated: &Validated) -> Result<(), ExchangeError> {
    let held = scopes(validated.claims());
    match route
        .required_scopes
        .iter()
        .find(|scope| !held.contains(scope.as_str()))
    {
        Some(missing) => Err(ExchangeError::InvalidGrant(format!(
            "the subject token lacks scope {missing:?}"
        ))),
        None => Ok(()),
    }
}

/// The scopes requested, when the route allows them all, or the route's
/// scopes when none are requested.
fn granted_scopes(route: &Route, requested: Option<&str>) -> Result<Vec<String>, ExchangeError> {
    let Some(requested) = requested else {
        return Ok(route.scopes.clone());
    };
    let requested: BTreeSet<&str> = requested.split_whitespace().collect();
    if let Some(refused) = requested
        .iter()
        .find(|scope| !route.scopes.iter().any(|allowed| allowed == *scope))
    {
        return Err(ExchangeError::InvalidScope(format!(
            "scope {refused:?} is not allowed for audience {:?}",
            route.audience
        )));
    }
    Ok(requested.into_iter().map(str::to_owned).collect())
}

/// The route's audience and its downstream's host.
fn audiences(route: &Route) -> Vec<&str> {
    let mut audiences = vec![route.audience.as_str()];
    if let Some(host) = route.downstream.host_str()
        && host != route.audience
    {
        audiences.push(host);
    }
    audiences
}
