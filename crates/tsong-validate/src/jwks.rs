//! Fetching an issuer's signing keys.

use std::future::Future;
use std::pin::Pin;

use jsonwebtoken::jwk::JwkSet;
use reqwest::Url;
use serde::Deserialize;
use tsong_config::TrustedIssuer;

/// What [`JwksFetcher::fetch`] returns.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<JwkSet, FetchError>> + Send + 'a>>;

/// A source of an issuer's JWKS.
pub trait JwksFetcher: Send + Sync {
    fn fetch<'a>(&'a self, issuer: &'a TrustedIssuer) -> FetchFuture<'a>;
}

/// Why a JWKS couldn't be fetched.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    #[error("discovery document: {0}")]
    Discovery(String),
}

/// Fetches JWKS over HTTP: from the configured `jwks_url`, or from the
/// `jwks_uri` in the issuer's OIDC discovery document, found at its
/// `discovery_url` or the well-known path. Each request takes no longer
/// than the issuer's `jwks_timeout`.
#[derive(Debug, Clone, Default)]
pub struct HttpFetcher {
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

impl HttpFetcher {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// The JWKS location the issuer's discovery document names. The
    /// document must name the same issuer, and a JWKS on the issuer's
    /// scheme.
    async fn discover(&self, trusted: &TrustedIssuer) -> Result<Url, FetchError> {
        let issuer = trusted.issuer.as_str();
        let url = match &trusted.discovery_url {
            Some(url) => url.clone(),
            None => Url::parse(&format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
            .map_err(|error| FetchError::Discovery(format!("url: {error}")))?,
        };
        let discovery: Discovery = self
            .client
            .get(url)
            .timeout(trusted.jwks_timeout)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if discovery.issuer != issuer {
            return Err(FetchError::Discovery(format!(
                "names issuer {:?}, not {issuer:?}",
                discovery.issuer
            )));
        }
        let jwks_uri = Url::parse(&discovery.jwks_uri)
            .map_err(|error| FetchError::Discovery(format!("jwks_uri: {error}")))?;
        let scheme = issuer.split_once(':').map(|(scheme, _)| scheme);
        if Some(jwks_uri.scheme()) != scheme {
            return Err(FetchError::Discovery(format!(
                "jwks_uri {jwks_uri} is not on the issuer's scheme"
            )));
        }
        Ok(jwks_uri)
    }
}

impl JwksFetcher for HttpFetcher {
    fn fetch<'a>(&'a self, issuer: &'a TrustedIssuer) -> FetchFuture<'a> {
        Box::pin(async move {
            let url = match &issuer.jwks_url {
                Some(url) => url.clone(),
                None => self.discover(issuer).await?,
            };
            Ok(self
                .client
                .get(url)
                .timeout(issuer.jwks_timeout)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?)
        })
    }
}
