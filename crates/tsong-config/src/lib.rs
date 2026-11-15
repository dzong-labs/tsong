//! Tsong's configuration: the issuer, the gateway, the trusted inbound
//! issuers, claim mapping and routes.
//!
//! [`Config::from_toml`] parses a document and validates it as a whole, so
//! a config either loads with every reference resolved or fails with every
//! problem listed. Unknown fields are errors: a misspelled security setting
//! must not fall back to its default.

mod duration;
mod store;
mod validate;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

pub use store::{ConfigStore, FileStore, LoadFuture};
pub use validate::{Problems, RESERVED_CLAIMS};

/// A whole Tsong configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: Issuer,
    pub gateway: Gateway,
    #[serde(default)]
    pub trusted_issuers: BTreeMap<String, TrustedIssuer>,
    #[serde(default)]
    pub claims: Claims,
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// The token exchange issuer Tsong hosts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// The `iss` of every token Tsong signs, exactly as written, and the
    /// base of its discovery document. An https URL.
    pub url: String,
    /// Where the issuer serves the token endpoint, JWKS and discovery.
    pub listen: SocketAddr,
    /// The longest lifetime of a token Tsong signs.
    #[serde(with = "duration")]
    pub token_lifetime: Duration,
    /// Allowance for clocks that disagree: added to inbound `exp` and taken
    /// off inbound `nbf`, and taken off every cache lifetime.
    #[serde(with = "duration")]
    pub clock_skew: Duration,
    pub signing: Signing,
}

/// Where the issuer's signing keys come from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub provider: KeyProvider,
    pub algorithm: SigningAlgorithm,
    pub keys: Vec<KeyEntry>,
}

/// A source of signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProvider {
    /// PKCS#8 PEM files on disk.
    File,
}

/// An algorithm Tsong signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum SigningAlgorithm {
    ES256,
}

/// One signing key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub kid: String,
    pub state: KeyState,
    /// The key's file, for the file provider.
    pub path: Option<PathBuf>,
}

/// Whether a key signs, or is only published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyState {
    /// Signs new tokens. Exactly one key is active.
    Active,
    /// Published in JWKS until the tokens it signed expire; never signs.
    Retiring,
}

/// The reverse proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub listen: SocketAddr,
    /// Proxies whose `X-Forwarded-For` hops are believed.
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Client ranges allowed through. Empty allows every client.
    #[serde(default)]
    pub allow: Vec<IpNet>,
    pub cache: Cache,
}

/// The exchanged-token cache.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub max_entries: u64,
}

/// An issuer whose tokens Tsong accepts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    /// The `iss` its tokens carry, compared exactly. An https URL.
    pub issuer: String,
    /// The `aud` values Tsong accepts from it.
    pub audiences: Vec<String>,
    #[serde(default)]
    pub validation: Validation,
    /// The algorithms its JWTs may be signed with.
    #[serde(default)]
    pub algorithms: Vec<InboundAlgorithm>,
    /// Where its JWKS is. Unset, it is found through the issuer's OIDC
    /// discovery document.
    pub jwks_url: Option<Url>,
    /// The shortest time between JWKS fetches. A token with an unknown key
    /// ID refetches the JWKS, but no sooner than this.
    #[serde(default = "default_jwks_refetch", with = "duration")]
    pub jwks_refetch: Duration,
    pub introspection_url: Option<Url>,
    pub client_id: Option<String>,
    /// The environment variable holding the introspection client secret.
    pub client_secret_env: Option<String>,
}

fn default_jwks_refetch() -> Duration {
    Duration::from_secs(30)
}

/// How an inbound token is validated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Validation {
    /// Locally, against the issuer's JWKS.
    #[default]
    Jwt,
    /// By asking the issuer (RFC 7662), for opaque tokens.
    Introspection,
}

/// An algorithm an inbound JWT may be signed with. Asymmetric only: `none`
/// and the HMAC algorithms don't parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum InboundAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

/// Which inbound claims carry over into exchanged tokens.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Claims copied from every issuer.
    #[serde(default)]
    pub copy: Vec<String>,
    /// Per trusted issuer, inbound claim name to outbound claim name.
    #[serde(default)]
    pub rename: BTreeMap<String, BTreeMap<String, String>>,
}

/// A path or host mapped to a downstream service. The upstream is the
/// caller; the downstream is where the request goes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: Match,
    pub downstream: Url,
    /// Names from `trusted_issuers` whose tokens this route exchanges.
    pub trusted_issuers: Vec<String>,
    /// The `aud` of the tokens exchanged for this route. The downstream's
    /// host is added as a second audience.
    pub audience: String,
    /// The scopes exchanged tokens may carry.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The scopes an inbound token must carry to be exchanged.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Narrows the gateway's allow list for this route.
    #[serde(default)]
    pub allow: Vec<IpNet>,
}

/// What a request must match to take a route. At least one is set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub host: Option<String>,
    pub path_prefix: Option<String>,
}

/// Why a config didn't load.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config:\n{0}")]
    Invalid(Problems),
}

impl Config {
    /// Parses and validates a TOML document.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate().map_err(ConfigError::Invalid)?;
        Ok(config)
    }

    /// Reads, parses and validates a TOML file. Relative key paths are
    /// taken from the file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut config = Self::from_toml(&text)?;
        let dir = path.parent().unwrap_or(Path::new(""));
        for key in &mut config.issuer.signing.keys {
            if let Some(key_path) = &mut key.path {
                *key_path = dir.join(&*key_path);
            }
        }
        Ok(config)
    }

    /// The active signing key: always one, in a validated config.
    pub fn active_key(&self) -> Option<&KeyEntry> {
        self.issuer
            .signing
            .keys
            .iter()
            .find(|key| key.state == KeyState::Active)
    }
}
