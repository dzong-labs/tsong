//! Tsong's configuration: the issuer, the gateway, the trusted inbound
//! issuers, claim mapping and routes.
//!
//! [`Config::from_toml`] parses a document and validates it as a whole, so
//! a config either loads with every reference resolved or fails with every
//! problem listed. Unknown fields are errors: a misspelled security setting
//! must not fall back to its default.

mod bootstrap;
mod duration;
mod lint;
mod network;
mod store;
mod validate;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

pub use bootstrap::{
    Admin, Bootstrap, BootstrapError, CONFIG_FILE, GitHost, GitSource, Source, Webhook,
};
pub use lint::Warnings;
pub use network::{allowed, client_ip};
pub use store::{ConfigStore, Fetched, FileStore, LoadFuture, Snapshot, hex};
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
    /// Client ranges allowed through. Empty denies every client;
    /// `["0.0.0.0/0", "::/0"]` allows every client.
    pub allow: Vec<IpNet>,
    /// The longest the gateway waits on a downstream between reads, before
    /// answering 504. A route may set its own.
    #[serde(default = "default_read_timeout", with = "duration")]
    pub read_timeout: Duration,
    pub cache: Cache,
}

fn default_read_timeout() -> Duration {
    Duration::from_secs(60)
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

/// A host mapped to a downstream service. The upstream is the caller; the
/// downstream is where the request goes.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    /// The host requests for this route arrive on, without a port.
    /// Compared without regard to case.
    pub host: String,
    /// The https origin requests are forwarded to. The request's path and
    /// query are kept.
    pub downstream: Url,
    /// Added to the `aud` of tokens minted for this route. Empty adds
    /// nothing.
    pub append_audience: String,
    /// The inbound `aud` values the route accepts: the inbound token must
    /// carry one. Empty denies every token; `"*"` accepts any.
    pub allowed_audiences: Vec<String>,
    /// The inbound scopes the route accepts: every scope the inbound token
    /// carries must be one. Empty denies every token; `"*"` accepts any.
    pub allowed_scopes: Vec<String>,
    /// Client ranges allowed to this route, checked after the gateway's
    /// `allow`. Unset, the gateway's list alone applies. Empty denies
    /// every client.
    pub allow: Option<Vec<IpNet>>,
    /// Overrides `gateway.read_timeout` for this route.
    #[serde(default, with = "duration::option")]
    pub read_timeout: Option<Duration>,
}

impl Route {
    /// The longest the gateway waits on this route's downstream between
    /// reads.
    pub fn read_timeout(&self, gateway: &Gateway) -> Duration {
        self.read_timeout.unwrap_or(gateway.read_timeout)
    }
}

/// The entry in `allowed_audiences` or `allowed_scopes` that accepts any
/// value.
pub const ANY: &str = "*";

impl Route {
    /// Whether the route accepts a token with these audiences.
    pub fn accepts_audiences<'a>(&self, mut audiences: impl Iterator<Item = &'a str>) -> bool {
        let allowed = &self.allowed_audiences;
        allowed.iter().any(|value| value == ANY)
            || audiences.any(|aud| allowed.iter().any(|value| value == aud))
    }

    /// The first of these scopes the route doesn't accept. An empty
    /// `allowed_scopes` accepts nothing, so even a token without scopes is
    /// refused, reported as `None` in `Err`.
    pub fn refused_scope<'a>(
        &self,
        mut scopes: impl Iterator<Item = &'a str>,
    ) -> Result<(), Option<&'a str>> {
        let allowed = &self.allowed_scopes;
        if allowed.is_empty() {
            return Err(None);
        }
        if allowed.iter().any(|value| value == ANY) {
            return Ok(());
        }
        match scopes.find(|scope| !allowed.iter().any(|value| value == scope)) {
            Some(refused) => Err(Some(refused)),
            None => Ok(()),
        }
    }
}

/// The routes keyed by host, for lookup in constant time.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: HashMap<String, Route>,
}

impl RouteTable {
    /// Indexes `routes` by lowercased host. A validated config has no
    /// repeated host; were one repeated, the first route would win.
    pub fn new(routes: &[Route]) -> Self {
        let mut table = HashMap::with_capacity(routes.len());
        for route in routes {
            table
                .entry(route.host.to_ascii_lowercase())
                .or_insert_with(|| route.clone());
        }
        Self { routes: table }
    }

    /// The route for `host`, compared without regard to case. The host
    /// carries no port.
    pub fn get(&self, host: &str) -> Option<&Route> {
        self.routes.get(&host.to_ascii_lowercase())
    }
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
    /// The store couldn't produce the config, such as a failed fetch.
    #[error("{0}")]
    Store(String),
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
        Self::from_text(&store::read(path)?, Some(&store::directory(path)))
    }

    /// Parses and validates a TOML document, taking relative key paths from
    /// `base_dir`. Without one, as for a config from Git, a relative key
    /// path is a problem: it has nothing to be relative to.
    pub fn from_text(text: &str, base_dir: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = Self::from_toml(text)?;
        let mut problems = Vec::new();
        for key in &mut config.issuer.signing.keys {
            let Some(key_path) = &mut key.path else {
                continue;
            };
            match base_dir {
                Some(dir) => *key_path = dir.join(&*key_path),
                None if key_path.is_relative() => problems.push(format!(
                    "issuer.signing.keys {:?} path must be absolute, since the config has no directory",
                    key.kid
                )),
                None => {}
            }
        }
        if problems.is_empty() {
            Ok(config)
        } else {
            Err(ConfigError::Invalid(Problems(problems)))
        }
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
