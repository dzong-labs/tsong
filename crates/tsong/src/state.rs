//! The runtime state one config produces, and the routers that always
//! serve the current state.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::response::IntoResponse;
use tokio::sync::watch;
use tower::ServiceExt;
use tsong_clock::Clock;
use tsong_config::{Config, Snapshot};
use tsong_gateway::Gateway;
use tsong_issuer::Issuer;
use tsong_keys::KeySet;
use tsong_secrets::Secrets;
use tsong_validate::{HttpFetcher, JwksFetcher, Validator};

use crate::Error;
use crate::reload::{Audit, Lines};
use crate::telemetry::{ExchangeAudit, Metrics, REFRESH_TICK, Refresher};

/// Everything built from one config: its signing keys, JWKS cache, route
/// table, exchange cache and downstream clients, behind the issuer's and
/// the gateway's routers. A reload builds a new one, so nothing carries
/// over from the old config.
pub struct State {
    pub revision: String,
    /// The config's content ID: a reload whose content matches changes
    /// nothing.
    pub content: String,
    pub author: Option<String>,
    pub config: Arc<Config>,
    pub issuer: Router,
    pub gateway: Router,
    /// Keeps the trusted issuers' keys current while this state lives;
    /// `None` for a state built without one.
    _refresher: Option<Refresher>,
}

impl State {
    /// Builds the state for `snapshot`, loading its signing keys, with
    /// metrics of its own, no exchange audit, and no background key
    /// refresh: keys are fetched over HTTP when a token needs them.
    pub async fn build(snapshot: Snapshot, clock: Arc<dyn Clock>) -> Result<Self, Error> {
        let quiet: Arc<dyn Audit> = Arc::new(Lines::new(std::io::sink()));
        let fetcher: Arc<dyn JwksFetcher> = Arc::new(HttpFetcher::default());
        Self::assemble(snapshot, clock, &Metrics::default(), quiet, fetcher, false).await
    }

    /// Builds the state for `snapshot`, loading its signing keys. It counts
    /// into `metrics`, audits each exchange to `audit`, fetches keys with
    /// `fetcher`, and renews them in the background while it lives.
    pub async fn build_with(
        snapshot: Snapshot,
        clock: Arc<dyn Clock>,
        metrics: &Metrics,
        audit: Arc<dyn Audit>,
        fetcher: Arc<dyn JwksFetcher>,
    ) -> Result<Self, Error> {
        Self::assemble(snapshot, clock, metrics, audit, fetcher, true).await
    }

    async fn assemble(
        snapshot: Snapshot,
        clock: Arc<dyn Clock>,
        metrics: &Metrics,
        audit: Arc<dyn Audit>,
        fetcher: Arc<dyn JwksFetcher>,
        refresh: bool,
    ) -> Result<Self, Error> {
        let config = Arc::new(snapshot.config);
        let keys = KeySet::from_config(&config.issuer.signing, &Secrets::default()).await?;
        let validator = Validator::new(&config, fetcher, clock.clone());
        let observer = ExchangeAudit {
            audit,
            exchanges: metrics.exchanges.clone(),
            clock: clock.clone(),
        };
        let issuer = Issuer::new(config.clone(), keys, validator, clock.clone())
            .with_observer(Arc::new(observer));
        let issuer = Arc::new(issuer);
        let refresher = refresh
            .then(|| Refresher::spawn(issuer.clone(), metrics.jwks_age.clone(), REFRESH_TICK))
            .flatten();
        let gateway = Gateway::new(&config, issuer.clone(), clock, metrics.gateway.clone())?;
        let gateway = Arc::new(gateway);
        Ok(Self {
            revision: snapshot.revision,
            content: snapshot.content,
            author: snapshot.author,
            config,
            issuer: tsong_issuer::router(issuer),
            gateway: tsong_gateway::router(gateway),
            _refresher: refresher,
        })
    }
}

/// A router that hands each request to the router `pick` chooses from the
/// state current when the request arrives. A request keeps that state
/// until it finishes, even if a reload swaps in another.
pub fn current(state: watch::Receiver<Arc<State>>, pick: fn(&State) -> &Router) -> Router {
    Router::new().fallback(move |request: Request| {
        let router = pick(&state.borrow()).clone();
        async move { router.oneshot(request).await.into_response() }
    })
}

/// The addresses a config listens on, which only a restart changes.
pub fn listen_addresses(config: &Config) -> [(&'static str, SocketAddr); 2] {
    [
        ("issuer.listen", config.issuer.listen),
        ("gateway.listen", config.gateway.listen),
    ]
}
