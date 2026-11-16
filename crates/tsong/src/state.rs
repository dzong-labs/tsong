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
use tsong_validate::{HttpFetcher, Validator};

use crate::Error;
use crate::reload::{Audit, Lines};
use crate::telemetry::{CountingFetcher, ExchangeAudit, Metrics};

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
}

impl State {
    /// Builds the state for `snapshot`, loading its signing keys, with
    /// metrics of its own and no exchange audit.
    pub fn build(snapshot: Snapshot, clock: Arc<dyn Clock>) -> Result<Self, Error> {
        let quiet: Arc<dyn Audit> = Arc::new(Lines::new(std::io::sink()));
        Self::build_with(snapshot, clock, &Metrics::default(), quiet)
    }

    /// Builds the state for `snapshot`, loading its signing keys. It counts
    /// into `metrics` and audits each exchange to `audit`.
    pub fn build_with(
        snapshot: Snapshot,
        clock: Arc<dyn Clock>,
        metrics: &Metrics,
        audit: Arc<dyn Audit>,
    ) -> Result<Self, Error> {
        let config = Arc::new(snapshot.config);
        let keys = KeySet::from_config(&config.issuer.signing)?;
        let fetcher = CountingFetcher {
            inner: HttpFetcher::default(),
            failures: metrics.jwks_failures.clone(),
        };
        let validator = Validator::new(&config, Arc::new(fetcher), clock.clone());
        let observer = ExchangeAudit {
            audit,
            exchanges: metrics.exchanges.clone(),
            clock: clock.clone(),
        };
        let issuer = Issuer::new(config.clone(), keys, validator, clock.clone())
            .with_observer(Arc::new(observer));
        let issuer = Arc::new(issuer);
        let gateway = Gateway::new(&config, issuer.clone(), clock, metrics.gateway.clone())?;
        let gateway = Arc::new(gateway);
        Ok(Self {
            revision: snapshot.revision,
            content: snapshot.content,
            author: snapshot.author,
            config,
            issuer: tsong_issuer::router(issuer),
            gateway: tsong_gateway::router(gateway),
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
