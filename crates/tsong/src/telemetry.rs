//! What Tsong reports about itself: Prometheus metrics, kept for the life
//! of the process, and the audit line written for each token exchange.

use std::sync::Arc;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use serde_json::json;
use tsong_clock::Clock;
use tsong_config::TrustedIssuer;
use tsong_gateway::GatewayMetrics;
use tsong_issuer::{ExchangeEvent, ExchangeObserver};
use tsong_validate::{FetchFuture, JwksFetcher};

use crate::reload::Audit;

/// An outcome, as a label: `issued` or an OAuth error code for an
/// exchange, `applied` or a reason for a reload.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutcomeLabel {
    pub outcome: String,
}

/// A trusted issuer's `iss`, as a label.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct IssuerLabel {
    pub issuer: String,
}

/// Every metric Tsong keeps, and the registry `GET /metrics` encodes.
pub struct Metrics {
    pub registry: Registry,
    pub gateway: Arc<GatewayMetrics>,
    /// Token exchanges, by outcome.
    pub exchanges: Family<OutcomeLabel, Counter>,
    /// Failed JWKS fetches, by trusted issuer.
    pub jwks_failures: Family<IssuerLabel, Counter>,
    /// Config reloads that found a new revision, by outcome.
    pub reloads: Family<OutcomeLabel, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        let gateway = Arc::new(GatewayMetrics::register(&mut registry));
        let exchanges = Family::<OutcomeLabel, Counter>::default();
        let jwks_failures = Family::<IssuerLabel, Counter>::default();
        let reloads = Family::<OutcomeLabel, Counter>::default();
        registry.register(
            "tsong_exchanges",
            "Token exchanges, by outcome",
            exchanges.clone(),
        );
        registry.register(
            "tsong_jwks_fetch_failures",
            "Failed JWKS fetches, by trusted issuer",
            jwks_failures.clone(),
        );
        registry.register(
            "tsong_config_reloads",
            "Config reloads that found a new revision, by outcome",
            reloads.clone(),
        );
        Self {
            registry,
            gateway,
            exchanges,
            jwks_failures,
            reloads,
        }
    }
}

impl Metrics {
    /// The metrics in the Prometheus text format.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &self.registry)?;
        Ok(text)
    }
}

/// Writes one audit line per token exchange and counts it.
pub struct ExchangeAudit {
    pub audit: Arc<dyn Audit>,
    pub exchanges: Family<OutcomeLabel, Counter>,
    pub clock: Arc<dyn Clock>,
}

impl ExchangeObserver for ExchangeAudit {
    fn exchanged(&self, event: &ExchangeEvent) {
        let outcome = event.error.unwrap_or("issued");
        self.exchanges
            .get_or_create(&OutcomeLabel {
                outcome: outcome.to_owned(),
            })
            .inc();
        let line = json!({
            "event": "token_exchange",
            "at": self.clock.unix_seconds(),
            "outcome": outcome,
            "request_id": event.context.request_id,
            "trace_id": event.context.trace_id,
            "audience": event.audience,
            "trusted_issuer": event.trusted_issuer,
            "iss": event.iss,
            "sub": event.sub,
            "scope": event.scope,
            "error_description": event.error_description,
            "duration_ms": event.duration.as_secs_f64() * 1000.0,
        });
        self.audit.record(&line.to_string());
    }
}

/// A JWKS fetcher that counts each failed fetch by issuer.
pub struct CountingFetcher<F> {
    pub inner: F,
    pub failures: Family<IssuerLabel, Counter>,
}

impl<F: JwksFetcher> JwksFetcher for CountingFetcher<F> {
    fn fetch<'a>(&'a self, issuer: &'a TrustedIssuer) -> FetchFuture<'a> {
        Box::pin(async move {
            let result = self.inner.fetch(issuer).await;
            if result.is_err() {
                self.failures
                    .get_or_create(&IssuerLabel {
                        issuer: issuer.issuer.clone(),
                    })
                    .inc();
            }
            result
        })
    }
}
