//! What Tsong reports about itself: Prometheus metrics, kept for the life
//! of the process, the audit line written for each token exchange, and the
//! audit lines for JWKS fetches that fail and for the fetch that recovers.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde_json::json;
use std::time::Duration;
use tsong_clock::Clock;
use tsong_config::TrustedIssuer;
use tsong_gateway::GatewayMetrics;
use tsong_issuer::{ExchangeEvent, ExchangeObserver, Issuer};
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
    /// Seconds since each trusted issuer's keys were fetched.
    pub jwks_age: Family<IssuerLabel, Gauge>,
    /// Config reloads that found a new revision, by outcome.
    pub reloads: Family<OutcomeLabel, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        let gateway = Arc::new(GatewayMetrics::register(&mut registry));
        let exchanges = Family::<OutcomeLabel, Counter>::default();
        let jwks_failures = Family::<IssuerLabel, Counter>::default();
        let jwks_age = Family::<IssuerLabel, Gauge>::default();
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
            "tsong_jwks_age_seconds",
            "Seconds since each trusted issuer's keys were fetched",
            jwks_age.clone(),
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
            jwks_age,
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

/// A JWKS fetcher that counts each failed fetch by issuer and audits it,
/// and audits the first fetch that succeeds after a failure.
pub struct ObservedFetcher<F> {
    inner: F,
    failures: Family<IssuerLabel, Counter>,
    audit: Arc<dyn Audit>,
    clock: Arc<dyn Clock>,
    /// The issuers whose last fetch failed, by `iss`.
    failing: Mutex<HashSet<String>>,
}

impl<F> ObservedFetcher<F> {
    pub fn new(
        inner: F,
        failures: Family<IssuerLabel, Counter>,
        audit: Arc<dyn Audit>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner,
            failures,
            audit,
            clock,
            failing: Mutex::default(),
        }
    }

    /// The fetcher it wraps.
    pub fn inner(&self) -> &F {
        &self.inner
    }

    fn failing(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.failing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn record(&self, issuer: &str, outcome: &str, error: Option<String>) {
        let line = json!({
            "event": "jwks_fetch",
            "at": self.clock.unix_seconds(),
            "outcome": outcome,
            "issuer": issuer,
            "error": error,
        });
        self.audit.record(&line.to_string());
    }
}

impl<F: JwksFetcher> JwksFetcher for ObservedFetcher<F> {
    fn fetch<'a>(&'a self, issuer: &'a TrustedIssuer) -> FetchFuture<'a> {
        Box::pin(async move {
            let iss = issuer.issuer.as_str();
            let result = self.inner.fetch(issuer).await;
            match &result {
                Err(error) => {
                    self.failures
                        .get_or_create(&IssuerLabel {
                            issuer: iss.to_owned(),
                        })
                        .inc();
                    self.failing().insert(iss.to_owned());
                    self.record(iss, "failed", Some(error.to_string()));
                }
                Ok(_) => {
                    let recovered = self.failing().remove(iss);
                    if recovered {
                        self.record(iss, "recovered", None);
                    }
                }
            }
            result
        })
    }
}

/// How often the refresher looks for expired keys.
pub const REFRESH_TICK: Duration = Duration::from_secs(1);

/// Keeps one config's trusted-issuer keys current: each tick it refetches
/// expired keys and reports every issuer's key age. It stops when dropped,
/// which a reload does once the old state's requests finish.
pub struct Refresher(tokio::task::JoinHandle<()>);

impl Refresher {
    /// Starts refreshing `issuer`'s keys every `tick`, or returns `None`
    /// outside a Tokio runtime.
    pub fn spawn(
        issuer: Arc<Issuer>,
        ages: Family<IssuerLabel, Gauge>,
        tick: Duration,
    ) -> Option<Self> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        Some(Self(runtime.spawn(async move {
            loop {
                refresh(&issuer, &ages).await;
                tokio::time::sleep(tick).await;
            }
        })))
    }
}

impl Drop for Refresher {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Refetches `issuer`'s expired keys once, then sets each trusted issuer's
/// key age in `ages`.
pub async fn refresh(issuer: &Issuer, ages: &Family<IssuerLabel, Gauge>) {
    let validator = issuer.validator();
    validator.refresh_due().await;
    for (iss, age) in validator.key_ages().await {
        if let Some(age) = age {
            ages.get_or_create(&IssuerLabel { issuer: iss })
                .set(i64::try_from(age.as_secs()).unwrap_or(i64::MAX));
        }
    }
}
