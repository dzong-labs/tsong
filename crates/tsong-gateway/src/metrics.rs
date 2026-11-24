//! The gateway's Prometheus metrics. They outlive any one config, so a
//! reload keeps counting into the same series.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

/// A route, as a label. Requests for no route are labelled `-`.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabel {
    pub route: String,
}

/// A route and the status the gateway answered with.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteStatus {
    pub route: String,
    pub status: u16,
}

/// What the gateway counts.
#[derive(Debug, Clone)]
pub struct GatewayMetrics {
    /// Requests whose exchanged token came from the cache, or from an
    /// exchange another request had already started.
    pub cache_hits: Counter,
    /// Requests that exchanged their token.
    pub cache_misses: Counter,
    /// Exchanged tokens held in the cache, as of the last request.
    pub cache_entries: Gauge,
    /// Requests answered, by route and status.
    pub requests: Family<RouteStatus, Counter>,
    /// Requests with no `Authorization` header passed through without a
    /// token, by route and the status they were answered with. Requests
    /// refused before that, by the allow lists or the `access_token`
    /// query check, aren't counted here.
    pub anonymous_requests: Family<RouteStatus, Counter>,
    /// Seconds from sending a request downstream to receiving its response
    /// headers, by route.
    pub downstream_seconds: Family<RouteLabel, Histogram>,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self {
            cache_hits: Counter::default(),
            cache_misses: Counter::default(),
            cache_entries: Gauge::default(),
            requests: Family::default(),
            anonymous_requests: Family::default(),
            // 1ms to about 16s.
            downstream_seconds: Family::new_with_constructor(|| {
                Histogram::new(exponential_buckets(0.001, 2.0, 15))
            }),
        }
    }
}

impl GatewayMetrics {
    /// New metrics, registered in `registry` under `tsong_`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        registry.register(
            "tsong_cache_hits",
            "Requests whose exchanged token came from the cache",
            metrics.cache_hits.clone(),
        );
        registry.register(
            "tsong_cache_misses",
            "Requests that exchanged their token",
            metrics.cache_misses.clone(),
        );
        registry.register(
            "tsong_cache_entries",
            "Exchanged tokens held in the cache",
            metrics.cache_entries.clone(),
        );
        registry.register(
            "tsong_gateway_requests",
            "Gateway requests answered, by route and status",
            metrics.requests.clone(),
        );
        registry.register(
            "tsong_anonymous_requests",
            "Requests passed through without a token, by route and status",
            metrics.anonymous_requests.clone(),
        );
        registry.register(
            "tsong_downstream_seconds",
            "Seconds until a downstream's response headers, by route",
            metrics.downstream_seconds.clone(),
        );
        metrics
    }
}
