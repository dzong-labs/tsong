//! The reverse proxy. For each request it looks up the route by host,
//! checks the client's address against the allow lists, exchanges the
//! bearer token for one Tsong signs, and streams the request to the
//! route's downstream with the exchanged token in its place. A request
//! with no `Authorization` header goes without one. The upstream is the
//! caller; the downstream is where the request goes.
//!
//! It fails closed: a request with a token that can't be authenticated or
//! exchanged, or with any scheme other than `Bearer`, is answered by the
//! gateway and never forwarded, and the inbound credential is never sent
//! downstream.

mod cache;
mod correlate;
mod credential;
mod exchange;
mod forward;
mod metrics;
mod query;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use tsong_clock::Clock;
use tsong_config::{
    ACCESS_TOKEN, Config, Route, RouteTable, allowed, client_ip, fold_name_char, normalize_name,
};
use tsong_issuer::{ExchangeContext, ExchangeError};

use credential::{Credential, credential};
use query::has_refused_param;

pub use cache::{ExchangeCache, lifetime};
pub use correlate::correlate;
pub use exchange::{ExchangeFuture, Exchanger};
pub use metrics::{GatewayMetrics, RouteLabel, RouteStatus};

/// How long the gateway waits to connect to a downstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the gateway couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("building the downstream client: {0}")]
    Client(#[from] reqwest::Error),
}

/// The reverse proxy for one config.
pub struct Gateway {
    routes: RouteTable,
    allow: Vec<IpNet>,
    trusted_proxies: Vec<IpNet>,
    read_timeout: Duration,
    cache: ExchangeCache,
    /// One downstream client per read timeout in the config.
    clients: HashMap<Duration, reqwest::Client>,
    metrics: Arc<GatewayMetrics>,
    /// The refused query parameter names, normalized: `access_token`, then
    /// the config's.
    refused_query_params: Vec<String>,
    /// The refused header names, normalized, each with its name as the
    /// config spells it.
    refused_headers: Vec<(String, String)>,
}

impl Gateway {
    pub fn new(
        config: &Config,
        exchanger: Arc<dyn Exchanger>,
        clock: Arc<dyn Clock>,
        metrics: Arc<GatewayMetrics>,
    ) -> Result<Self, GatewayError> {
        let mut clients = HashMap::new();
        let timeouts = config
            .routes
            .iter()
            .map(|route| route.read_timeout(&config.gateway))
            .chain([config.gateway.read_timeout]);
        for timeout in timeouts {
            if let Entry::Vacant(entry) = clients.entry(timeout) {
                entry.insert(client(timeout)?);
            }
        }
        let refused_query_params = std::iter::once(ACCESS_TOKEN)
            .chain(
                config
                    .gateway
                    .refused_query_params
                    .iter()
                    .map(String::as_str),
            )
            .map(normalize_name)
            .collect();
        let refused_headers = config
            .gateway
            .refused_headers
            .iter()
            .map(|name| (normalize_name(name), name.clone()))
            .collect();
        Ok(Self {
            routes: RouteTable::new(&config.routes),
            allow: config.gateway.allow.clone(),
            trusted_proxies: config.gateway.trusted_proxies.clone(),
            read_timeout: config.gateway.read_timeout,
            cache: ExchangeCache::new(
                exchanger,
                clock,
                config.gateway.cache.max_entries,
                config.issuer.clock_skew,
                metrics.clone(),
            ),
            clients,
            metrics,
            refused_query_params,
            refused_headers,
        })
    }

    /// Answers `request`, with its request ID on the response, and counts
    /// the answer by route, status, and whether it came without an
    /// `Authorization` header.
    async fn handle(&self, peer: SocketAddr, mut request: Request) -> Response {
        let Some(request_id) = correlate(request.headers_mut()) else {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no randomness for a request ID",
            );
        };
        let route = forward::request_host(&request)
            .and_then(|host| self.routes.get(&host))
            .map_or_else(|| "-".to_owned(), |route| route.name.clone());
        let anonymous = !request.headers().contains_key(header::AUTHORIZATION);
        let mut response = self.route(peer, request).await;
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response
                .headers_mut()
                .insert(tsong_issuer::REQUEST_ID, value);
        }
        self.metrics
            .requests
            .get_or_create(&RouteStatus {
                route,
                status: response.status().as_u16(),
                anonymous,
            })
            .inc();
        response
    }

    async fn route(&self, peer: SocketAddr, request: Request) -> Response {
        let Some(host) = forward::request_host(&request) else {
            return refuse(StatusCode::NOT_FOUND, "no route for this host");
        };
        let Some(route) = self.routes.get(&host) else {
            return refuse(StatusCode::NOT_FOUND, "no route for this host");
        };
        let peer = peer.ip().to_canonical();
        let forwarded_for = request.headers().get_all(forward::X_FORWARDED_FOR);
        let Some(client) = client_ip(
            peer,
            forwarded_for.iter().map(HeaderValue::as_bytes),
            &self.trusted_proxies,
        ) else {
            return refuse(StatusCode::BAD_REQUEST, "malformed X-Forwarded-For");
        };
        if !allowed(client, &self.allow, route.allow.as_deref()) {
            return refuse(StatusCode::FORBIDDEN, "client address not allowed");
        }
        if has_refused_param(request.uri().query(), &self.refused_query_params) {
            return unauthorized("a token in the query is not accepted", None);
        }
        if let Some(name) = self.refused_header(request.headers()) {
            return unauthorized(&format!("the {name} header is not accepted"), None);
        }
        let minted = match credential(request.headers()) {
            Credential::None => None,
            Credential::Bearer(token) => {
                let context = ExchangeContext::from_headers(request.headers());
                match self.cache.token(token, &host, &context).await {
                    Ok(minted) => Some(minted),
                    Err(error) => return exchange_failure(&error),
                }
            }
            Credential::Repeated => {
                return unauthorized("more than one Authorization header", None);
            }
            Credential::Malformed => return unauthorized("a bearer token is required", None),
            Credential::Unsupported => {
                return unauthorized("only the Bearer scheme is accepted", None);
            }
        };
        self.send_downstream(route, request, minted.as_deref(), peer)
            .await
    }

    /// The configured name of the first refused header `headers` carries,
    /// comparing normalized names, so `X_API_Key` is `X-API-Key`.
    fn refused_header(&self, headers: &HeaderMap) -> Option<&str> {
        headers.keys().find_map(|header| {
            self.refused_headers
                .iter()
                .find(|(normalized, _)| {
                    header
                        .as_str()
                        .chars()
                        .flat_map(fold_name_char)
                        .eq(normalized.chars())
                })
                .map(|(_, name)| name.as_str())
        })
    }

    /// Streams `request` to `route`'s downstream with `minted` as its
    /// bearer token, if any, and times the downstream.
    async fn send_downstream(
        &self,
        route: &Route,
        request: Request,
        minted: Option<&str>,
        peer: IpAddr,
    ) -> Response {
        let timeout = route.read_timeout.unwrap_or(self.read_timeout);
        let Some(downstream) = self.clients.get(&timeout) else {
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "no downstream client");
        };
        let trusted_peer = self.trusted_proxies.iter().any(|net| net.contains(&peer));
        let started = Instant::now();
        let response =
            forward::forward(downstream, route, request, minted, peer, trusted_peer).await;
        self.metrics
            .downstream_seconds
            .get_or_create(&RouteLabel {
                route: route.name.clone(),
            })
            .observe(started.elapsed().as_secs_f64());
        response
    }
}

/// A downstream client that waits at most `read_timeout` between reads.
fn client(read_timeout: Duration) -> Result<reqwest::Client, GatewayError> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(read_timeout)
        .build()?)
}

/// The gateway's routes: every method and path, dispatched by host. Serve
/// it with `into_make_service_with_connect_info::<SocketAddr>()`, so the
/// gateway knows each connection's peer.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new().fallback(proxy).with_state(gateway)
}

async fn proxy(
    State(gateway): State<Arc<Gateway>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    gateway.handle(peer, request).await
}

/// The response to an exchange that failed.
fn exchange_failure(error: &ExchangeError) -> Response {
    let message = error.to_string();
    match error {
        ExchangeError::InvalidRequest(_) => unauthorized(&message, Some("invalid_token")),
        ExchangeError::InvalidTarget(_)
        | ExchangeError::InvalidScope(_)
        | ExchangeError::AccessDenied => refuse(StatusCode::FORBIDDEN, &message),
        // Outages and internal failures carry detail about keys and
        // issuers, which callers don't need.
        ExchangeError::Unavailable(_) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "token exchange is unavailable",
        ),
        ExchangeError::Server(_) | ExchangeError::UnsupportedGrantType => {
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "token exchange failed")
        }
    }
}

/// A 401 with the `WWW-Authenticate` challenge RFC 6750 defines.
fn unauthorized(message: &str, error: Option<&str>) -> Response {
    let challenge = match error {
        Some(error) => format!("Bearer error=\"{error}\""),
        None => "Bearer".to_owned(),
    };
    let mut response = refuse(StatusCode::UNAUTHORIZED, message);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// A response the gateway answers itself, with a plain-text reason.
fn refuse(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}
