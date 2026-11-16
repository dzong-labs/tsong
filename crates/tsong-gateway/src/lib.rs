//! The reverse proxy. For each request it looks up the route by host,
//! checks the client's address against the allow lists, exchanges the
//! bearer token for one Tsong signs, and streams the request to the
//! route's downstream with the exchanged token in its place. The upstream
//! is the caller; the downstream is where the request goes.
//!
//! It fails closed: a request that can't be authenticated or exchanged is
//! answered by the gateway and never forwarded, and the inbound token is
//! never sent downstream.

mod cache;
mod exchange;
mod forward;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use tsong_clock::Clock;
use tsong_config::{Config, RouteTable, allowed, client_ip};
use tsong_issuer::ExchangeError;

pub use cache::{ExchangeCache, lifetime};
pub use exchange::{ExchangeFuture, Exchanger};

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
}

impl Gateway {
    pub fn new(
        config: &Config,
        exchanger: Arc<dyn Exchanger>,
        clock: Arc<dyn Clock>,
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
            ),
            clients,
        })
    }

    async fn handle(&self, peer: SocketAddr, request: Request) -> Response {
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
        let Some(token) = bearer(request.headers()) else {
            return unauthorized("a bearer token is required", None);
        };
        let minted = match self.cache.token(token, &host).await {
            Ok(minted) => minted,
            Err(error) => return exchange_failure(&error),
        };
        let timeout = route.read_timeout.unwrap_or(self.read_timeout);
        let Some(downstream) = self.clients.get(&timeout) else {
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "no downstream client");
        };
        let trusted_peer = self.trusted_proxies.iter().any(|net| net.contains(&peer));
        forward::forward(downstream, route, request, &minted, peer, trusted_peer).await
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

/// The token in the request's one `Authorization: Bearer` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(' '))
        .then_some(token)
}

/// The response to an exchange that failed.
fn exchange_failure(error: &ExchangeError) -> Response {
    let message = error.to_string();
    match error {
        ExchangeError::InvalidGrant(_) | ExchangeError::InvalidRequest(_) => {
            unauthorized(&message, Some("invalid_token"))
        }
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
