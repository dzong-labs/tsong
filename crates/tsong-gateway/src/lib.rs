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
mod exchange;
mod forward;
mod metrics;

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
use tsong_config::{Config, Route, RouteTable, allowed, client_ip};
use tsong_issuer::{ExchangeContext, ExchangeError};

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
        })
    }

    /// Answers `request`, with its request ID on the response, and counts
    /// the answer by route and status.
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
        if has_access_token(request.uri().query()) {
            return unauthorized("a token in the query is not accepted", None);
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
        let anonymous = minted.is_none();
        let response = self
            .send_downstream(route, request, minted.as_deref(), peer)
            .await;
        if anonymous {
            self.metrics
                .anonymous_requests
                .get_or_create(&RouteStatus {
                    route: route.name.clone(),
                    status: response.status().as_u16(),
                })
                .inc();
        }
        response
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

/// What a request's `Authorization` header carries.
#[derive(Debug, PartialEq, Eq)]
enum Credential<'a> {
    /// No `Authorization` header.
    None,
    /// The token in the request's one `Authorization: Bearer` header.
    Bearer(&'a str),
    /// More than one `Authorization` header.
    Repeated,
    /// An empty or unreadable header, a scheme that isn't an RFC 9110
    /// token, or a `Bearer` header without exactly one token.
    Malformed,
    /// One header with a scheme other than `Bearer`, which Tsong can't
    /// vouch for and never forwards.
    Unsupported,
}

/// The credential in `headers`. Scheme names compare case-insensitively
/// (RFC 9110 section 11.1).
fn credential(headers: &HeaderMap) -> Credential<'_> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Credential::None;
    };
    if values.next().is_some() {
        return Credential::Repeated;
    }
    let Ok(value) = value.to_str() else {
        return Credential::Malformed;
    };
    let (scheme, token) = value.split_once(' ').unwrap_or((value, ""));
    if !is_token(scheme) {
        return Credential::Malformed;
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Credential::Unsupported;
    }
    match token.trim_matches(' ') {
        token if is_visible(token) => Credential::Bearer(token),
        _ => Credential::Malformed,
    }
}

/// Whether `text` is one or more visible ASCII characters, 0x21 to 0x7E,
/// so a token holds no whitespace. Opaque tokens use more than RFC 6750's
/// `b64token` characters, such as `:`, `%` and `,`.
fn is_visible(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Whether `query` has an `access_token` parameter (RFC 6750 section
/// 2.3) as some downstream could read it: pairs split on `&` or `;`, and
/// the name percent-decoded, `+` read as a space.
fn has_access_token(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        query.split(['&', ';']).any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            reads_as_access_token(&percent_decoded(name))
        })
    })
}

/// Whether some downstream framework could read the decoded parameter
/// name `name` as `access_token`. Rather than follow each framework's
/// parser, the name is normalized generously: cut at the first NUL and
/// the first `[`, trimmed, case-folded, and stripped of everything but
/// ASCII letters and digits. It counts when that leaves `accesstoken`,
/// cut or not, so `access_token[]`, `access-token`, `ACCESS.TOKEN` and
/// look-alikes with `ſ` or the Kelvin sign all count.
fn reads_as_access_token(name: &[u8]) -> bool {
    let cut = name
        .iter()
        .position(|&byte| byte == 0 || byte == b'[')
        .and_then(|end| name.get(..end))
        .unwrap_or(name);
    normalized(cut) == ACCESS_TOKEN || normalized(name) == ACCESS_TOKEN
}

/// `name` trimmed, case-folded and stripped to ASCII letters and digits.
fn normalized(name: &[u8]) -> String {
    String::from_utf8_lossy(name)
        .trim()
        .chars()
        .flat_map(|c| match c {
            // The non-ASCII characters whose Unicode simple case folding
            // is an ASCII letter: the long s and the Kelvin sign.
            '\u{017F}' => 's'.to_lowercase(),
            '\u{212A}' => 'k'.to_lowercase(),
            c => c.to_lowercase(),
        })
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

/// `access_token`, as [`normalized`] leaves it.
const ACCESS_TOKEN: &str = "accesstoken";

/// `text` percent-decoded as some downstream could read it: `%XX`, and
/// IIS's `%uXXXX` as UTF-8, with `+` read as a space. Decoding repeats, up
/// to three passes, until the text stops changing, so a double-encoded
/// `%255F` decodes too. A malformed escape is kept as it is.
fn percent_decoded(text: &str) -> Vec<u8> {
    let mut decoded = text.as_bytes().to_vec();
    for _ in 0..3 {
        let next = decoded_once(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded
}

/// `bytes` with one pass of escapes decoded.
fn decoded_once(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let rest = bytes.get(index + 1..).unwrap_or_default();
        let wide = rest
            .split_first()
            .filter(|&(&u, _)| byte == b'%' && u.eq_ignore_ascii_case(&b'u'))
            .and_then(|(_, digits)| hex(digits.get(..4)?))
            .and_then(char::from_u32);
        let narrow = (byte == b'%')
            .then(|| hex(rest.get(..2)?))
            .flatten()
            .and_then(|value| u8::try_from(value).ok());
        if let Some(c) = wide {
            let mut utf8 = [0; 4];
            decoded.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            index += 6;
        } else if let Some(value) = narrow {
            decoded.push(value);
            index += 3;
        } else {
            decoded.push(if byte == b'+' { b' ' } else { byte });
            index += 1;
        }
    }
    decoded
}

/// The value of `digits`, when they are all hex digits.
fn hex(digits: &[u8]) -> Option<u32> {
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// Whether `text` is an RFC 9110 token, as an auth scheme must be.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
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
