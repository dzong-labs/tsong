//! Forwarding: the downstream request built from the inbound one, and the
//! downstream's response passed back, both streamed.

use std::net::IpAddr;

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use tsong_config::Route;

use crate::refuse;

pub const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_HOST: &str = "x-forwarded-host";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";
const FORWARDED: &str = "forwarded";
const KEEP_ALIVE: &str = "keep-alive";
const PROXY_CONNECTION: &str = "proxy-connection";

/// Headers that describe one connection, not the message, and so never
/// cross the gateway (RFC 9110 section 7.6.1).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    KEEP_ALIVE,
    PROXY_CONNECTION,
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers the gateway sets or strips itself, so the inbound values never
/// pass. `Forwarded` is stripped and not set.
const REPLACED: [&str; 6] = [
    "host",
    "authorization",
    FORWARDED,
    X_FORWARDED_FOR,
    X_FORWARDED_HOST,
    X_FORWARDED_PROTO,
];

/// The request's host, lowercased and without its port: from the URI when
/// it is absolute, otherwise from the `Host` header.
pub fn request_host(request: &Request) -> Option<String> {
    let authority = match request.uri().authority() {
        Some(authority) => authority.clone(),
        None => request
            .headers()
            .get(header::HOST)?
            .to_str()
            .ok()?
            .parse::<Authority>()
            .ok()?,
    };
    Some(authority.host().to_ascii_lowercase())
}

/// Sends `request` to the route's downstream with `minted` as its bearer
/// token, and returns the downstream's response.
pub async fn forward(
    client: &reqwest::Client,
    route: &Route,
    request: Request,
    minted: &str,
    peer: IpAddr,
    trusted_peer: bool,
) -> Response {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let url = format!("{}{path}", route.downstream.origin().ascii_serialization());
    let headers = match outbound_headers(&request, minted, peer, trusted_peer) {
        Some(headers) => headers,
        None => return refuse(StatusCode::BAD_REQUEST, "malformed forwarding headers"),
    };
    let method = request.method().clone();
    let mut downstream = client.request(method, url).headers(headers);
    // A body known to be empty is not sent, so a GET doesn't go out as an
    // empty chunked stream.
    if request.body().size_hint().exact() != Some(0) {
        downstream = downstream.body(reqwest::Body::wrap_stream(
            request.into_body().into_data_stream(),
        ));
    }
    let sent = downstream.send().await;
    match sent {
        Ok(response) => inbound_response(response),
        Err(_) => refuse(StatusCode::BAD_GATEWAY, "the downstream is unreachable"),
    }
}

/// The downstream request's headers: the inbound headers without the
/// hop-by-hop and replaced ones, then the minted bearer token and the
/// `X-Forwarded-*` headers. The downstream host is set by the client from
/// the URL.
fn outbound_headers(
    request: &Request,
    minted: &str,
    peer: IpAddr,
    trusted_peer: bool,
) -> Option<HeaderMap> {
    let inbound = request.headers();
    let mut headers = end_to_end(inbound);
    for name in REPLACED {
        headers.remove(name);
    }

    let mut authorization = HeaderValue::from_str(&format!("Bearer {minted}")).ok()?;
    authorization.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, authorization);

    // A trusted proxy's chain is kept; anyone else's could be forged.
    let mut chain: Vec<u8> = Vec::new();
    if trusted_peer {
        for value in inbound.get_all(X_FORWARDED_FOR) {
            chain.extend_from_slice(value.as_bytes());
            chain.extend_from_slice(b", ");
        }
    }
    chain.extend_from_slice(peer.to_string().as_bytes());
    headers.insert(X_FORWARDED_FOR, HeaderValue::from_bytes(&chain).ok()?);

    let proto = match inbound.get(X_FORWARDED_PROTO) {
        Some(proto) if trusted_peer => proto.clone(),
        _ => HeaderValue::from_static("http"),
    };
    headers.insert(X_FORWARDED_PROTO, proto);

    let host = match (inbound.get(X_FORWARDED_HOST), request.uri().authority()) {
        (Some(host), _) if trusted_peer => Some(host.clone()),
        (_, Some(authority)) => HeaderValue::from_str(authority.as_str()).ok(),
        (_, None) => inbound.get(header::HOST).cloned(),
    };
    if let Some(host) = host {
        headers.insert(X_FORWARDED_HOST, host);
    }
    Some(headers)
}

/// The downstream's response, streamed back without its hop-by-hop
/// headers.
fn inbound_response(downstream: reqwest::Response) -> Response {
    let status = downstream.status();
    let headers = end_to_end(downstream.headers());
    let mut response = Response::new(Body::from_stream(downstream.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// `headers` without the hop-by-hop headers, including any `Connection`
/// names.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    let mut kept = headers.clone();
    for name in HOP_BY_HOP.into_iter() {
        kept.remove(name);
    }
    for name in &listed {
        kept.remove(name);
    }
    kept
}
