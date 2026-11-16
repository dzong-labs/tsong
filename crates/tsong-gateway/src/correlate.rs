//! Request correlation: every request leaves the gateway with an
//! `X-Request-Id` and a W3C `traceparent`, so its logs line up with the
//! caller's and the downstream's.

use axum::http::{HeaderMap, HeaderValue};
use tsong_config::hex;
use tsong_issuer::{REQUEST_ID, TRACEPARENT, request_id_is_valid, trace_id};

const TRACESTATE: &str = "tracestate";

/// Gives `headers` a request ID and a `traceparent` for the gateway's hop,
/// and returns the request ID.
///
/// A valid `X-Request-Id` is kept; anything else is replaced with a random
/// one. A valid `traceparent` keeps its trace ID and flags with a new
/// parent ID, the gateway's own span; without one, a new trace starts and
/// any `tracestate` is dropped, as the W3C spec requires. `None` when the
/// system has no randomness to draw IDs from.
pub fn correlate(headers: &mut HeaderMap) -> Option<String> {
    let request_id = match headers.get(REQUEST_ID).map(HeaderValue::to_str) {
        Some(Ok(id)) if request_id_is_valid(id) => id.to_owned(),
        _ => random_hex::<16>()?,
    };
    let inbound = headers
        .get(TRACEPARENT)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let trace = trace_id(value)?;
            let flags = value.trim().rsplit('-').next()?;
            Some((trace.to_owned(), flags.to_owned()))
        });
    let (trace, flags) = match inbound {
        Some(continued) => continued,
        None => {
            headers.remove(TRACESTATE);
            (random_hex::<16>()?, "00".to_owned())
        }
    };
    let traceparent = format!("00-{trace}-{}-{flags}", random_hex::<8>()?);
    headers.insert(REQUEST_ID, HeaderValue::from_str(&request_id).ok()?);
    headers.insert(TRACEPARENT, HeaderValue::from_str(&traceparent).ok()?);
    Some(request_id)
}

/// `N` random bytes as hex. W3C forbids an all-zero ID, which 8 or more
/// random bytes draw with a chance of at most one in 2^64.
fn random_hex<const N: usize>() -> Option<String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).ok()?;
    Some(hex(&bytes))
}
