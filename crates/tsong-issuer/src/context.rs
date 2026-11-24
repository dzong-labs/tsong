//! What an exchange is observed with: the request it belongs to, and the
//! event an observer, such as an audit log, receives for each exchange and
//! for each request passed through without a token.

use std::time::Duration;

use axum::http::HeaderMap;

/// The header that names a request across services.
pub const REQUEST_ID: &str = "x-request-id";
/// The W3C Trace Context header: `version-traceid-parentid-flags`.
pub const TRACEPARENT: &str = "traceparent";

/// The request an exchange belongs to, for correlating it with other logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeContext {
    /// The request's `X-Request-Id`.
    pub request_id: Option<String>,
    /// The trace ID from the request's `traceparent`.
    pub trace_id: Option<String>,
}

impl ExchangeContext {
    /// The context `headers` carry. A header that is missing or malformed
    /// leaves its field empty.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let text = |name| headers.get(name).and_then(|value| value.to_str().ok());
        Self {
            request_id: text(REQUEST_ID)
                .filter(|id| request_id_is_valid(id))
                .map(str::to_owned),
            trace_id: text(TRACEPARENT).and_then(trace_id).map(str::to_owned),
        }
    }
}

/// Whether `id` can serve as a request ID: 1 to 128 visible ASCII
/// characters. Anything else is replaced rather than forwarded or logged.
pub fn request_id_is_valid(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_graphic())
}

/// The trace ID of a version-00 `traceparent`: 32 lowercase hex digits,
/// not all zero. `None` for anything malformed.
pub fn trace_id(traceparent: &str) -> Option<&str> {
    let mut parts = traceparent.trim().split('-');
    let (version, trace, parent, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex = |text: &str, len: usize| {
        text.len() == len
            && text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    };
    let not_zero = |text: &str| text.bytes().any(|byte| byte != b'0');
    let valid = parts.next().is_none()
        && version == "00"
        && hex(trace, 32)
        && not_zero(trace)
        && hex(parent, 16)
        && not_zero(parent)
        && hex(flags, 2);
    valid.then_some(trace)
}

/// One exchange, as an observer sees it. The tokens are never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeEvent {
    pub context: ExchangeContext,
    /// The audience requested: a route's host.
    pub audience: Option<String>,
    /// The trusted issuer's name in the config.
    pub trusted_issuer: Option<String>,
    /// The subject token's `iss` and `sub`, once it validated.
    pub iss: Option<String>,
    pub sub: Option<String>,
    /// The scopes granted.
    pub scope: Option<String>,
    /// The OAuth error code, or `None` when a token was issued.
    pub error: Option<&'static str>,
    /// Why it failed, when it did.
    pub error_description: Option<String>,
    pub duration: Duration,
}

/// Receives every exchange the issuer makes, through the gateway or the
/// token endpoint, and every request the gateway passes through without a
/// token.
pub trait ExchangeObserver: Send + Sync {
    fn exchanged(&self, event: &ExchangeEvent);

    /// A request with no `Authorization` header, passed through to the
    /// route whose host is `audience` without an exchange.
    fn passed_anonymous(&self, audience: &str, context: &ExchangeContext);
}
