//! Reading the credential in a request's `Authorization` header.

use axum::http::{HeaderMap, header};

/// What a request's `Authorization` header carries.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Credential<'a> {
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
pub(crate) fn credential(headers: &HeaderMap) -> Credential<'_> {
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

/// Whether `text` is an RFC 9110 token, as an auth scheme must be.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}
