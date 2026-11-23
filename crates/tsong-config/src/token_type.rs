//! The `typ` header values a trusted issuer's tokens may carry (RFC 8725
//! section 3.11), compared as RFC 7515 section 4.1.9 says: as media types,
//! without regard to case, with `application/` optional.

use serde::Deserialize;

const APPLICATION: &str = "application/";

/// A `typ` value a trusted issuer's tokens may carry, held in its short
/// form: lowercase, without `application/` when nothing else needs it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct TokenType(String);

/// RFC 9068's type for JWT access tokens, the default.
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// The token types a trusted issuer accepts when it names none.
pub(crate) fn default_token_types() -> Vec<TokenType> {
    vec![TokenType(ACCESS_TOKEN_TYPE.to_owned())]
}

impl TokenType {
    /// Whether a token's `typ` header names this type.
    pub fn matches(&self, typ: &str) -> bool {
        short(typ).eq_ignore_ascii_case(&self.0)
    }
}

impl TryFrom<String> for TokenType {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let short = short(&text);
        let parts: Vec<&str> = short.split('/').collect();
        if parts.len() <= 2 && parts.iter().all(|part| is_restricted_name(part)) {
            Ok(Self(short.to_ascii_lowercase()))
        } else {
            Err(format!(
                "token type {text:?} is not a media type such as \"at+jwt\": one or two parts split by /, each starting with a letter or digit, then letters, digits and !#$&-^_.+, up to 127 characters"
            ))
        }
    }
}

/// `typ` without an `application/` prefix, which RFC 7515 lets a type
/// leave out when it holds no other `/`.
fn short(typ: &str) -> &str {
    match typ.split_at_checked(APPLICATION.len()) {
        Some((prefix, rest)) if prefix.eq_ignore_ascii_case(APPLICATION) && !rest.contains('/') => {
            rest
        }
        _ => typ,
    }
}

/// Whether `text` is an RFC 6838 restricted name: a type or subtype.
fn is_restricted_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && text.len() <= 127
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&byte))
}
