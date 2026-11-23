//! TOML parse errors that name where the problem is, without quoting the
//! line, which may hold a secret written in by mistake.

use std::fmt;

use serde::Deserializer;
use serde::de::{Error as _, IgnoredAny};

/// Why a document didn't parse, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl ParseError {
    /// The error `toml` reported for `text`, without its quoted source.
    pub(crate) fn new(text: &str, error: &toml::de::Error) -> Self {
        let message = error.message().trim_end();
        let Some(before) = error.span().and_then(|span| text.get(..span.start)) else {
            return Self(message.to_owned());
        };
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit('\n')
            .next()
            .map_or(0, |start| start.chars().count())
            + 1;
        Self(format!("line {line}, column {column}: {message}"))
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// Defines, for each removed route key, a `deserialize_with` function that
/// refuses the key at its value's line and column, naming what took its
/// place.
macro_rules! refuse_removed_keys {
    ($($function:ident: $key:literal => $message:literal;)+) => {$(
        #[doc = concat!("Refuses a route's `", $key, "`, at its value's line and column, naming what took its place.")]
        pub(crate) fn $function<'de, D: Deserializer<'de>>(
            _: D,
        ) -> Result<Option<IgnoredAny>, D::Error> {
            Err(D::Error::custom(concat!($key, " is replaced by ", $message)))
        }
    )+};
}

refuse_removed_keys! {
    refuse_allowed_audiences: "allowed_audiences" =>
        "[routes.audiences]; move its values to audiences.allow, which also refuses a token carrying any audience outside it. An empty allowed_audiences refused every token; to keep that, remove the route";
    refuse_allowed_scopes: "allowed_scopes" =>
        "[routes.scopes]; move its values to scopes.allow, where an omitted allow means \"*\" and an empty one is refused. An empty allowed_scopes refused every token; to keep that, remove the route";
    refuse_required_scopes: "required_scopes" =>
        "[routes.scopes]; move its values to scopes.require";
}

/// Parses `text` as `T`, with any error as a [`ParseError`].
pub(crate) fn from_str<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ParseError> {
    toml::from_str(text).map_err(|error| ParseError::new(text, &error))
}
