//! Exchange failures, as RFC 6749 section 5.2 error responses.

use tsong_keys::KeyError;
use tsong_validate::ValidateError;

/// Why an exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("only token exchange is supported")]
    UnsupportedGrantType,
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    InvalidGrant(String),
    #[error("{0}")]
    InvalidTarget(String),
    #[error("{0}")]
    InvalidScope(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Server(String),
}

impl ExchangeError {
    /// The OAuth `error` code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidTarget(_) => "invalid_target",
            Self::InvalidScope(_) => "invalid_scope",
            Self::Unavailable(_) => "temporarily_unavailable",
            Self::Server(_) => "server_error",
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            Self::Unavailable(_) => 503,
            Self::Server(_) => 500,
            _ => 400,
        }
    }
}

impl From<ValidateError> for ExchangeError {
    fn from(error: ValidateError) -> Self {
        match error {
            ValidateError::Unsupported(_) => Self::InvalidRequest(error.to_string()),
            ValidateError::Jwks(_) => Self::Unavailable(error.to_string()),
            _ => Self::InvalidGrant(error.to_string()),
        }
    }
}

impl From<KeyError> for ExchangeError {
    fn from(error: KeyError) -> Self {
        Self::Server(format!("signing: {error}"))
    }
}
