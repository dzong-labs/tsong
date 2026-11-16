//! Exchange failures, as RFC 6749 section 5.2 error responses. A subject
//! token that fails validation, or lacks the subject the minted token needs,
//! is `invalid_request`, as RFC 8693 section 2.2.2 requires.

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
    InvalidTarget(String),
    #[error("{0}")]
    InvalidScope(String),
    #[error("client address not allowed")]
    AccessDenied,
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
            Self::InvalidTarget(_) => "invalid_target",
            Self::InvalidScope(_) => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::Unavailable(_) => "temporarily_unavailable",
            Self::Server(_) => "server_error",
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            Self::AccessDenied => 403,
            Self::Unavailable(_) => 503,
            Self::Server(_) => 500,
            _ => 400,
        }
    }
}

impl From<ValidateError> for ExchangeError {
    fn from(error: ValidateError) -> Self {
        match error {
            ValidateError::Jwks(_) | ValidateError::KeysExpired => {
                Self::Unavailable(error.to_string())
            }
            _ => Self::InvalidRequest(error.to_string()),
        }
    }
}

impl From<KeyError> for ExchangeError {
    fn from(error: KeyError) -> Self {
        Self::Server(format!("signing: {error}"))
    }
}
