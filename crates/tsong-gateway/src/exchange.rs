//! How the gateway reaches the issuer: through a trait, so it can call the
//! issuer in-process today and over HTTP later.

use std::future::Future;
use std::pin::Pin;

use tsong_issuer::{
    ACCESS_TOKEN, ExchangeContext, ExchangeError, Issuer, TOKEN_EXCHANGE, TokenRequest,
    TokenResponse,
};

/// The future an [`Exchanger`] returns.
pub type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TokenResponse, ExchangeError>> + Send + 'a>>;

/// Exchanges an inbound access token for one Tsong signs.
pub trait Exchanger: Send + Sync {
    /// Exchanges `token` for a token for the route whose host is
    /// `audience`, for the request `context` describes.
    fn exchange<'a>(
        &'a self,
        token: &'a str,
        audience: &'a str,
        context: &'a ExchangeContext,
    ) -> ExchangeFuture<'a>;
}

/// The issuer in the same process.
impl Exchanger for Issuer {
    fn exchange<'a>(
        &'a self,
        token: &'a str,
        audience: &'a str,
        context: &'a ExchangeContext,
    ) -> ExchangeFuture<'a> {
        Box::pin(Issuer::exchange_with(
            self,
            TokenRequest {
                grant_type: Some(TOKEN_EXCHANGE.into()),
                subject_token: Some(token.into()),
                subject_token_type: Some(ACCESS_TOKEN.into()),
                audience: Some(audience.into()),
                ..TokenRequest::default()
            },
            context,
        ))
    }
}
