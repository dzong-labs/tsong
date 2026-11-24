//! What the gateway reports about requests it forwards without an
//! exchange.

use tsong_issuer::ExchangeContext;

/// Receives the requests the gateway forwards without an exchange.
pub trait RequestObserver: Send + Sync {
    /// A request with no `Authorization` header, passed through without a
    /// token to the route whose host is `audience`.
    fn passed_anonymous(&self, audience: &str, context: &ExchangeContext);
}
