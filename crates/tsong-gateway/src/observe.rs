//! What the gateway reports about requests it forwards without an
//! exchange.

use std::net::IpAddr;

use tsong_issuer::ExchangeContext;

/// A request with no `Authorization` header, as an observer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousRequest<'a> {
    /// The route's host.
    pub audience: &'a str,
    /// The client address the allow lists admitted: the only identity an
    /// anonymous caller has.
    pub client: IpAddr,
    /// The status the gateway answered with: the downstream's, the
    /// gateway's own when forwarding failed, or 499 when the caller went
    /// away first.
    pub status: u16,
    pub context: &'a ExchangeContext,
}

/// Receives the requests the gateway forwards without an exchange.
pub trait RequestObserver: Send + Sync {
    /// A request with no `Authorization` header, passed through without a
    /// token, once it was answered or abandoned. It runs on the request's
    /// task, so it must not block.
    fn passed_anonymous(&self, request: &AnonymousRequest<'_>);
}
