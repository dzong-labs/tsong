//! Who the client is, and whether it may pass.

use std::net::IpAddr;

use axum::http::HeaderValue;
use axum::http::header::GetAll;
use ipnet::IpNet;

/// The client's address. It is the connection's peer, unless the peer is
/// a trusted proxy: then `X-Forwarded-For` is read from the right, each hop
/// believed while the address before it is a trusted proxy, and the first
/// address that isn't one is the client. Hops left of the client are never
/// read. `None` when a hop that must be believed isn't an IP address.
pub fn client_ip(
    peer: IpAddr,
    forwarded_for: GetAll<'_, HeaderValue>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    let mut client = peer.to_canonical();
    if !trusted(&client) {
        return Some(client);
    }
    for value in forwarded_for.iter().rev() {
        for hop in value.to_str().ok()?.rsplit(',') {
            client = hop.trim().parse::<IpAddr>().ok()?.to_canonical();
            if !trusted(&client) {
                return Some(client);
            }
        }
    }
    Some(client)
}

/// Whether `client` is in the gateway's allow list and, when the route
/// has one, the route's.
pub fn allowed(client: IpAddr, gateway: &[IpNet], route: Option<&[IpNet]>) -> bool {
    let within = |list: &[IpNet]| list.iter().any(|net| net.contains(&client));
    within(gateway) && route.is_none_or(within)
}
