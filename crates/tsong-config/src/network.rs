//! Who a client is, and whether it may pass: the client-address rules the
//! gateway and the issuer's token endpoint both enforce.

use std::net::IpAddr;

use ipnet::IpNet;

/// The client's address. It is the connection's peer, unless the peer is
/// a trusted proxy: then the `X-Forwarded-For` values, given in header
/// order, are read from the right, each hop believed while the address
/// before it is a trusted proxy, and the first address that isn't one is
/// the client. Hops left of the client are never read. `None` when a hop
/// that must be believed isn't an IP address.
pub fn client_ip<'a>(
    peer: IpAddr,
    forwarded_for: impl DoubleEndedIterator<Item = &'a [u8]>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let client = find_client(peer, forwarded_for, trusted_proxies);
    // Allow lists compare canonical addresses: an IPv4-mapped IPv6 address
    // here would let ::ffff:10.0.0.1 miss a rule for 10.0.0.1.
    debug_assert!(client.is_none_or(|client| client == client.to_canonical()));
    client
}

fn find_client<'a>(
    peer: IpAddr,
    forwarded_for: impl DoubleEndedIterator<Item = &'a [u8]>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    let mut client = peer.to_canonical();
    if !trusted(&client) {
        return Some(client);
    }
    for value in forwarded_for.rev() {
        for hop in std::str::from_utf8(value).ok()?.rsplit(',') {
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
