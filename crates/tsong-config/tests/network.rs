use std::error::Error;
use std::net::IpAddr;

use ipnet::IpNet;
use tsong_config::{allowed, client_ip};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn nets(list: &[&str]) -> TestResult<Vec<IpNet>> {
    Ok(list
        .iter()
        .map(|net| net.parse())
        .collect::<Result<_, _>>()?)
}

/// The client address for a connection from `peer` with these
/// `X-Forwarded-For` header values, trusting 10.0.0.0/24 and fd00::/8.
fn client(peer: &str, forwarded_for: &[&[u8]]) -> TestResult<Option<IpAddr>> {
    let trusted = nets(&["10.0.0.0/24", "fd00::/8"])?;
    Ok(client_ip(
        peer.parse()?,
        forwarded_for.iter().copied(),
        &trusted,
    ))
}

fn ip(text: &str) -> TestResult<Option<IpAddr>> {
    Ok(Some(text.parse()?))
}

#[test]
fn an_untrusted_peer_is_the_client_whatever_it_forwards() -> TestResult {
    assert_eq!(client("192.0.2.1", &[])?, ip("192.0.2.1")?);
    assert_eq!(client("192.0.2.1", &[b"10.9.9.9"])?, ip("192.0.2.1")?);
    assert_eq!(client("192.0.2.1", &[b"garbage"])?, ip("192.0.2.1")?);
    Ok(())
}

#[test]
fn a_trusted_peer_hands_off_to_the_first_untrusted_hop() -> TestResult {
    assert_eq!(client("10.0.0.5", &[b"192.0.2.1"])?, ip("192.0.2.1")?);
    assert_eq!(
        client("10.0.0.5", &[b"198.51.100.7, 192.0.2.1, 10.0.0.9"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(
        client("10.0.0.5", &[b"198.51.100.7", b"192.0.2.1 , 10.0.0.9"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(
        client("10.0.0.5", &[b"garbage, 192.0.2.1"])?,
        ip("192.0.2.1")?
    );
    Ok(())
}

#[test]
fn a_chain_of_trusted_proxies_ends_at_the_last_one() -> TestResult {
    assert_eq!(client("10.0.0.5", &[])?, ip("10.0.0.5")?);
    assert_eq!(client("10.0.0.5", &[b"10.0.0.7"])?, ip("10.0.0.7")?);
    Ok(())
}

#[test]
fn hops_left_of_the_client_are_never_read() -> TestResult {
    assert_eq!(
        client("10.0.0.5", &[b"\xff", b"unknown, 192.0.2.1"])?,
        ip("192.0.2.1")?
    );
    Ok(())
}

#[test]
fn a_hop_that_must_be_believed_must_be_an_address() -> TestResult {
    assert_eq!(client("10.0.0.5", &[b"192.0.2.1, garbage"])?, None);
    assert_eq!(client("10.0.0.5", &[b"192.0.2.1:443"])?, None);
    assert_eq!(client("10.0.0.5", &[b""])?, None);
    assert_eq!(client("10.0.0.5", &[b"\xff"])?, None);
    Ok(())
}

#[test]
fn mapped_ipv6_addresses_are_read_as_ipv4() -> TestResult {
    assert_eq!(
        client("::ffff:10.0.0.5", &[b"192.0.2.1"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(
        client("10.0.0.5", &[b"::ffff:192.0.2.1"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(client("fd00::1", &[b"2001:db8::1"])?, ip("2001:db8::1")?);
    Ok(())
}

#[test]
fn a_client_must_be_in_the_gateway_list_and_any_route_list() -> TestResult {
    let gateway = nets(&["10.0.0.0/8"])?;
    let route = nets(&["10.1.0.0/16"])?;
    let inside: IpAddr = "10.1.2.3".parse()?;
    let outside_route: IpAddr = "10.2.0.1".parse()?;
    let outside: IpAddr = "192.0.2.1".parse()?;
    assert!(allowed(inside, &gateway, None));
    assert!(allowed(inside, &gateway, Some(&route)));
    assert!(allowed(outside_route, &gateway, None));
    assert!(!allowed(outside_route, &gateway, Some(&route)));
    assert!(!allowed(outside, &gateway, None));
    assert!(!allowed(outside, &route, Some(&nets(&["0.0.0.0/0"])?)));
    assert!(!allowed(inside, &[], None));
    assert!(!allowed(inside, &gateway, Some(&[])));
    Ok(())
}
