mod common;

use std::net::IpAddr;
use std::time::Duration;

use axum::http::HeaderMap;
use common::{NOW, TestResult, minted};
use ipnet::IpNet;
use tsong_gateway::{allowed, client_ip, lifetime};
use tsong_issuer::TokenResponse;

fn nets(list: &[&str]) -> TestResult<Vec<IpNet>> {
    Ok(list
        .iter()
        .map(|net| net.parse())
        .collect::<Result<_, _>>()?)
}

/// The client address for a connection from `peer` with these
/// `X-Forwarded-For` headers, trusting 10.0.0.0/24 and fd00::/8.
fn client(peer: &str, forwarded_for: &[&str]) -> TestResult<Option<IpAddr>> {
    let mut headers = HeaderMap::new();
    for value in forwarded_for {
        headers.append("x-forwarded-for", value.parse()?);
    }
    let trusted = nets(&["10.0.0.0/24", "fd00::/8"])?;
    Ok(client_ip(
        peer.parse()?,
        headers.get_all("x-forwarded-for"),
        &trusted,
    ))
}

fn ip(text: &str) -> TestResult<Option<IpAddr>> {
    Ok(Some(text.parse()?))
}

#[test]
fn an_untrusted_peer_is_the_client_whatever_it_forwards() -> TestResult {
    assert_eq!(client("192.0.2.1", &[])?, ip("192.0.2.1")?);
    assert_eq!(client("192.0.2.1", &["10.9.9.9"])?, ip("192.0.2.1")?);
    assert_eq!(client("192.0.2.1", &["garbage"])?, ip("192.0.2.1")?);
    Ok(())
}

#[test]
fn a_trusted_peer_hands_off_to_the_first_untrusted_hop() -> TestResult {
    assert_eq!(client("10.0.0.5", &["192.0.2.1"])?, ip("192.0.2.1")?);
    assert_eq!(
        client("10.0.0.5", &["198.51.100.7, 192.0.2.1, 10.0.0.9"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(
        client("10.0.0.5", &["198.51.100.7", "192.0.2.1 , 10.0.0.9"])?,
        ip("192.0.2.1")?
    );
    assert_eq!(
        client("10.0.0.5", &["garbage, 192.0.2.1"])?,
        ip("192.0.2.1")?
    );
    Ok(())
}

#[test]
fn a_chain_of_trusted_proxies_ends_at_the_last_one() -> TestResult {
    assert_eq!(client("10.0.0.5", &[])?, ip("10.0.0.5")?);
    assert_eq!(client("10.0.0.5", &["10.0.0.7"])?, ip("10.0.0.7")?);
    Ok(())
}

#[test]
fn hops_left_of_the_client_are_never_read() -> TestResult {
    let mut headers = HeaderMap::new();
    headers.append(
        "x-forwarded-for",
        axum::http::HeaderValue::from_bytes(b"\xff")?,
    );
    headers.append("x-forwarded-for", "unknown, 192.0.2.1".parse()?);
    let trusted = nets(&["10.0.0.0/24"])?;
    let peer: IpAddr = "10.0.0.5".parse()?;
    assert_eq!(
        client_ip(peer, headers.get_all("x-forwarded-for"), &trusted),
        ip("192.0.2.1")?
    );
    Ok(())
}

#[test]
fn a_hop_that_must_be_believed_must_be_an_address() -> TestResult {
    assert_eq!(client("10.0.0.5", &["192.0.2.1, garbage"])?, None);
    assert_eq!(client("10.0.0.5", &["192.0.2.1:443"])?, None);
    assert_eq!(client("10.0.0.5", &[""])?, None);
    let mut headers = HeaderMap::new();
    headers.append(
        "x-forwarded-for",
        axum::http::HeaderValue::from_bytes(b"\xff")?,
    );
    let trusted = nets(&["10.0.0.0/24"])?;
    let peer: IpAddr = "10.0.0.5".parse()?;
    assert_eq!(
        client_ip(peer, headers.get_all("x-forwarded-for"), &trusted),
        None
    );
    Ok(())
}

#[test]
fn mapped_ipv6_addresses_are_read_as_ipv4() -> TestResult {
    assert_eq!(client("::ffff:10.0.0.5", &["192.0.2.1"])?, ip("192.0.2.1")?);
    assert_eq!(client("10.0.0.5", &["::ffff:192.0.2.1"])?, ip("192.0.2.1")?);
    assert_eq!(client("fd00::1", &["2001:db8::1"])?, ip("2001:db8::1")?);
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

fn response(access_token: String, expires_in: u64) -> TokenResponse {
    TokenResponse {
        access_token,
        issued_token_type: tsong_issuer::ACCESS_TOKEN.into(),
        token_type: "Bearer".into(),
        expires_in,
        scope: None,
    }
}

#[test]
fn a_token_is_kept_until_its_exp_less_the_skew() -> TestResult {
    let skew = Duration::from_secs(30);
    let token = response(minted("a", NOW + 900)?, 1);
    assert_eq!(lifetime(&token, NOW, skew), Duration::from_secs(870));
    assert_eq!(lifetime(&token, NOW + 880, skew), Duration::ZERO);
    assert_eq!(lifetime(&token, NOW + 2000, skew), Duration::ZERO);
    Ok(())
}

#[test]
fn expires_in_stands_in_when_exp_cannot_be_read() -> TestResult {
    let skew = Duration::from_secs(30);
    for token in [
        "opaque".to_owned(),
        "h.!!!.s".to_owned(),
        "h.bm90IGpzb24.s".to_owned(),
        format!("h.{}.s", "eyJuYW1lIjoibm8gZXhwIn0"),
        format!("h.{}.s", "eyJleHAiOiJzb29uIn0"),
    ] {
        assert_eq!(
            lifetime(&response(token.clone(), 600), NOW, skew),
            Duration::from_secs(570),
            "{token}"
        );
    }
    assert_eq!(
        lifetime(&response("opaque".into(), 10), NOW, skew),
        Duration::ZERO
    );
    Ok(())
}
