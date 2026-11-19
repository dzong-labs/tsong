//! Properties of the client-address rules and route policy, over generated
//! inputs. Each run tries `PROPTEST_CASES` cases, 256 unless set; the
//! weekly workflow sets more.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use tsong_config::{ANY, Policy, Refusal, Route, RouteTable, SigningAlgorithm, allowed, client_ip};
use url::Url;

/// The run's settings: `PROPTEST_CASES` and the rest from the
/// environment, with failures saved beside this file to replay first.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/properties.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

/// An address in 10.0.0.0/16, so generated networks often hold it.
fn ip() -> impl Strategy<Value = IpAddr> {
    (0u8..4, any::<u8>()).prop_map(|(c, d)| IpAddr::V4(Ipv4Addr::new(10, 0, c, d)))
}

/// A network within 10.0.0.0/16, from a /16 down to a single address.
fn net() -> impl Strategy<Value = IpNet> {
    (ip(), 16u8..=32).prop_filter_map("a valid prefix", |(ip, prefix)| {
        IpNet::new(ip, prefix).ok().map(|net| net.trunc())
    })
}

fn nets() -> impl Strategy<Value = Vec<IpNet>> {
    prop::collection::vec(net(), 0..4)
}

/// `hops` as `X-Forwarded-For` values: one comma-joined value split into
/// header values at `cuts`, as proxies append to the header or add their
/// own.
fn header_values(hops: &[String], cuts: &[bool]) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for (i, hop) in hops.iter().enumerate() {
        current.push(hop);
        if cuts.get(i).copied().unwrap_or(false) {
            values.push(current.join(", ").into_bytes());
            current.clear();
        }
    }
    if !current.is_empty() {
        values.push(current.join(", ").into_bytes());
    }
    values
}

fn client(peer: IpAddr, values: &[Vec<u8>], trusted: &[IpNet]) -> Option<IpAddr> {
    client_ip(peer, values.iter().map(Vec::as_slice), trusted)
}

fn trusted(ip: &IpAddr, nets: &[IpNet]) -> bool {
    nets.iter().any(|net| net.contains(ip))
}

proptest! {
    #![proptest_config(config())]

    /// A peer that isn't a trusted proxy is the client, whatever it says.
    #[test]
    fn an_untrusted_peer_is_the_client(
        (c, d) in (any::<u8>(), any::<u8>()),
        trusted_proxies in nets(),
        hops in prop::collection::vec(".*", 0..4),
    ) {
        // Outside 10.0.0.0/16, so never a trusted proxy.
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, c, d));
        let values: Vec<Vec<u8>> = hops.into_iter().map(String::into_bytes).collect();
        prop_assert_eq!(client(peer, &values, &trusted_proxies), Some(peer));
    }

    /// Behind trusted proxies, the client is the first untrusted hop from
    /// the right. Whatever the caller wrote to the left of it, an address,
    /// garbage or nothing, never changes the answer.
    #[test]
    fn hops_left_of_the_client_are_never_read(
        trusted_proxies in prop::collection::vec(net(), 1..4),
        (c, d) in (any::<u8>(), any::<u8>()),
        proxies in prop::collection::vec(any::<prop::sample::Index>(), 0..4),
        forged in prop::collection::vec("[^,]*", 0..4),
        cuts in prop::collection::vec(any::<bool>(), 0..12),
    ) {
        // Outside 10.0.0.0/16, so never a trusted proxy.
        let the_client = IpAddr::V4(Ipv4Addr::new(192, 168, c, d));
        let proxies: Vec<IpAddr> = proxies
            .iter()
            .map(|index| index.get(&trusted_proxies).addr())
            .collect();
        let Some(peer) = trusted_proxies.first().map(IpNet::addr) else {
            return Ok(());
        };
        let mut hops = forged;
        hops.push(the_client.to_string());
        hops.extend(proxies.iter().map(ToString::to_string));
        let values = header_values(&hops, &cuts);
        prop_assert_eq!(client(peer, &values, &trusted_proxies), Some(the_client));
    }

    /// One comma-joined header value and the same hops split across many
    /// header values give the same client.
    #[test]
    fn splitting_the_header_changes_nothing(
        peer in ip(),
        trusted_proxies in nets(),
        hops in prop::collection::vec(ip(), 0..6),
        cuts in prop::collection::vec(any::<bool>(), 0..6),
    ) {
        let hops: Vec<String> = hops.iter().map(ToString::to_string).collect();
        let joined = vec![hops.join(", ").into_bytes()];
        let joined = if hops.is_empty() { Vec::new() } else { joined };
        let split = header_values(&hops, &cuts);
        prop_assert_eq!(
            client(peer, &joined, &trusted_proxies),
            client(peer, &split, &trusted_proxies)
        );
    }

    /// The client is never a trusted proxy unless every hop was one.
    #[test]
    fn the_client_is_a_proxy_only_when_every_hop_is(
        peer in ip(),
        trusted_proxies in nets(),
        hops in prop::collection::vec(ip(), 0..6),
    ) {
        let values: Vec<Vec<u8>> = hops.iter().map(|hop| hop.to_string().into_bytes()).collect();
        if let Some(found) = client(peer, &values, &trusted_proxies)
            && trusted(&found, &trusted_proxies)
        {
            prop_assert!(trusted(&peer, &trusted_proxies));
            prop_assert!(hops.iter().all(|hop| trusted(hop, &trusted_proxies)));
        }
    }

    /// An IPv4 address written as IPv4-mapped IPv6 is the same client.
    #[test]
    fn a_mapped_address_is_its_ipv4_address(
        peer in ip(),
        trusted_proxies in nets(),
    ) {
        let IpAddr::V4(v4) = peer else {
            return Ok(());
        };
        let mapped = IpAddr::V6(v4.to_ipv6_mapped());
        prop_assert_eq!(
            client(mapped, &[], &trusted_proxies),
            client(peer, &[], &trusted_proxies)
        );
        prop_assert_eq!(
            allowed(mapped.to_canonical(), &trusted_proxies, None),
            allowed(peer, &trusted_proxies, None)
        );
    }

    /// A route's list narrows the gateway's and never widens it.
    #[test]
    fn a_route_allow_list_only_narrows(
        address in ip(),
        gateway in nets(),
        route in nets(),
    ) {
        prop_assert_eq!(
            allowed(address, &gateway, Some(&route)),
            allowed(address, &gateway, None) && allowed(address, &route, None)
        );
        prop_assert!(!allowed(address, &[], Some(&route)));
        prop_assert!(!allowed(address, &gateway, Some(&[])));
    }
}

/// Audiences a route may name or a token carry. Only `allow` holds `"*"`,
/// and `require` never names `admin`.
const AUDIENCES: [&str; 5] = ["tsong", "api", "other", "admin", ANY];

/// Scopes a route may name or a token carry, held to the same rules.
const SCOPES: [&str; 5] = ["orders.read", "orders.write", "billing.read", "admin", ANY];

fn names(universe: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(prop::sample::select(universe), 0..5)
        .prop_map(|names| names.into_iter().map(str::to_owned).collect())
}

/// A policy allowing any value.
fn any_value() -> Policy {
    Policy {
        allow: vec![ANY.into()],
        require: Vec::new(),
        deny: Vec::new(),
    }
}

/// A route allowing any audience and scope, and nothing else set.
fn route() -> Result<Route, url::ParseError> {
    Ok(Route {
        name: "r".into(),
        host: "r.test".into(),
        downstream: Url::parse("https://r-lb.test")?,
        append_audience: String::new(),
        audiences: any_value(),
        scopes: any_value(),
        signing_algorithm: SigningAlgorithm::default(),
        allow: None,
        read_timeout: None,
    })
}

/// Checks `policy`'s answer for a token carrying `held` against a model of
/// its four checks: the token is accepted exactly when it carries at least
/// one value `allow` admits, none outside `allow`, every one `require`
/// lists and none `deny` lists. A refusal names the first check that
/// failed, and every check before it passed.
fn matches_model(policy: &Policy, held: &[&str]) -> Result<(), TestCaseError> {
    let Policy {
        allow,
        require,
        deny,
    } = policy;
    let allowed = |value: &str| allow.iter().any(|a| a == ANY || a == value);
    let one_allowed = held.iter().any(|value| allowed(value));
    let none_outside = held.iter().all(|value| allowed(value));
    let all_required = require.iter().all(|r| held.contains(&r.as_str()));
    let none_denied = !held.iter().any(|value| deny.iter().any(|d| d == value));
    let refusal = policy.refusal(held);
    prop_assert_eq!(
        refusal.is_none(),
        one_allowed && none_outside && all_required && none_denied
    );
    match refusal {
        None => {}
        Some(Refusal::NoValue) => prop_assert!(held.is_empty()),
        Some(Refusal::NotAllowed) => {
            prop_assert!(!one_allowed && !held.is_empty());
        }
        Some(Refusal::Outside(value)) => {
            prop_assert!(one_allowed);
            prop_assert!(held.contains(&value) && !allowed(value));
        }
        Some(Refusal::Missing(value)) => {
            prop_assert!(one_allowed && none_outside);
            prop_assert!(require.iter().any(|r| r == value) && !held.contains(&value));
        }
        Some(Refusal::Denied(value)) => {
            prop_assert!(one_allowed && none_outside && all_required);
            prop_assert!(held.contains(&value) && deny.iter().any(|d| d == value));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    /// A route's audience policy matches the model.
    #[test]
    fn a_route_accepts_only_audiences_its_policy_admits(
        allow in names(&AUDIENCES),
        require in names(&AUDIENCES[..3]),
        deny in names(&AUDIENCES[..4]),
        audiences in names(&AUDIENCES[..4]),
    ) {
        let mut route = route()?;
        route.audiences = Policy { allow, require, deny };
        let held: Vec<&str> = audiences.iter().map(String::as_str).collect();
        matches_model(&route.audiences, &held)?;
    }

    /// A route's scope policy matches the same model, so a token with no
    /// scopes is refused by every route.
    #[test]
    fn a_route_accepts_only_scopes_its_policy_admits(
        allow in names(&SCOPES),
        require in names(&SCOPES[..3]),
        deny in names(&SCOPES[..4]),
        scopes in names(&SCOPES[..4]),
    ) {
        let mut route = route()?;
        route.scopes = Policy { allow, require, deny };
        let held: Vec<&str> = scopes.iter().map(String::as_str).collect();
        matches_model(&route.scopes, &held)?;
        if held.is_empty() {
            prop_assert_eq!(route.scopes.refusal(&held), Some(Refusal::NoValue));
        }
    }

    /// A route is found by its host in any case, and no other host finds it.
    #[test]
    fn a_route_is_found_by_its_host_in_any_case(
        host in "[a-z]{1,8}\\.test",
        other in "[a-z]{1,8}\\.test",
        upper in prop::collection::vec(any::<bool>(), 13),
    ) {
        let mut route = route()?;
        route.host.clone_from(&host);
        let table = RouteTable::new(std::slice::from_ref(&route));
        let cased: String = host
            .chars()
            .zip(upper.iter().chain(std::iter::repeat(&false)))
            .map(|(c, &up)| if up { c.to_ascii_uppercase() } else { c })
            .collect();
        prop_assert_eq!(table.get(&cased).map(|found| found.host.as_str()), Some(host.as_str()));
        if other != host {
            prop_assert!(table.get(&other).is_none());
        }
    }
}
