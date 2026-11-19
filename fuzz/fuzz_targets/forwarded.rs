//! Reads the client address from arbitrary `X-Forwarded-For` values: it
//! must never panic, an untrusted peer is always the client, and the client
//! is always in canonical form.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;
use tsong_config::client_ip;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let trusted: Vec<IpNet> = ["10.0.0.0/8", "::ffff:10.0.0.0/104", "fd00::/8"]
        .into_iter()
        .filter_map(|net| net.parse().ok())
        .collect();
    // The first byte picks the peer; 0xFF separates header values.
    let peer = match selector % 4 {
        0 => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1 => IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()),
        2 => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        _ => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let values = rest.split(|&byte| byte == 0xFF);
    let client = client_ip(peer, values, &trusted);
    if selector % 4 == 3 {
        assert_eq!(client, Some(peer));
    }
    if let Some(client) = client {
        assert_eq!(client, client.to_canonical());
    }
});
