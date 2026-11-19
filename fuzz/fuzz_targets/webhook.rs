//! Reads arbitrary webhook deliveries and signatures: neither may panic,
//! and no signature verifies without the secret.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsong_config::GitHost;
use tsong_git::webhook::{pushed_branch, verify};

fuzz_target!(|data: &[u8]| {
    let _ = pushed_branch(data);
    // The first line is the signature header, the rest the body.
    let (signature, body) = match data.iter().position(|&byte| byte == b'\n') {
        Some(end) => (data.get(..end).unwrap_or_default(), data.get(end + 1..).unwrap_or_default()),
        None => (data, &[][..]),
    };
    let secret = b"a webhook secret the fuzzer doesn't know";
    assert!(!verify(GitHost::GitHub, secret, Some(signature), body));
    assert!(!verify(GitHost::GitLab, secret, Some(signature), body));
    assert!(!verify(GitHost::GitHub, b"", Some(signature), body));
});
