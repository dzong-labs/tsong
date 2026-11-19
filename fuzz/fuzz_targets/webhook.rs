//! Reads arbitrary webhook deliveries and signatures: neither may panic,
//! and no signature verifies without the secret.

#![no_main]

use std::hash::{BuildHasher, RandomState};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tsong_config::GitHost;
use tsong_git::webhook::{pushed_branch, verify};

/// A secret drawn at random when the run starts, which no input can know.
fn secret() -> &'static [u8] {
    static SECRET: OnceLock<Vec<u8>> = OnceLock::new();
    SECRET.get_or_init(|| {
        let state = RandomState::new();
        (0u8..4)
            .flat_map(|i| state.hash_one(i).to_le_bytes())
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = pushed_branch(data);
    // The first line is the signature header, the rest the body.
    let (signature, body) = match data.iter().position(|&byte| byte == b'\n') {
        Some(end) => (
            data.get(..end).unwrap_or_default(),
            data.get(end + 1..).unwrap_or_default(),
        ),
        None => (data, &[][..]),
    };
    let secret = secret();
    assert!(!verify(GitHost::GitHub, secret, Some(signature), body));
    assert!(!verify(GitHost::GitLab, secret, Some(signature), body));
    // An empty secret verifies nothing, whatever the signature.
    assert!(!verify(GitHost::GitHub, &[], Some(signature), body));
});
